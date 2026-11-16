package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testPassword = "demo-password-for-tests"

func authApp(t *testing.T) *App {
	t.Helper()
	dir := t.TempDir()
	a := &App{authPath: filepath.Join(dir, "auth.json"), configPath: filepath.Join(dir, "config.json"), statePath: filepath.Join(dir, "state.json"), listen: "192.168.1.1:1001", loginGate: make(chan struct{}, 1), failures: map[string]loginFailure{}}
	if err := setPasswordFromInput(a.authPath, strings.NewReader(testPassword+"\n")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(a.configPath, []byte(`{"inbounds":[],"outbounds":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := a.load(); err != nil {
		t.Fatal(err)
	}
	return a
}

func request(a *App, path, password string, cookie *http.Cookie, origin string) *httptest.ResponseRecorder {
	method := "GET"
	var body *bytes.Reader
	if path == "/auth/login" || path == "/auth/logout" {
		method = "POST"
		b, _ := json.Marshal(map[string]string{"password": password})
		body = bytes.NewReader(b)
	} else {
		body = bytes.NewReader(nil)
	}
	r := httptest.NewRequest(method, "http://"+a.listen+path, body)
	r.RemoteAddr = "192.168.1.20:12345"
	r.Header.Set("Origin", origin)
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	a.handle(w, r)
	return w
}

func loggedInCookie(t *testing.T, a *App) *http.Cookie {
	t.Helper()
	w := request(a, "/auth/login", testPassword, nil, "http://"+a.listen)
	if w.Code != 200 {
		t.Fatalf("login: %d %s", w.Code, w.Body)
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatal("session cookie missing")
	}
	return cookies[0]
}

func TestIndependentLoginSessionAndLogout(t *testing.T) {
	a := authApp(t)
	if request(a, "/api/stats", "", nil, "").Code != 401 {
		t.Fatal("anonymous API accepted")
	}
	legacy := &http.Cookie{Name: "session_id", Value: "legacy-panel-session"}
	if request(a, "/api/stats", "", legacy, "").Code != 401 {
		t.Fatal("foreign panel cookie accepted")
	}
	bad := request(a, "/auth/login", "wrong-password", nil, "http://"+a.listen)
	if bad.Code != 401 || len(bad.Result().Cookies()) != 0 {
		t.Fatal("incorrect password accepted")
	}
	cookie := loggedInCookie(t, a)
	if cookie.Name != statsCookie || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.MaxAge != 43200 || cookie.Path != "/" {
		t.Fatal("unsafe cookie properties")
	}
	if request(a, "/api/stats", "", cookie, "").Code != 200 {
		t.Fatal("own session rejected")
	}
	restarted := &App{authPath: a.authPath}
	r := httptest.NewRequest("GET", "http://"+a.listen+"/api/stats", nil)
	r.AddCookie(cookie)
	if !restarted.authorized(r) {
		t.Fatal("session lost across service restart")
	}
	if request(a, "/auth/logout", "", cookie, "http://other.example").Code != 403 || !a.authorized(r) {
		t.Fatal("cross-origin logout changed session")
	}
	if request(a, "/auth/logout", "", cookie, "http://"+a.listen).Code != 200 {
		t.Fatal("logout failed")
	}
	if restarted.authorized(r) {
		t.Fatal("logged-out session accepted after restart")
	}
	data, _ := os.ReadFile(a.authPath)
	if bytes.Contains(data, []byte(testPassword)) || bytes.Contains(data, []byte(cookie.Value)) {
		t.Fatal("plaintext password/token persisted")
	}
}

func TestPasswordResetAndCorruptAuthFailClosed(t *testing.T) {
	a := authApp(t)
	cookie := loggedInCookie(t, a)
	before, err := readAuth(a.authPath)
	if err != nil {
		t.Fatal(err)
	}
	if err = setPasswordFromInput(a.authPath, strings.NewReader(testPassword)); err != nil {
		t.Fatal(err)
	}
	after, _ := readAuth(a.authPath)
	if before.Salt == after.Salt || before.PasswordHash == after.PasswordHash {
		t.Fatal("password reset reused salt")
	}
	if request(a, "/api/stats", "", cookie, "").Code != 401 {
		t.Fatal("reset did not revoke sessions")
	}
	if err = setPasswordFromInput(a.authPath, strings.NewReader("short")); err == nil {
		t.Fatal("short password accepted")
	}
	for _, data := range []string{`{}`, `{"auth":{"enabled":true}}`, `{"version":1,"algorithm":"pbkdf2-sha256","iterations":1}`} {
		if err = os.WriteFile(a.authPath, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err = readAuth(a.authPath); err == nil {
			t.Fatal("invalid auth accepted")
		}
		if request(a, "/api/stats", "", cookie, "").Code != 401 {
			t.Fatal("invalid auth opened API")
		}
	}
}

func TestExpiredAndTamperedSessions(t *testing.T) {
	a := authApp(t)
	cookie := loggedInCookie(t, a)
	bad := *cookie
	bad.Value = strings.Repeat("A", 43)
	if request(a, "/api/stats", "", &bad, "").Code != 401 {
		t.Fatal("tampered cookie accepted")
	}
	c, _ := readAuth(a.authPath)
	c.Sessions[0].Expires = time.Now().Add(-time.Second).Unix()
	if err := writeAuth(a.authPath, c); err != nil {
		t.Fatal(err)
	}
	if request(a, "/api/stats", "", cookie, "").Code != 401 {
		t.Fatal("expired session accepted")
	}
}

func TestLoginOriginRateLimitAndConcurrency(t *testing.T) {
	a := authApp(t)
	if request(a, "/auth/login", testPassword, nil, "http://other.example").Code != 403 {
		t.Fatal("cross-origin login accepted")
	}
	a.failures["192.168.1.20"] = loginFailure{Count: 5, Until: time.Now().Add(time.Minute)}
	if request(a, "/auth/login", testPassword, nil, "http://"+a.listen).Code != 429 {
		t.Fatal("brute-force limit absent")
	}
	a.failures["192.168.1.20"] = loginFailure{Count: 5, Until: time.Now().Add(-time.Second)}
	a.loginGate <- struct{}{}
	if request(a, "/auth/login", testPassword, nil, "http://"+a.listen).Code != 429 {
		t.Fatal("concurrent password hashing allowed")
	}
	<-a.loginGate
	if request(a, "/auth/login", testPassword, nil, "http://"+a.listen).Code != 200 {
		t.Fatal("expired rate limit did not clear")
	}
}

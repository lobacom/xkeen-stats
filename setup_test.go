package main

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func setupApp(t *testing.T) (*App, string) {
	t.Helper()
	dir := t.TempDir()
	a := &App{authPath: filepath.Join(dir, "auth.json"), setupTokenPath: filepath.Join(dir, "setup-token"), statePath: filepath.Join(dir, "state.json"), configPath: filepath.Join(dir, "config.json"), listen: "192.168.1.1:1001", loginGate: make(chan struct{}, 1)}
	required, err := initialAccess(a.authPath, a.setupTokenPath, true)
	if err != nil || !required {
		t.Fatalf("prepare: %v %v", required, err)
	}
	a.allowSetup = true
	if err = os.WriteFile(a.configPath, []byte(`{"inbounds":[],"outbounds":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err = a.load(); err != nil {
		t.Fatal(err)
	}
	token, err := readSetupToken(a.setupTokenPath)
	if err != nil {
		t.Fatal(err)
	}
	return a, token
}

func setupRequest(a *App, token, password, confirm, origin string) *httptest.ResponseRecorder {
	b, _ := json.Marshal(map[string]string{"token": token, "password": password, "confirm_password": confirm})
	r := httptest.NewRequest("POST", "http://"+a.listen+"/auth/setup", bytes.NewReader(b))
	r.RemoteAddr = "192.168.1.20:1234"
	r.Header.Set("Origin", origin)
	w := httptest.NewRecorder()
	a.handle(w, r)
	return w
}

func TestFirstSetupRequiresPrivateLinkAndCreatesOwnSession(t *testing.T) {
	a, token := setupApp(t)
	origin := "http://" + a.listen
	status := request(a, "/auth/status", "", nil, "")
	if status.Code != 200 || strings.Contains(status.Body.String(), token) || !strings.Contains(status.Body.String(), `"setup_required":true`) {
		t.Fatal("unsafe setup status")
	}
	if request(a, "/api/stats", "", nil, "").Code != 401 {
		t.Fatal("statistics exposed before setup")
	}
	if setupRequest(a, token, testPassword, testPassword, "http://other.example").Code != 403 {
		t.Fatal("cross-origin setup accepted")
	}
	if setupRequest(a, strings.Repeat("A", 43), testPassword, testPassword, origin).Code != 403 {
		t.Fatal("setup without private token accepted")
	}
	if setupRequest(a, token, testPassword, "different", origin).Code != 400 {
		t.Fatal("password mismatch accepted")
	}
	if _, err := os.Stat(a.authPath); !os.IsNotExist(err) {
		t.Fatal("failed setup created auth file")
	}
	w := setupRequest(a, token, testPassword, testPassword, origin)
	if w.Code != 201 {
		t.Fatalf("setup failed: %d %s", w.Code, w.Body)
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != statsCookie {
		t.Fatal("first session missing")
	}
	if request(a, "/api/stats", "", cookies[0], "").Code != 200 {
		t.Fatal("created session rejected")
	}
	before, _ := os.ReadFile(a.authPath)
	if setupRequest(a, token, "another-password", "another-password", origin).Code != 409 {
		t.Fatal("setup overwritten existing password")
	}
	after, _ := os.ReadFile(a.authPath)
	if !bytes.Equal(before, after) {
		t.Fatal("existing authentication modified")
	}
	if bytes.Contains(after, []byte(testPassword)) || bytes.Contains(after, []byte(token)) {
		t.Fatal("plaintext secret persisted in auth file")
	}
	if _, err := os.Stat(a.setupTokenPath); !os.IsNotExist(err) {
		t.Fatal("setup token not consumed")
	}
}

func TestInitialAccessRejectsCorruptExistingAuth(t *testing.T) {
	a, _ := setupApp(t)
	if err := os.WriteFile(a.authPath, []byte(`{"broken":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	if required, err := initialAccess(a.authPath, a.setupTokenPath, true); err == nil || required {
		t.Fatal("corrupt auth reopened setup")
	}
	if request(a, "/auth/status", "", nil, "").Code != 503 {
		t.Fatal("corrupt auth not reported")
	}
}

func TestInitialAuthCreationCannotRaceOrOverwrite(t *testing.T) {
	a, _ := setupApp(t)
	c, err := newAuthConfig(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); results <- createFirstAuth(a.authPath, c) }()
	}
	wg.Wait()
	close(results)
	success, exists := 0, 0
	for err := range results {
		if err == nil {
			success++
		} else if os.IsExist(err) {
			exists++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || exists != 1 {
		t.Fatalf("creation race: success=%d exists=%d", success, exists)
	}
}

func TestSetupDoesNotReopenAfterConfiguredFileIsRemoved(t *testing.T) {
	a := authApp(t)
	a.setupTokenPath = filepath.Join(filepath.Dir(a.authPath), "setup-token")
	if required, err := initialAccess(a.authPath, a.setupTokenPath, true); err != nil || required {
		t.Fatal("configured instance entered setup")
	}
	if err := os.Remove(a.authPath); err != nil {
		t.Fatal(err)
	}
	if request(a, "/auth/status", "", nil, "").Code != 503 {
		t.Fatal("running configured service reopened setup")
	}
	if setupRequest(a, strings.Repeat("A", 43), testPassword, testPassword, "http://"+a.listen).Code != 409 {
		t.Fatal("configured service allowed setup after file removal")
	}
}

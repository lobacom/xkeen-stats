package main

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	passwordIterations = 600000
	statsCookie        = "xkeen_stats_session"
	sessionLifetime    = 12 * time.Hour
	maxSessions        = 32
)

type authSession struct {
	Hash    string `json:"hash"`
	Expires int64  `json:"expires"`
}

type authConfig struct {
	Version      int           `json:"version"`
	Algorithm    string        `json:"algorithm"`
	Iterations   int           `json:"iterations"`
	Salt         string        `json:"salt"`
	PasswordHash string        `json:"password_hash"`
	Sessions     []authSession `json:"sessions"`
}

type loginFailure struct {
	Count int
	Until time.Time
}

func readAuth(path string) (authConfig, error) {
	var c authConfig
	f, err := os.Open(path)
	if err != nil {
		return c, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil {
		return c, err
	}
	if len(data) > 65536 {
		return c, errors.New("authentication file too large")
	}
	if err = json.Unmarshal(data, &c); err != nil {
		return c, errors.New("invalid authentication JSON")
	}
	salt, e1 := base64.RawStdEncoding.DecodeString(c.Salt)
	hash, e2 := base64.RawStdEncoding.DecodeString(c.PasswordHash)
	if c.Version != 1 || c.Algorithm != "pbkdf2-sha256" || c.Iterations != passwordIterations || e1 != nil || e2 != nil || len(salt) != 16 || len(hash) != 32 || len(c.Sessions) > maxSessions {
		return c, errors.New("invalid authentication configuration")
	}
	for _, s := range c.Sessions {
		digest, err := hex.DecodeString(s.Hash)
		if err != nil || len(digest) != 32 || s.Expires <= 0 {
			return c, errors.New("invalid saved session")
		}
	}
	return c, nil
}

func writeAuth(path string, c authConfig) error {
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".auth-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(name, path)
}

func setPasswordFromInput(path string, input io.Reader) error {
	data, err := io.ReadAll(io.LimitReader(input, 1027))
	if err != nil {
		return err
	}
	// Убираем только окончание строки; пробелы являются частью пароля.
	password := strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r")
	if len(password) < 8 || len(password) > 1024 || strings.ContainsAny(password, "\r\n") {
		return errors.New("password must be 8 to 1024 bytes on one line")
	}
	salt := make([]byte, 16)
	if _, err = rand.Read(salt); err != nil {
		return err
	}
	hash, err := pbkdf2.Key(sha256.New, password, salt, passwordIterations, 32)
	if err != nil {
		return err
	}
	c := authConfig{Version: 1, Algorithm: "pbkdf2-sha256", Iterations: passwordIterations, Salt: base64.RawStdEncoding.EncodeToString(salt), PasswordHash: base64.RawStdEncoding.EncodeToString(hash), Sessions: []authSession{}}
	return writeAuth(path, c)
}

func passwordMatches(c authConfig, password string) bool {
	salt, err := base64.RawStdEncoding.DecodeString(c.Salt)
	if err != nil {
		return false
	}
	expected, err := base64.RawStdEncoding.DecodeString(c.PasswordHash)
	if err != nil {
		return false
	}
	actual, err := pbkdf2.Key(sha256.New, password, salt, c.Iterations, 32)
	return err == nil && subtle.ConstantTimeCompare(actual, expected) == 1
}

func tokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (a *App) authorized(r *http.Request) bool {
	cookie, err := r.Cookie(statsCookie)
	if err != nil || len(cookie.Value) != 43 {
		return false
	}
	a.authMu.Lock()
	defer a.authMu.Unlock()
	c, err := readAuth(a.authPath)
	if err != nil {
		return false
	}
	hash := tokenHash(cookie.Value)
	for _, session := range c.Sessions {
		if session.Expires > time.Now().Unix() && subtle.ConstantTimeCompare([]byte(session.Hash), []byte(hash)) == 1 {
			return true
		}
	}
	return false
}

func authReply(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if message != "" {
		_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "error": message})
	} else {
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
	}
}

func (a *App) sameOriginPost(r *http.Request) bool {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return r.Method == http.MethodPost && r.Header.Get("Origin") == scheme+"://"+a.listen
}

func (a *App) login(w http.ResponseWriter, r *http.Request) {
	if !a.sameOriginPost(r) {
		authReply(w, 403, "Недопустимый источник запроса")
		return
	}
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	a.authMu.Lock()
	if a.failures == nil {
		a.failures = map[string]loginFailure{}
	}
	now := time.Now()
	for key, f := range a.failures {
		if !now.Before(f.Until) {
			delete(a.failures, key)
		}
	}
	failure := a.failures[ip]
	blocked := failure.Count >= 5 || len(a.failures) >= 256
	a.authMu.Unlock()
	if blocked {
		w.Header().Set("Retry-After", "60")
		authReply(w, 429, "Слишком много попыток. Повторите через минуту")
		return
	}
	var input struct {
		Password string `json:"password"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&input) != nil || len(input.Password) == 0 || len(input.Password) > 1024 {
		authReply(w, 400, "Некорректный запрос")
		return
	}
	// На роутере одновременно выполняется только одна дорогая проверка пароля.
	select {
	case a.loginGate <- struct{}{}:
		defer func() { <-a.loginGate }()
	default:
		w.Header().Set("Retry-After", "2")
		authReply(w, 429, "Выполняется проверка входа. Повторите через несколько секунд")
		return
	}
	a.authMu.Lock()
	c, err := readAuth(a.authPath)
	a.authMu.Unlock()
	if err != nil {
		authReply(w, 503, "Авторизация не настроена")
		return
	}
	if !passwordMatches(c, input.Password) {
		a.authMu.Lock()
		failure = a.failures[ip]
		failure.Count++
		if failure.Until.IsZero() {
			failure.Until = time.Now().Add(time.Minute)
		}
		a.failures[ip] = failure
		a.authMu.Unlock()
		authReply(w, 401, "Неверный пароль")
		return
	}
	tokenBytes := make([]byte, 32)
	if _, err = rand.Read(tokenBytes); err != nil {
		authReply(w, 503, "Не удалось создать сессию")
		return
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	expires := time.Now().Add(sessionLifetime)
	a.authMu.Lock()
	defer a.authMu.Unlock()
	latest, err := readAuth(a.authPath)
	if err != nil || latest.PasswordHash != c.PasswordHash || latest.Salt != c.Salt {
		authReply(w, 503, "Настройки входа изменились. Повторите вход")
		return
	}
	oldHash := ""
	if old, err := r.Cookie(statsCookie); err == nil {
		oldHash = tokenHash(old.Value)
	}
	sessions := []authSession{}
	for _, s := range latest.Sessions {
		if s.Expires > time.Now().Unix() && s.Hash != oldHash {
			sessions = append(sessions, s)
		}
	}
	if len(sessions) >= maxSessions {
		sessions = sessions[len(sessions)-maxSessions+1:]
	}
	latest.Sessions = append(sessions, authSession{Hash: tokenHash(token), Expires: expires.Unix()})
	if err = writeAuth(a.authPath, latest); err != nil {
		authReply(w, 503, "Не удалось сохранить сессию")
		return
	}
	delete(a.failures, ip)
	http.SetCookie(w, &http.Cookie{Name: statsCookie, Value: token, Path: "/", HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode, MaxAge: int(sessionLifetime.Seconds()), Expires: expires})
	authReply(w, 200, "")
}

func (a *App) logout(w http.ResponseWriter, r *http.Request) {
	if !a.sameOriginPost(r) {
		authReply(w, 403, "Недопустимый источник запроса")
		return
	}
	a.authMu.Lock()
	defer a.authMu.Unlock()
	c, err := readAuth(a.authPath)
	if err != nil {
		authReply(w, 503, "Авторизация недоступна")
		return
	}
	cookie, _ := r.Cookie(statsCookie)
	hash := ""
	if cookie != nil {
		hash = tokenHash(cookie.Value)
	}
	sessions := []authSession{}
	for _, s := range c.Sessions {
		if s.Expires > time.Now().Unix() && s.Hash != hash {
			sessions = append(sessions, s)
		}
	}
	c.Sessions = sessions
	if err = writeAuth(a.authPath, c); err != nil {
		authReply(w, 503, "Не удалось завершить сессию")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: statsCookie, Value: "", Path: "/", HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode, MaxAge: -1, Expires: time.Unix(1, 0)})
	authReply(w, 200, "")
}

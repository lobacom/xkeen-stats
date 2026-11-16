package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

func readSetupToken(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 129))
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(b))
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if len(b) > 128 || err != nil || len(raw) != 32 {
		return "", errors.New("invalid initial setup token")
	}
	return token, nil
}

// Жёсткая ссылка атомарно создаёт конечный файл и никогда не заменяет существующий.
func createPrivateFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".initial-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
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
	if err = os.Link(f.Name(), path); err != nil {
		return err
	}
	if runtime.GOOS == "linux" {
		dir, openErr := os.Open(filepath.Dir(path))
		if openErr != nil {
			return openErr
		}
		syncErr := dir.Sync()
		_ = dir.Close()
		return syncErr
	}
	return nil
}

func initialAccess(authPath, tokenPath string, create bool) (bool, error) {
	if _, err := readAuth(authPath); err == nil {
		return false, nil
	} else if !os.IsNotExist(err) {
		return false, err
	}
	if _, err := readSetupToken(tokenPath); err == nil {
		return true, nil
	} else if !os.IsNotExist(err) || !create {
		return false, err
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return false, err
	}
	if err := createPrivateFile(tokenPath, []byte(base64.RawURLEncoding.EncodeToString(secret))); err != nil && !os.IsExist(err) {
		return false, err
	}
	_, err := readSetupToken(tokenPath)
	return err == nil, err
}

func createFirstAuth(path string, c authConfig) error {
	b, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return createPrivateFile(path, b)
}

func (a *App) authStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		authReply(w, 405, "Метод не поддерживается")
		return
	}
	a.authMu.Lock()
	defer a.authMu.Unlock()
	if _, err := readAuth(a.authPath); err == nil {
		a.allowSetup = false
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]bool{"setup_required": false})
		return
	} else if !os.IsNotExist(err) || !a.allowSetup {
		authReply(w, 503, "Не удалось прочитать настройки входа")
		return
	}
	if _, err := readSetupToken(a.setupTokenPath); err != nil {
		authReply(w, 503, "Первоначальная настройка недоступна")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"setup_required": true})
}

func (a *App) setup(w http.ResponseWriter, r *http.Request) {
	if !a.sameOriginPost(r) {
		authReply(w, 403, "Недопустимый источник запроса")
		return
	}
	var input struct {
		Password string `json:"password"`
		Confirm  string `json:"confirm_password"`
		Token    string `json:"token"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&input) != nil {
		authReply(w, 400, "Некорректный запрос")
		return
	}
	a.authMu.Lock()
	_, statErr := os.Lstat(a.authPath)
	if !a.allowSetup || !os.IsNotExist(statErr) {
		a.allowSetup = false
		a.authMu.Unlock()
		authReply(w, 409, "Пароль уже задан. Выполните вход")
		return
	}
	expected, err := readSetupToken(a.setupTokenPath)
	a.authMu.Unlock()
	if err != nil || len(input.Token) != 43 || subtle.ConstantTimeCompare([]byte(input.Token), []byte(expected)) != 1 {
		authReply(w, 403, "Откройте действующую ссылку первоначальной настройки")
		return
	}
	if input.Password != input.Confirm {
		authReply(w, 400, "Пароли не совпадают")
		return
	}
	if len(input.Password) < 8 || len(input.Password) > 1024 || strings.ContainsAny(input.Password, "\r\n") {
		authReply(w, 400, "Пароль должен занимать от 8 до 1024 байт и не содержать переводов строки")
		return
	}
	select {
	case a.loginGate <- struct{}{}:
		defer func() { <-a.loginGate }()
	default:
		w.Header().Set("Retry-After", "2")
		authReply(w, 429, "Создание пароля уже выполняется")
		return
	}
	c, err := newAuthConfig(input.Password)
	if err != nil {
		authReply(w, 503, "Не удалось создать пароль")
		return
	}
	tokenBytes := make([]byte, 32)
	if _, err = rand.Read(tokenBytes); err != nil {
		authReply(w, 503, "Не удалось создать сессию")
		return
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	expires := time.Now().Add(sessionLifetime)
	c.Sessions = []authSession{{Hash: tokenHash(token), Expires: expires.Unix()}}
	a.authMu.Lock()
	defer a.authMu.Unlock()
	if !a.allowSetup {
		authReply(w, 409, "Пароль уже задан. Выполните вход")
		return
	}
	if err = createFirstAuth(a.authPath, c); err != nil {
		if os.IsExist(err) {
			authReply(w, 409, "Пароль уже задан. Выполните вход")
		} else {
			authReply(w, 503, "Не удалось сохранить пароль")
		}
		return
	}
	a.allowSetup = false
	_ = os.Remove(a.setupTokenPath)
	http.SetCookie(w, &http.Cookie{Name: statsCookie, Value: token, Path: "/", HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode, MaxAge: int(sessionLifetime.Seconds()), Expires: expires})
	authReply(w, 201, "")
}

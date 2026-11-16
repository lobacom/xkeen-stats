package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUpdateVersions(t *testing.T) {
	for _, c := range []struct {
		latest, current string
		want            bool
	}{{"v0.2.0", "dev", true}, {"v0.2.0", "v0.2.0-dev", true}, {"v0.2.0", "v0.2.0", false}, {"v0.2.0", "v0.3.0", false}, {"v1.10.0", "v1.9.9", true}, {"v2.0.0-beta", "v1.0.0", false}, {"v01.0.0", "dev", false}} {
		if got := newerVersion(c.latest, c.current); got != c.want {
			t.Fatalf("%+v: %v", c, got)
		}
	}
}

func TestSignedUpdateManifest(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	sum := strings.Repeat("a", 64)
	name := "xkeen-stats-linux-mipsle"
	manifest := []byte("# xkeen-stats v0.2.0\n" + sum + "  " + name + "\n")
	signature := []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(private, manifest)))
	if got, err := verifyManifest(public, manifest, signature, "v0.2.0", name); err != nil || got != sum {
		t.Fatalf("%s %v", got, err)
	}
	if _, err := verifyManifest(public, append(manifest, 'x'), signature, "v0.2.0", name); err == nil {
		t.Fatal("modified manifest accepted")
	}
	if _, err := verifyManifest(public, manifest, signature, "v0.3.0", name); err == nil {
		t.Fatal("old manifest replayed under new version")
	}
	if _, err := signedChecksum(manifest, signature, "v0.2.0", name); err == nil {
		t.Fatal("untrusted signing key accepted")
	}
	if _, err := parseManifest(append(manifest, []byte(sum+" "+name+"\n")...), "v0.2.0", name); err == nil {
		t.Fatal("duplicate checksum accepted")
	}
}

func TestUpdateSourceRestrictions(t *testing.T) {
	for _, bad := range []string{"http://github.com/test", "https://evil.example/file", "https://github.com.evil.example/file", "https://user@github.com/file", "https://github.com:443/file"} {
		if trustedUpdateURL(bad) {
			t.Fatal("trusted " + bad)
		}
	}
	r := githubRelease{Tag: "v0.2.0", Assets: []releaseAsset{{Name: "SHA256SUMS", URL: "https://evil.example/SHA256SUMS", Size: 1}}}
	if _, err := assetFor(r, "SHA256SUMS"); err == nil {
		t.Fatal("foreign asset URL accepted")
	}
	if platformAsset("windows", "amd64") != "" || platformAsset("linux", "mipsle") != "xkeen-stats-linux-mipsle" {
		t.Fatal("wrong platform mapping")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestDownloadChecksumMismatchKeepsCurrentBinary(t *testing.T) {
	dir := t.TempDir()
	current := filepath.Join(dir, "current")
	_ = os.WriteFile(current, []byte("old"), 0700)
	u := &updater{client: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("new")), Header: make(http.Header)}, nil
	})}}
	a := releaseAsset{URL: "https://github.com/lobacom/xkeen-stats/releases/download/v0.2.0/xkeen-stats-linux-mipsle", Size: 3}
	if err := u.download(a, filepath.Join(dir, "candidate"), strings.Repeat("0", 64)); err == nil {
		t.Fatal("corrupt download accepted")
	}
	b, _ := os.ReadFile(current)
	if string(b) != "old" {
		t.Fatal("download modified installed binary")
	}
}

func transactionJob(t *testing.T) updateJob {
	t.Helper()
	dir := t.TempDir()
	j := updateJob{Directory: dir, Executable: filepath.Join(dir, "installed"), Candidate: filepath.Join(dir, "candidate"), Previous: filepath.Join(dir, "previous"), Target: "v0.2.0", PreviousVersion: "v0.1.0"}
	_ = os.WriteFile(j.Executable, []byte("old-binary"), 0700)
	_ = os.WriteFile(j.Candidate, []byte("new-binary"), 0700)
	sum := sha256.Sum256([]byte("new-binary"))
	j.Checksum = hex.EncodeToString(sum[:])
	return j
}

func TestUpdateTransactionAndRollback(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "rollback"}[fail], func(t *testing.T) {
			j := transactionJob(t)
			state := filepath.Join(j.Directory, "state.json")
			_ = os.WriteFile(state, []byte("preserved-history"), 0600)
			err := installTransaction(j, func() error { return nil }, func() error { return nil }, func(v string) error {
				if fail && v == j.Target {
					return errors.New("startup failed")
				}
				return nil
			}, func(string) {})
			b, _ := os.ReadFile(j.Executable)
			if fail {
				if err == nil || string(b) != "old-binary" {
					t.Fatalf("rollback: %s %v", b, err)
				}
			} else if err != nil || string(b) != "new-binary" {
				t.Fatalf("install: %s %v", b, err)
			}
			original, _ := os.ReadFile(j.Previous)
			if string(original) != "old-binary" {
				t.Fatal("backup missing")
			}
			data, _ := os.ReadFile(state)
			if string(data) != "preserved-history" {
				t.Fatal("history modified")
			}
		})
	}
}

func TestInterruptedUpdateRecovery(t *testing.T) {
	dir := t.TempDir()
	jobDir := filepath.Join(dir, "job-test")
	_ = os.Mkdir(jobDir, 0700)
	j := updateJob{Directory: jobDir, Executable: filepath.Join(dir, "installed"), Candidate: filepath.Join(jobDir, "candidate"), Previous: filepath.Join(jobDir, "previous"), Target: "v0.2.0"}
	_ = os.WriteFile(j.Executable, []byte("broken-new"), 0700)
	_ = os.WriteFile(j.Previous, []byte("working-old"), 0700)
	jobFile := filepath.Join(jobDir, "job.json")
	_ = writeUpdateJSON(jobFile, j)
	_ = writeUpdateJSON(filepath.Join(dir, "pending.json"), updatePending{Job: jobFile, PID: 99999999})
	_ = setUpdateProgress(dir, "restarting", j.Target, "")
	if err := recoverUpdate(dir); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(j.Executable)
	if !bytes.Equal(b, []byte("working-old")) {
		t.Fatal("interrupted installation not recovered")
	}
	if _, err := os.Stat(filepath.Join(dir, "pending.json")); !os.IsNotExist(err) {
		t.Fatal("stale pending lock retained")
	}
}

func TestUpdateEndpointsRequireOwnSessionAndOrigin(t *testing.T) {
	a := authApp(t)
	a.updater = &updater{app: a, dir: t.TempDir(), client: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 404, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
	})}}
	if request(a, "/api/update", "", nil, "").Code != 401 {
		t.Fatal("anonymous update status accepted")
	}
	cookie := loggedInCookie(t, a)
	r := httpRequestForUpdate(a, "/api/update/check", cookie, "http://other.example")
	if r != 403 {
		t.Fatal("cross-origin update accepted")
	}
}

func httpRequestForUpdate(a *App, path string, cookie *http.Cookie, origin string) int {
	r := httptest.NewRequest("POST", "http://"+a.listen+path, strings.NewReader(`{}`))
	r.RemoteAddr = "192.168.1.20:12345"
	r.Header.Set("Origin", origin)
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	a.handle(w, r)
	return w.Code
}

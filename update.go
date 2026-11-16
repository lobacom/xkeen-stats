package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

var version = "dev"
var revision = "unknown"

const releaseRepository = "lobacom/xkeen-stats"
const releasePublicKey = "MeXlQXEJ/oazafi9vpo3hdUhxmpKB8fIHsSv6oGNCRM="
const maxUpdateBytes int64 = 64 << 20

var stableVersion = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

type releaseAsset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
	Size int64  `json:"size"`
}
type githubRelease struct {
	Tag        string         `json:"tag_name"`
	Draft      bool           `json:"draft"`
	Prerelease bool           `json:"prerelease"`
	Assets     []releaseAsset `json:"assets"`
}
type updateStatus struct {
	Current    string `json:"current"`
	Latest     string `json:"latest"`
	Available  bool   `json:"available"`
	Supported  bool   `json:"supported"`
	Checking   bool   `json:"checking"`
	Checked    int64  `json:"checked"`
	CheckError string `json:"check_error"`
	Phase      string `json:"phase"`
	Error      string `json:"error"`
	Target     string `json:"target"`
	ReleaseURL string `json:"release_url"`
}
type updateProgress struct {
	Phase  string `json:"phase"`
	Error  string `json:"error,omitempty"`
	Target string `json:"target"`
}
type updater struct {
	mu                 sync.Mutex
	app                *App
	dir                string
	client             *http.Client
	checking, working  bool
	checked            time.Time
	latest, checkError string
}

func versionNumbers(v string) ([3]uint64, bool) {
	var out [3]uint64
	m := stableVersion.FindStringSubmatch(strings.TrimSuffix(v, "-dev"))
	if m == nil {
		return out, false
	}
	for i := range out {
		n, err := strconv.ParseUint(m[i+1], 10, 32)
		if err != nil {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

func newerVersion(latest, current string) bool {
	a, ok := versionNumbers(latest)
	if !ok || !stableVersion.MatchString(latest) {
		return false
	}
	if current == "dev" {
		return true
	}
	b, ok := versionNumbers(current)
	if !ok {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return a[i] > b[i]
		}
	}
	return strings.HasSuffix(current, "-dev")
}

func platformAsset(goos, arch string) string {
	if goos != "linux" {
		return ""
	}
	switch arch {
	case "amd64", "arm64", "mips", "mipsle":
		return "xkeen-stats-linux-" + arch
	case "arm":
		return "xkeen-stats-linux-armv7"
	}
	return ""
}

func trustedUpdateURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Fragment != "" || u.Port() != "" {
		return false
	}
	switch u.Host {
	case "api.github.com", "github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com":
		return true
	}
	return false
}

func newUpdateClient() *http.Client {
	pool, _ := x509.SystemCertPool()
	if pool == nil {
		pool = x509.NewCertPool()
	}
	if pem, err := os.ReadFile("/opt/etc/ssl/certs/ca-certificates.crt"); err == nil {
		pool.AppendCertsFromPEM(pem)
	}
	return &http.Client{Timeout: 3 * time.Minute, Transport: &http.Transport{Proxy: http.ProxyFromEnvironment, TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) > 5 || !trustedUpdateURL(req.URL.String()) {
			return errors.New("untrusted release redirect")
		}
		return nil
	}}
}

func (u *updater) get(raw string, limit int64) ([]byte, int, error) {
	if !trustedUpdateURL(raw) {
		return nil, 0, errors.New("untrusted release URL")
	}
	req, err := http.NewRequest("GET", raw, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", "xkeen-stats/"+version)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := u.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, resp.StatusCode, fmt.Errorf("GitHub HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err == nil && int64(len(data)) > limit {
		err = errors.New("release metadata too large")
	}
	return data, resp.StatusCode, err
}

func (u *updater) fetchRelease() (githubRelease, error) {
	var r githubRelease
	data, status, err := u.get("https://api.github.com/repos/"+releaseRepository+"/releases/latest", 1<<20)
	if status == 404 {
		return r, nil
	}
	if err != nil {
		return r, err
	}
	if err = json.Unmarshal(data, &r); err != nil {
		return r, errors.New("invalid release metadata")
	}
	if r.Draft || r.Prerelease || !stableVersion.MatchString(r.Tag) {
		return r, errors.New("release is not a stable version")
	}
	return r, nil
}

func assetFor(r githubRelease, name string) (releaseAsset, error) {
	wanted := "https://github.com/" + releaseRepository + "/releases/download/" + r.Tag + "/" + name
	var found releaseAsset
	for _, a := range r.Assets {
		if a.Name == name {
			if found.Name != "" || a.URL != wanted || a.Size <= 0 || a.Size > maxUpdateBytes {
				return found, errors.New("invalid release asset")
			}
			found = a
		}
	}
	if found.Name == "" {
		return found, fmt.Errorf("release asset %s is missing", name)
	}
	return found, nil
}

func signedChecksum(manifest, signature []byte, tag, name string) (string, error) {
	public, err := base64.StdEncoding.DecodeString(releasePublicKey)
	if err != nil {
		return "", err
	}
	return verifyManifest(public, manifest, signature, tag, name)
}

func verifyManifest(public ed25519.PublicKey, manifest, signature []byte, tag, name string) (string, error) {
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(signature)))
	if err != nil || len(public) != ed25519.PublicKeySize || !ed25519.Verify(public, manifest, sig) {
		return "", errors.New("release signature verification failed")
	}
	return parseManifest(manifest, tag, name)
}

func parseManifest(manifest []byte, tag, name string) (string, error) {
	lines := strings.Split(strings.TrimSpace(string(manifest)), "\n")
	if len(lines) < 2 || lines[0] != "# xkeen-stats "+tag {
		return "", errors.New("signed manifest version mismatch")
	}
	found := ""
	seen := map[string]bool{}
	for _, line := range lines[1:] {
		f := strings.Fields(line)
		if len(f) != 2 || len(f[0]) != 64 || filepath.Base(f[1]) != f[1] || strings.ContainsAny(f[1], "/\\") || seen[f[1]] {
			return "", errors.New("invalid signed checksum manifest")
		}
		if _, err := hex.DecodeString(f[0]); err != nil {
			return "", err
		}
		seen[f[1]] = true
		if f[1] == name {
			found = strings.ToLower(f[0])
		}
	}
	if found == "" {
		return "", errors.New("platform checksum missing")
	}
	return found, nil
}

func (u *updater) startCheck(force bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	interval := 6 * time.Hour
	if force {
		interval = time.Minute
	}
	if u.checking || u.working || time.Since(u.checked) < interval {
		return
	}
	u.checking = true
	go func() {
		r, err := u.fetchRelease()
		u.mu.Lock()
		defer u.mu.Unlock()
		u.checking = false
		u.checked = time.Now()
		if err != nil {
			u.checkError = err.Error()
			return
		}
		u.checkError = ""
		u.latest = r.Tag
	}()
}

func (u *updater) status() updateStatus {
	u.mu.Lock()
	defer u.mu.Unlock()
	s := updateStatus{Current: version, Latest: u.latest, Supported: platformAsset(runtime.GOOS, runtime.GOARCH) != "", Available: newerVersion(u.latest, version), Checking: u.checking, CheckError: u.checkError}
	if !u.checked.IsZero() {
		s.Checked = u.checked.Unix()
	}
	if s.Latest != "" {
		s.ReleaseURL = "https://github.com/" + releaseRepository + "/releases/tag/" + s.Latest
	}
	var p updateProgress
	if readUpdateJSON(filepath.Join(u.dir, "status.json"), &p) == nil {
		s.Phase = p.Phase
		s.Error = p.Error
		s.Target = p.Target
	}
	if u.working && s.Phase != "downloading" && s.Phase != "installing" && s.Phase != "restarting" && s.Phase != "rollback" {
		s.Phase = "downloading"
	}
	return s
}

func (a *App) updateHandler(w http.ResponseWriter, r *http.Request) {
	if !a.authorized(r) {
		authReply(w, 401, "Требуется вход в статистику")
		return
	}
	if a.updater == nil {
		authReply(w, 503, "Обновление не настроено")
		return
	}
	u := a.updater
	if r.Method == "GET" && r.URL.Path == "/api/update" {
		u.startCheck(false)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(u.status())
		return
	}
	if !a.sameOriginPost(r) {
		authReply(w, 403, "Недопустимый источник запроса")
		return
	}
	if r.URL.Path == "/api/update/check" {
		u.startCheck(true)
		authReply(w, 202, "")
		return
	}
	if r.URL.Path != "/api/update/apply" {
		http.NotFound(w, r)
		return
	}
	var input struct {
		Version string `json:"version"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&input) != nil || !newerVersion(input.Version, version) {
		authReply(w, 400, "Нет подходящей новой версии")
		return
	}
	if platformAsset(runtime.GOOS, runtime.GOARCH) == "" {
		authReply(w, 400, "Эта платформа не поддерживает обновление")
		return
	}
	u.mu.Lock()
	if u.working || activePending(u.dir) {
		u.mu.Unlock()
		authReply(w, 409, "Обновление уже выполняется")
		return
	}
	u.working = true
	u.mu.Unlock()
	go func() {
		if err := u.prepare(input.Version); err != nil {
			_ = setUpdateProgress(u.dir, "failed", input.Version, err.Error())
			_ = os.Remove(filepath.Join(u.dir, "pending.json"))
			u.mu.Lock()
			u.working = false
			u.mu.Unlock()
		}
	}()
	authReply(w, 202, "")
}

func (u *updater) prepare(target string) error {
	if err := os.MkdirAll(u.dir, 0700); err != nil {
		return err
	}
	jobDir, err := os.MkdirTemp(u.dir, "job-")
	if err != nil {
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return err
	}
	j := updateJob{Directory: jobDir, Executable: executable, Candidate: filepath.Join(jobDir, "candidate"), Previous: filepath.Join(jobDir, "previous"), Service: "/opt/etc/init.d/S99xkeen-stats", Target: target, PreviousVersion: version, Listen: u.app.listen, Auth: u.app.authPath, State: u.app.statePath, Config: u.app.configPath, API: u.app.apiAddress}
	jobFile := filepath.Join(jobDir, "job.json")
	if err = writeUpdateJSON(jobFile, j); err != nil {
		return err
	}
	if err = writeUpdateJSON(filepath.Join(u.dir, "pending.json"), updatePending{Job: jobFile, PID: os.Getpid(), Preparing: true}); err != nil {
		return err
	}
	_ = setUpdateProgress(u.dir, "downloading", target, "")
	r, err := u.fetchRelease()
	if err != nil {
		return err
	}
	if r.Tag != target {
		return errors.New("latest version changed; check again")
	}
	name := platformAsset(runtime.GOOS, runtime.GOARCH)
	asset, err := assetFor(r, name)
	if err != nil {
		return err
	}
	manifestAsset, err := assetFor(r, "SHA256SUMS")
	if err != nil {
		return err
	}
	signatureAsset, err := assetFor(r, "SHA256SUMS.sig")
	if err != nil {
		return err
	}
	manifest, _, err := u.get(manifestAsset.URL, 65536)
	if err != nil {
		return err
	}
	signature, _, err := u.get(signatureAsset.URL, 256)
	if err != nil {
		return err
	}
	j.Checksum, err = signedChecksum(manifest, signature, target, name)
	if err != nil {
		return err
	}
	if err = u.download(asset, j.Candidate, j.Checksum); err != nil {
		return err
	}
	if err = checkCandidate(j); err != nil {
		return err
	}
	if err = writeUpdateJSON(jobFile, j); err != nil {
		return err
	}
	worker := filepath.Join(u.dir, "updater")
	if err = copyUpdateFile(executable, worker, 0700); err != nil {
		return err
	}
	logFile, err := os.OpenFile(filepath.Join(jobDir, "update.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	defer logFile.Close()
	cmd := exec.Command(worker, "-apply-update", jobFile)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err = cmd.Start(); err != nil {
		return err
	}
	if err = writeUpdateJSON(filepath.Join(u.dir, "pending.json"), updatePending{Job: jobFile, PID: cmd.Process.Pid}); err != nil {
		_ = cmd.Process.Kill()
		return err
	}
	return cmd.Process.Release()
}

func (u *updater) download(a releaseAsset, path, expected string) error {
	if !trustedUpdateURL(a.URL) {
		return errors.New("untrusted binary URL")
	}
	req, err := http.NewRequest("GET", a.URL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "xkeen-stats/"+version)
	resp, err := u.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("download HTTP %d", resp.StatusCode)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0700)
	if err != nil {
		return err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, maxUpdateBytes+1))
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
	if n != a.Size || n > maxUpdateBytes || hex.EncodeToString(h.Sum(nil)) != expected {
		return errors.New("download size or SHA256 mismatch")
	}
	return nil
}

func checkCandidate(j updateJob) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, j.Candidate, "-version").Output()
	if err != nil || strings.TrimSpace(string(output)) != j.Target {
		return errors.New("downloaded binary version check failed")
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel2()
	if err = exec.CommandContext(ctx2, j.Candidate, "-check-install", "-auth", j.Auth, "-state", j.State, "-config", j.Config).Run(); err != nil {
		return errors.New("new binary is incompatible with current data")
	}
	return nil
}

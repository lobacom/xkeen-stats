package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const managementFixture = `{
 "inbounds":[
 {"tag":"local-tcp","protocol":"tunnel","settings":{"allowedNetwork":"tcp","followRedirect":true}},
 {"tag":"local-udp","protocol":"tunnel","settings":{"allowedNetwork":"udp","followRedirect":true}},
 {"tag":"region-a","protocol":"vless","settings":{"decryption":"none","clients":[{"email":"alice","id":"11111111-1111-4111-8111-111111111111","level":3},{"email":"bob","id":"33333333-3333-4333-8333-333333333333"}]},"streamSettings":{"network":"xhttp","xhttpSettings":{"path":"/first/path","mode":"auto"}}},
 {"tag":"region-b","protocol":"vless","settings":{"decryption":"none","clients":[{"email":"alice","id":"22222222-2222-4222-8222-222222222222","level":4}]},"streamSettings":{"network":"xhttp","xhttpSettings":{"path":"/second/path"}}}],
 "outbounds":[{"tag":"exit-a","protocol":"vless","settings":{"private":"do-not-export"}},{"tag":"exit-b","protocol":"vless"},{"tag":"direct","protocol":"freedom"},{"tag":"blocked","protocol":"blackhole"}],
 "routing":{"domainStrategy":"IPIfNonMatch","rules":[
 {"inboundTag":["region-a","region-b"],"ip":["geoip:private"],"outboundTag":"blocked"},
 {"ip":["geoip:private"],"outboundTag":"direct"},
 {"inboundTag":["region-b"],"domain":["geosite:blocked"],"outboundTag":"exit-b"},
 {"domain":["geosite:blocked"],"outboundTag":"exit-a"},
 {"ip":["geoip:ru"],"outboundTag":"direct"},
 {"inboundTag":["region-b"],"outboundTag":"exit-b"},
 {"network":"tcp,udp","outboundTag":"exit-a"}]},
 "policy":{"levels":{"3":{"statsUserUplink":true}}}
}`

func fixtureConfig(t *testing.T) jsonObject {
	t.Helper()
	var cfg jsonObject
	if err := json.Unmarshal([]byte(managementFixture), &cfg); err != nil {
		t.Fatal(err)
	}
	return cfg
}
func fixtureManagement() managementConfig {
	var cfg managementConfig
	cfg.LAN.Inbounds = []string{"local-tcp", "local-udp"}
	cfg.LAN.Outbounds = []string{"exit-a", "exit-b"}
	cfg.LAN.BaseOutbound = "exit-a"
	cfg.Profiles = map[string]profileEndpoint{"region-a": {Address: "vpn.example.com", Port: 443, Parameters: map[string]string{"security": "tls", "sni": "vpn.example.com", "alpn": "h2", "fp": "firefox"}}, "region-b": {Address: "vpn.example.com", Port: 443, Parameters: map[string]string{"security": "tls", "sni": "vpn.example.com"}}}
	return cfg
}
func clientAt(cfg jsonObject, tag, name string) jsonObject {
	for _, v := range array(object(configuredTags(cfg, "inbounds")[tag]["settings"])["clients"]) {
		c := object(v)
		if str(c["email"]) == name {
			return c
		}
	}
	return nil
}

func TestClientEditingPreservesDifferentIDsAndOtherSettings(t *testing.T) {
	cfg := fixtureConfig(t)
	before := cloneObject(cfg)
	if err := changeClient(cfg, "alice", "alice-renamed", []string{"region-a", "region-b"}, false); err != nil {
		t.Fatal(err)
	}
	for _, tag := range []string{"region-a", "region-b"} {
		old := clientAt(before, tag, "alice")
		want := cloneObject(old)
		want["email"] = "alice-renamed"
		if !reflect.DeepEqual(clientAt(cfg, tag, "alice-renamed"), want) {
			t.Fatal("existing regional ID or extra fields changed")
		}
	}
	if !reflect.DeepEqual(cfg["routing"], before["routing"]) || !reflect.DeepEqual(cfg["outbounds"], before["outbounds"]) || !reflect.DeepEqual(clientAt(cfg, "region-a", "bob"), clientAt(before, "region-a", "bob")) {
		t.Fatal("unrelated configuration changed")
	}
	if err := changeClient(cfg, "alice-renamed", "alice-renamed", []string{"region-b"}, false); err != nil {
		t.Fatal(err)
	}
	if clientAt(cfg, "region-a", "alice-renamed") != nil || clientAt(cfg, "region-b", "alice-renamed")["id"] != clientAt(before, "region-b", "alice")["id"] {
		t.Fatal("input selection lost surviving credential")
	}
	if err := changeClient(cfg, "", "new-client", []string{"region-a", "region-b"}, false); err != nil {
		t.Fatal(err)
	}
	a := str(clientAt(cfg, "region-a", "new-client")["id"])
	b := str(clientAt(cfg, "region-b", "new-client")["id"])
	if len(a) != 36 || a == b {
		t.Fatal("new regional credentials not unique")
	}
	if err := changeClient(cfg, "new-client", "new-client", nil, true); err != nil {
		t.Fatal(err)
	}
	if clientAt(cfg, "region-a", "new-client") != nil || clientAt(cfg, "region-b", "new-client") != nil {
		t.Fatal("deleted client remains")
	}
	if changeClient(cfg, "", "bob", []string{"region-b"}, false) == nil || changeClient(cfg, "alice-renamed", "bob", []string{"region-b"}, false) == nil || changeClient(cfg, "", "bad", []string{"local-tcp"}, false) == nil {
		t.Fatal("conflict or unsupported input accepted")
	}
}

func TestLANSelectionPreservesDirectRulesAndExternalClients(t *testing.T) {
	cfg := fixtureConfig(t)
	original := cloneObject(cfg)
	mc := fixtureManagement()
	for _, exit := range []string{"exit-b", "exit-a", "exit-b"} {
		if err := switchLAN(cfg, mc, exit); err != nil {
			t.Fatal(err)
		}
		kept := []any{}
		managed := 0
		for _, v := range array(object(cfg["routing"])["rules"]) {
			r := object(v)
			if strings.HasPrefix(str(r["ruleTag"]), "xkeen-stats-lan-") {
				managed++
				if str(r["outboundTag"]) != exit || !reflect.DeepEqual(r["inboundTag"], []any{"local-tcp", "local-udp"}) {
					t.Fatal("LAN rule targets wrong traffic")
				}
			} else {
				kept = append(kept, v)
			}
		}
		if managed != 2 || !reflect.DeepEqual(kept, object(original["routing"])["rules"]) {
			t.Fatal("base routing changed or managed rules duplicated")
		}
		if !reflect.DeepEqual(cfg["inbounds"], original["inbounds"]) || !reflect.DeepEqual(cfg["outbounds"], original["outbounds"]) {
			t.Fatal("LAN switch changed endpoints or credentials")
		}
	}
	if switchLAN(cfg, mc, "not-allowed") == nil {
		t.Fatal("unapproved exit accepted")
	}
	mc.LAN.BaseOutbound = "nonexistent"
	b, _ := json.Marshal(cfg)
	if switchLAN(cfg, mc, "exit-a") == nil {
		t.Fatal("ambiguous routing accepted")
	}
	after, _ := json.Marshal(cfg)
	if !bytes.Equal(b, after) {
		t.Fatal("failed LAN switch mutated config")
	}
}

func TestProfileUsesMatchingInputCredentialAndExternalTLS(t *testing.T) {
	cfg := fixtureConfig(t)
	mc := fixtureManagement()
	for _, tag := range []string{"region-a", "region-b"} {
		uri, err := makeProfile(cfg, mc, "alice", tag)
		if err != nil {
			t.Fatal(err)
		}
		u, err := url.Parse(uri)
		if err != nil {
			t.Fatal(err)
		}
		if u.Host != "vpn.example.com:443" || u.User.Username() != clientAt(cfg, tag, "alice")["id"] || u.Query().Get("security") != "tls" || u.Query().Get("type") != "xhttp" || u.Query().Get("sni") != "vpn.example.com" {
			t.Fatal("export differs from selected endpoint")
		}
		if strings.Contains(uri, "do-not-export") {
			t.Fatal("outbound secret exported")
		}
	}
	delete(mc.Profiles, "region-b")
	if _, err := makeProfile(cfg, mc, "alice", "region-b"); err == nil {
		t.Fatal("guessed endpoint for reverse-proxied input")
	}
	if _, err := makeProfile(cfg, mc, "unknown", "region-a"); err == nil {
		t.Fatal("export for nonexistent client")
	}
}

func TestProfileNamesSupportInstallationPrefixWithoutChangingConnection(t *testing.T) {
	cfg := fixtureConfig(t)
	mc := fixtureManagement()
	oldURI, err := makeProfile(cfg, mc, "alice", "region-a")
	if err != nil {
		t.Fatal(err)
	}
	old, _ := url.Parse(oldURI)
	if old.Fragment != "region-a-alice" {
		t.Fatal("unexpected default profile name")
	}
	ep := mc.Profiles["region-a"]
	ep.NamePrefix = "office-tls-"
	mc.Profiles["region-a"] = ep
	uri, err := makeProfile(cfg, mc, "alice", "region-a")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(uri)
	if u.Fragment != "office-tls-alice" {
		t.Fatal("configured prefix missing")
	}
	u.Fragment = old.Fragment
	if u.String() != old.String() {
		t.Fatal("profile naming changed credentials or connection parameters")
	}
}

func TestProfilePrefixCanBeEditedWithoutRestartOrClientChanges(t *testing.T) {
	a := authApp(t)
	mc := fixtureManagement()
	mc.Source = a.configPath
	mc.Xray = os.Args[0]
	mc.Restart = []string{os.Args[0]}
	b, _ := json.Marshal(mc)
	var settings jsonObject
	_ = json.Unmarshal(b, &settings)
	settings["future_setting"] = "keep"
	b, _ = json.Marshal(settings)
	settingsPath := filepath.Join(filepath.Dir(a.authPath), "management.json")
	_ = os.WriteFile(settingsPath, b, 0600)
	_ = os.WriteFile(a.configPath, []byte(managementFixture), 0600)
	a.managementExec = func(managementConfig, []string, string) error {
		t.Fatal("prefix change executed Xray command")
		return nil
	}
	configured, configErr := a.managementConfig()
	if configErr != nil {
		t.Fatal(configErr)
	}
	mc = configured
	cookie := loggedInCookie(t, a)
	revision := managementSettingsRevision(mc)
	body := map[string]any{"settings_revision": revision, "inbound": "region-a", "prefix": "office-"}
	if managementRequest(a, "/api/manage/profile-name", body, nil, "http://"+a.listen).Code != 401 || managementRequest(a, "/api/manage/profile-name", body, cookie, "https://evil.example").Code != 403 {
		t.Fatal("prefix editing bypassed authorization")
	}
	w := managementRequest(a, "/api/manage/profile-name", body, cookie, "http://"+a.listen)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	var snapshot managementSnapshot
	if json.Unmarshal(w.Body.Bytes(), &snapshot) != nil {
		t.Fatal("invalid snapshot")
	}
	if managementRequest(a, "/api/manage/profile-name", body, cookie, "http://"+a.listen).Code != 409 {
		t.Fatal("stale prefix edit accepted")
	}
	updated, err := a.managementConfig()
	if err != nil || updated.Profiles["region-a"].NamePrefix != "office-" || updated.Profiles["region-b"].NamePrefix != "" {
		t.Fatal("prefix applied to wrong input")
	}
	var saved jsonObject
	b, _ = os.ReadFile(settingsPath)
	_ = json.Unmarshal(b, &saved)
	if saved["future_setting"] != "keep" {
		t.Fatal("unrelated management setting lost")
	}
	data, _ := os.ReadFile(a.configPath)
	if !bytes.Equal(data, []byte(managementFixture)) {
		t.Fatal("prefix editing modified Xray config")
	}
	body["settings_revision"] = snapshot.SettingsRevision
	body["prefix"] = ""
	w = managementRequest(a, "/api/manage/profile-name", body, cookie, "http://"+a.listen)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	updated, err = a.managementConfig()
	if err != nil {
		t.Fatal(err)
	}
	uri, err := makeProfile(fixtureConfig(t), updated, "alice", "region-a")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(uri)
	if u.Fragment != "region-a-alice" || strings.Contains(u.Fragment, "tls") {
		t.Fatal("neutral default unexpectedly assumes TLS")
	}
}

func managementRequest(a *App, path string, body any, cookie *http.Cookie, origin string) *httptest.ResponseRecorder {
	var b []byte
	method := "GET"
	if body != nil {
		method = "POST"
		b, _ = json.Marshal(body)
	}
	r := httptest.NewRequest(method, "http://"+a.listen+path, bytes.NewReader(b))
	r.RemoteAddr = "192.168.1.20:4000"
	r.Header.Set("Origin", origin)
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	a.handle(w, r)
	return w
}

func TestManagementSecretsRequireOwnSessionAndSameOrigin(t *testing.T) {
	a := authApp(t)
	mc := fixtureManagement()
	mc.Source = a.configPath
	mc.Xray = os.Args[0]
	mc.Restart = []string{os.Args[0]}
	b, _ := json.Marshal(mc)
	if err := os.WriteFile(filepath.Join(filepath.Dir(a.authPath), "management.json"), b, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(a.configPath, []byte(managementFixture), 0600); err != nil {
		t.Fatal(err)
	}
	profile := map[string]any{"name": "alice", "inbound": "region-a"}
	if managementRequest(a, "/api/manage/profile", profile, nil, "http://"+a.listen).Code != 401 {
		t.Fatal("anonymous export allowed")
	}
	cookie := loggedInCookie(t, a)
	if managementRequest(a, "/api/manage/profile", profile, cookie, "https://evil.example").Code != 403 {
		t.Fatal("cross-origin export allowed")
	}
	list := managementRequest(a, "/api/manage", nil, cookie, "")
	if list.Code != 200 || strings.Contains(list.Body.String(), "11111111-") || strings.Contains(list.Body.String(), "do-not-export") {
		t.Fatal("list leaks credentials")
	}
	w := managementRequest(a, "/api/manage/profile", profile, cookie, "http://"+a.listen)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	var data map[string]string
	if json.Unmarshal(w.Body.Bytes(), &data) != nil {
		t.Fatal("invalid profile response")
	}
	profileURL, parseErr := url.Parse(data["uri"])
	if parseErr != nil || data["name"] != "region-a-alice" || profileURL.Fragment != data["name"] {
		t.Fatal("dialog name and imported profile name differ")
	}
	png, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(data["qr"], "data:image/png;base64,"))
	if err != nil || !bytes.HasPrefix(png, []byte{137, 80, 78, 71}) {
		t.Fatal("QR not a local PNG")
	}
	w = managementRequest(a, "/api/manage/client", map[string]any{"revision": "stale", "name": "new", "inbounds": []string{"region-a"}}, cookie, "http://"+a.listen)
	if w.Code != 409 {
		t.Fatal("stale change accepted")
	}
}

func TestManagementValidationRollbackAndRecovery(t *testing.T) {
	for _, mode := range []string{"validation-fails", "restart-fails", "success", "crash-recovery"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			a := &App{authPath: filepath.Join(dir, "auth.json"), configPath: filepath.Join(dir, "active.json"), statePath: filepath.Join(dir, "state.json")}
			mc := fixtureManagement()
			mc.Source = filepath.Join(dir, "source.json")
			mc.Xray = os.Args[0]
			mc.Restart = []string{os.Args[0], "restart"}
			settings, _ := json.Marshal(mc)
			_ = os.WriteFile(filepath.Join(dir, "management.json"), settings, 0600)
			_ = os.WriteFile(a.configPath, []byte(managementFixture), 0600)
			_ = os.WriteFile(mc.Source, []byte(managementFixture), 0600)
			if err := a.load(); err != nil {
				t.Fatal(err)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Grpc-Status", "0")
				_, _ = w.Write(make([]byte, 5))
			}))
			defer server.Close()
			a.apiAddress = strings.TrimPrefix(server.URL, "http://")
			a.rpc = server.Client()
			restarts := 0
			a.managementExec = func(_ managementConfig, args []string, _ string) error {
				if len(args) > 1 && args[1] == "run" {
					if mode == "validation-fails" {
						return errors.New("bad config")
					}
					return nil
				}
				restarts++
				if mode == "restart-fails" && restarts == 1 {
					return errors.New("restart failed")
				}
				return nil
			}
			next := fixtureConfig(t)
			if err := changeClient(next, "", "new-client", []string{"region-a"}, false); err != nil {
				t.Fatal(err)
			}
			if mode == "crash-recovery" {
				backup := filepath.Join(a.managementDir(), "backups", "crash")
				if err := os.MkdirAll(backup, 0700); err != nil {
					t.Fatal(err)
				}
				for _, name := range []string{"active.json", "source.json"} {
					_ = os.WriteFile(filepath.Join(backup, name), []byte(managementFixture), 0600)
				}
				nb, _ := encodeManagedConfig(next)
				_ = os.WriteFile(a.configPath, nb, 0600)
				_ = os.WriteFile(mc.Source, nb, 0600)
				p, _ := json.Marshal(managementPending{a.configPath, mc.Source, backup})
				_ = os.WriteFile(filepath.Join(a.managementDir(), "pending.json"), p, 0600)
				if err := a.recoverManagement(); err != nil {
					t.Fatal(err)
				}
			} else {
				err := a.commitManagedConfig(mc, configRevision([]byte(managementFixture)), []byte(managementFixture), next)
				if (err == nil) != (mode == "success") {
					t.Fatalf("unexpected outcome: %v", err)
				}
			}
			for _, path := range []string{a.configPath, mc.Source} {
				b, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if mode == "success" {
					if !jsonEqual(b, mustEncode(next)) {
						t.Fatal("configuration not committed")
					}
				} else if !bytes.Equal(b, []byte(managementFixture)) {
					t.Fatal("old configuration not restored")
				}
			}
			if _, err := os.Stat(filepath.Join(a.managementDir(), "pending.json")); !os.IsNotExist(err) {
				t.Fatal("pending journal left after completed transaction")
			}
			if mode == "validation-fails" && restarts != 0 {
				t.Fatal("invalid config restarted Xray")
			}
		})
	}
}

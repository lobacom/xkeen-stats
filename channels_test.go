package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestChannelDescriptionsFollowConfigNotTagNames(t *testing.T) {
	dir := t.TempDir()
	config := `{"inbounds":[
	 {"tag":"anything-tcp","protocol":"tunnel","settings":{"allowedNetwork":"tcp","followRedirect":true}},
	 {"tag":"anything-udp","protocol":"dokodemo-door","settings":{"network":"udp","followRedirect":true},"streamSettings":{"sockopt":{"tproxy":"tproxy"}}},
	 {"tag":"home-de","protocol":"socks","settings":{"accounts":[{"user":"private-user","pass":"private-secret"}]}},
	 {"tag":"office","protocol":"vless","settings":{"clients":[{"email":"test-client","id":"private-id"}]},"streamSettings":{"network":"grpc","realitySettings":{"privateKey":"private-key"}}}],
	 "outbounds":[{"tag":"proxy-de","protocol":"blackhole"},{"tag":"block","protocol":"freedom"},{"tag":"another","protocol":"trojan","settings":{"servers":[{"address":"private-host","password":"private-password"}]}}]}`
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	a := &App{authPath: filepath.Join(dir, "auth.json"), configPath: path, statePath: filepath.Join(dir, "state.json")}
	if err := a.load(); err != nil {
		t.Fatal(err)
	}
	rows, err := a.rows()
	if err != nil {
		t.Fatal(err)
	}
	byKey := map[string]Row{}
	for _, row := range rows {
		byKey[row.Key] = row
	}
	for key, expected := range map[string]string{
		"inbound:anything-tcp": "Прозрачный прокси · TCP",
		"inbound:anything-udp": "Прозрачный прокси · UDP",
		"inbound:home-de":      "Прокси для приложений · SOCKS",
		"inbound:office":       "Клиентский вход · VLESS",
		"outbound:proxy-de":    "Блокировка",
		"outbound:block":       "Прямое подключение",
		"outbound:another":     "Прокси-выход · TROJAN",
	} {
		if byKey[key].Channel == nil || byKey[key].Channel.Title != expected {
			t.Fatalf("%s: %+v", key, byKey[key].Channel)
		}
	}
	if !strings.Contains(byKey["inbound:anything-udp"].Channel.Description, "TPROXY") || byKey["inbound:office"].Channel.Transport != "GRPC" {
		t.Fatal("protocol settings not reflected")
	}
	b, _ := json.Marshal(rows)
	for _, secret := range []string{"private-secret", "private-id", "private-key", "private-host", "private-password"} {
		if strings.Contains(string(b), secret) {
			t.Fatal("private configuration exposed")
		}
	}
	if byKey["user:test-client"].Channel != nil {
		t.Fatal("user mistaken for channel")
	}
}

func TestFreedomChainingIsNotDescribedAsDirect(t *testing.T) {
	var c channelConfig
	if err := json.Unmarshal([]byte(`{"tag":"direct","protocol":"freedom","streamSettings":{"sockopt":{"dialerProxy":"next-hop"}}}`), &c); err != nil {
		t.Fatal(err)
	}
	if info := describeChannel("outbound", c); info.Title == "Прямое подключение" || !strings.Contains(info.Description, "цепочки") {
		t.Fatal("chained freedom described as direct")
	}
}

func TestChannelLabelsAreLocalAndInvalidLabelsDoNotBlockStatistics(t *testing.T) {
	dir := t.TempDir()
	a := &App{authPath: filepath.Join(dir, "auth.json"), configPath: filepath.Join(dir, "config.json"), statePath: filepath.Join(dir, "state.json")}
	if err := os.WriteFile(a.configPath, []byte(`{"inbounds":[{"tag":"my-route","protocol":"vless"}],"outbounds":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := a.load(); err != nil {
		t.Fatal(err)
	}
	labelsPath := filepath.Join(dir, "labels.json")
	if err := os.WriteFile(labelsPath, []byte(`{"inbound:my-route":{"title":"Мой офис","description":"Корпоративный VPN"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	rows, err := a.rows()
	if err != nil || rows[0].Channel.Title != "Мой офис" || rows[0].Channel.Protocol != "VLESS" || a.labelsError != "" {
		t.Fatal("local label not applied or protocol lost")
	}
	if err := os.WriteFile(labelsPath, []byte(`{broken`), 0600); err != nil {
		t.Fatal(err)
	}
	rows, err = a.rows()
	if err != nil || len(rows) != 1 || rows[0].Channel.Title != "Клиентский вход · VLESS" || a.labelsError == "" {
		t.Fatal("invalid optional labels broke statistics or suppressed warning")
	}
	if err := os.Remove(labelsPath); err != nil {
		t.Fatal(err)
	}
	if _, err := a.rows(); err != nil || a.labelsError != "" {
		t.Fatal("optional labels required or stale error retained")
	}
}

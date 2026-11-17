package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func bypassFixture() bypassConfig {
	return bypassConfig{Version: 1, Interface: "br0", Rules: []bypassRule{
		{ID: "video", Name: "Видео", Enabled: true, Network: "all", Scope: "all", Destinations: []string{"198.51.100.0/24", "2001:db8::/48"}},
		{ID: "games", Name: "Игры", Enabled: true, Network: "udp", Ports: "27015-27140", Scope: "devices", Destinations: []string{"203.0.113.4"}, Devices: []bypassDevice{{MAC: "02:00:00:00:00:01", Name: "Computer"}}},
	}}
}

func TestBuiltInBypassTemplates(t *testing.T) {
	counts := map[string]int{"kinopoisk": 2, "telemost": 45, "vk": 8, "steam-sdr": 151}
	if len(builtinBypassTemplates) != len(counts) {
		t.Fatal("expected four built-in categories")
	}
	seen := map[string]bool{}
	for _, template := range builtinBypassTemplates {
		if seen[template.ID] || counts[template.ID] != len(template.Destinations) || template.Updated != "2026-11-17" || template.Description == "" {
			t.Fatal("invalid template metadata", template.ID)
		}
		seen[template.ID] = true
		rule := bypassRule{ID: template.ID, Name: template.Name, Enabled: true, Network: template.Network, Ports: template.Ports, Scope: template.Scope, Destinations: append([]string(nil), template.Destinations...)}
		if template.ID == "steam-sdr" {
			if template.Scope != "devices" || template.Network != "udp" || template.Ports != "27015-27140" {
				t.Fatal("Steam game scope changed")
			}
			rule.Devices = []bypassDevice{{MAC: "02:00:00:00:00:01", Name: "Selected computer"}}
		} else if template.Scope != "all" || template.Network != "all" || template.Ports != "" {
			t.Fatal("unexpected service defaults")
		}
		c, err := normalizeBypass(bypassConfig{Version: 1, Interface: "br0", Rules: []bypassRule{rule}})
		if err != nil || len(c.Rules[0].Destinations) != counts[template.ID] {
			t.Fatal("template cannot be saved", template.ID, err)
		}
		for _, address := range template.Destinations {
			if strings.Contains(address, ":") {
				t.Fatal("unverified IPv6 added to template")
			}
		}
	}
	a := &App{authPath: filepath.Join(t.TempDir(), "auth.json")}
	c, raw, err := a.readBypass()
	if err != nil {
		t.Fatal(err)
	}
	snapshot := a.bypassSnapshot(c, raw)
	if len(snapshot["templates"].([]bypassTemplate)) != 4 || len(c.Rules) != 0 || raw != nil {
		t.Fatal("catalogue enabled rules automatically")
	}
	if _, err := os.Stat(a.bypassPath()); !os.IsNotExist(err) {
		t.Fatal("reading catalogue wrote config")
	}
	var fields []map[string]any
	if err := json.Unmarshal(bypassTemplatesJSON, &fields); err != nil {
		t.Fatal(err)
	}
	for _, template := range fields {
		for _, key := range []string{"devices", "mac", "ip", "enabled"} {
			if _, ok := template[key]; ok {
				t.Fatal("installation-specific data in template", key)
			}
		}
	}
}

func TestBypassValidationAndStableDeviceIdentity(t *testing.T) {
	c := bypassFixture()
	c.Rules[1].Destinations = append(c.Rules[1].Destinations, "203.0.113.4/32")
	c.Rules[1].Devices[0].IP = "192.168.1.42"
	c.Rules[1].Devices[0].Online = true
	n, err := normalizeBypass(c)
	if err != nil || len(n.Rules[1].Destinations) != 1 || n.Rules[1].Devices[0].IP != "" || n.Rules[1].Devices[0].Online {
		t.Fatal(n, err)
	}
	for name, edit := range map[string]func(*bypassConfig){
		"empty-selected-devices": func(c *bypassConfig) { c.Rules[1].Devices = nil },
		"devices-on-all":         func(c *bypassConfig) { c.Rules[1].Scope = "all" },
		"broadcast-mac":          func(c *bypassConfig) { c.Rules[1].Devices[0].MAC = "ff:ff:ff:ff:ff:ff" },
		"zero-mac":               func(c *bypassConfig) { c.Rules[1].Devices[0].MAC = "00:00:00:00:00:00" },
		"bad-destination":        func(c *bypassConfig) { c.Rules[1].Destinations = []string{"example.com; reboot"} },
		"default-route":          func(c *bypassConfig) { c.Rules[1].Destinations = []string{"0.0.0.0/0"} },
		"mapped-v6":              func(c *bypassConfig) { c.Rules[1].Destinations = []string{"::ffff:203.0.113.4"} },
		"loopback":               func(c *bypassConfig) { c.Rules[1].Destinations = []string{"127.0.0.1"} },
		"invalid-interface":      func(c *bypassConfig) { c.Interface = "br0; reboot" },
		"duplicate-id":           func(c *bypassConfig) { c.Rules[1].ID = "video" },
		"injected-id":            func(c *bypassConfig) { c.Rules[1].ID = "games;reboot" },
		"port-with-all":          func(c *bypassConfig) { c.Rules[1].Network = "all" },
		"port-injection":         func(c *bypassConfig) { c.Rules[1].Ports = "443 -j ACCEPT" },
		"reverse-range":          func(c *bypassConfig) { c.Rules[1].Ports = "30000-27015" },
		"too-many-ranges":        func(c *bypassConfig) { c.Rules[1].Ports = strings.Repeat("80-90,", 7) + "80-90" },
	} {
		t.Run(name, func(t *testing.T) {
			c := bypassFixture()
			edit(&c)
			if _, err := normalizeBypass(c); err == nil {
				t.Fatal("invalid rule accepted")
			}
		})
	}
}

func TestBypassRenderingExitsWholeTableAndUsesMACSets(t *testing.T) {
	c, err := normalizeBypass(bypassFixture())
	if err != nil {
		t.Fatal(err)
	}
	c.Rules[1].Name = "$(do-not-execute) ' пользователь"
	p := renderBypass(c, strings.Repeat("a", 64), []int{4, 6})
	if !strings.Contains(string(p.SetData), "hash:mac") || !strings.Contains(string(p.SetData), "02:00:00:00:00:01") {
		t.Fatal("MAC selection missing")
	}
	for family, raw := range p.Restore {
		s := string(raw)
		if strings.Contains(s, "do-not-execute") || strings.Contains(s, "192.168.") || strings.Contains(s, "-F xkeen") || strings.Contains(s, "-F PREROUTING") {
			t.Fatal("unsafe render", s)
		}
		if strings.Count(s, "COMMIT") != 2 || !strings.Contains(s, "-j ACCEPT") || !strings.Contains(s, "-m connmark ! --mark 0x111") {
			t.Fatal("bypass would not terminate the parent table", s)
		}
		if family == 4 && (!strings.Contains(s, "--dports 27015:27140") || !strings.Contains(s, "_1m src")) {
			t.Fatal("game scope missing", s)
		}
		if family == 6 && strings.Contains(s, "xkst-bypass-rule:games") {
			t.Fatal("IPv4-only game leaked into IPv6")
		}
	}
	c.Rules[1].Enabled = false
	disabled := renderBypass(c, strings.Repeat("b", 64), []int{4, 6})
	if strings.Contains(string(disabled.SetData), "203.0.113.4") || strings.Contains(string(disabled.Restore[4]), "xkst-bypass-rule:games") {
		t.Fatal("disabled rule still bypasses")
	}
}

func TestBypassCommitCASRollbackAndInterruptedRecovery(t *testing.T) {
	a := &App{authPath: filepath.Join(t.TempDir(), "auth.json")}
	c, _ := normalizeBypass(bypassFixture())
	old, _ := json.Marshal(c)
	if err := atomicWrite(a.bypassPath(), old); err != nil {
		t.Fatal(err)
	}
	calls := []string{}
	a.bypassApply = func(c bypassConfig, _ string) error {
		name := c.Rules[0].Name
		calls = append(calls, name)
		if name == "fail" {
			return errors.New("simulated kernel failure")
		}
		return nil
	}
	next := bypassFixture()
	next.Rules[0].Name = "fail"
	if err := a.commitBypass(bypassRevision(old), next.Rules); err == nil {
		t.Fatal("kernel failure ignored")
	}
	b, _ := os.ReadFile(a.bypassPath())
	if string(b) != string(old) || !reflect.DeepEqual(calls, []string{"fail", "Видео"}) {
		t.Fatal("rollback failed", calls, string(b))
	}
	if _, err := os.Stat(filepath.Join(a.bypassDir(), "pending.json")); !os.IsNotExist(err) {
		t.Fatal("journal not cleared")
	}
	next.Rules[0].Name = "changed"
	if err := a.commitBypass(bypassRevision(old), next.Rules); err != nil {
		t.Fatal(err)
	}
	if err := a.commitBypass(bypassRevision(old), next.Rules); err == nil {
		t.Fatal("stale revision accepted")
	}
	_, current, _ := a.readBypass()
	journal, _ := json.Marshal(bypassPending{Old: old, NextRevision: bypassRevision(current)})
	_ = atomicWrite(filepath.Join(a.bypassDir(), "pending.json"), journal)
	if err := a.restoreBypass(); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(a.bypassPath())
	if string(b) != string(old) {
		t.Fatal("interrupted transaction not recovered")
	}
	// Изменения третьего редактора не затираются восстановлением.
	_ = atomicWrite(filepath.Join(a.bypassDir(), "pending.json"), journal)
	c.Rules[0].Name = "external"
	external, _ := json.Marshal(c)
	_ = atomicWrite(a.bypassPath(), external)
	if err := a.restoreBypass(); err == nil {
		t.Fatal("external edit silently overwritten")
	}
	b, _ = os.ReadFile(a.bypassPath())
	if string(b) != string(external) {
		t.Fatal("external edit lost")
	}
}

func TestBypassAPIAuthScopeValidationAndNoXrayRestart(t *testing.T) {
	a := authApp(t)
	a.managementExec = func(managementConfig, []string, string) error { t.Fatal("bypass restarted Xray"); return nil }
	applied := 0
	a.bypassApply = func(bypassConfig, string) error { applied++; return nil }
	body := map[string]any{"revision": bypassRevision(nil), "rules": bypassFixture().Rules}
	if managementRequest(a, "/api/bypass", nil, nil, "").Code != 401 {
		t.Fatal("anonymous config disclosure")
	}
	cookie := loggedInCookie(t, a)
	if managementRequest(a, "/api/bypass", body, cookie, "https://other.example").Code != 403 {
		t.Fatal("cross-origin write accepted")
	}
	before, _ := os.ReadFile(a.configPath)
	w := managementRequest(a, "/api/bypass", body, cookie, "http://"+a.listen)
	if w.Code != 200 || applied != 1 {
		t.Fatal(w.Code, w.Body, applied)
	}
	if managementRequest(a, "/api/bypass", body, cookie, "http://"+a.listen).Code != 409 {
		t.Fatal("stale write accepted")
	}
	after, _ := os.ReadFile(a.configPath)
	if string(before) != string(after) {
		t.Fatal("Xray config changed")
	}
	_, raw, _ := a.readBypass()
	bad := bypassFixture()
	bad.Rules[1].Devices = nil
	w = managementRequest(a, "/api/bypass", map[string]any{"revision": bypassRevision(raw), "rules": bad.Rules}, cookie, "http://"+a.listen)
	if w.Code == 200 || applied != 1 {
		t.Fatal("empty device scope broadened to all LAN")
	}
}

func TestBypassRuntimeOwnChainsIdempotencyAndCollision(t *testing.T) {
	c, _ := normalizeBypass(bypassFixture())
	raw, _ := json.Marshal(c)
	rev := bypassRevision(raw)
	a := &App{authPath: filepath.Join(t.TempDir(), "auth.json")}
	a.bypassHook = filepath.Join(filepath.Dir(a.authPath), "hook.sh")
	p := renderBypass(c, rev, []int{4, 6})
	restores := 0
	setLoads := 0
	marker := ""
	jump := false
	a.bypassRun = func(_ context.Context, name string, args []string, input []byte) ([]byte, error) {
		if name == "ipset" {
			if contains(args, "restore") {
				setLoads++
				return nil, nil
			}
			if contains(args, "-name") {
				return []byte(strings.Join(p.Sets, "\n")), nil
			}
			return nil, nil
		}
		if strings.HasSuffix(name, "-restore") {
			restores++
			s := string(input)
			if !strings.Contains(s, "-F "+bypassChain) || strings.Contains(s, "-F xkeen") {
				t.Fatal("foreign chain modified")
			}
			marker = bypassMarker + rev[:12]
			return nil, nil
		}
		if contains(args, "-S") && args[len(args)-1] == bypassChain {
			if marker == "" {
				return nil, errors.New("missing")
			}
			return []byte(marker), nil
		}
		if contains(args, "-C") && !jump {
			return nil, errors.New("missing jump")
		}
		if contains(args, "-I") {
			jump = true
		}
		if name != "iptables" && name != "ip6tables" {
			t.Fatal("unexpected command", name)
		}
		return nil, nil
	}
	if err := a.applyBypassConfig(c, raw); err != nil {
		t.Fatal(err)
	}
	if restores != 2 || setLoads != 1 {
		t.Fatal(restores, setLoads)
	}
	if err := a.applyBypassConfig(c, raw); err != nil {
		t.Fatal(err)
	}
	if restores != 2 || setLoads != 1 {
		t.Fatal("unchanged firewall rewritten", restores, setLoads)
	}
	// Нельзя перезаписывать постороннюю цепочку с совпавшим именем.
	a.bypassRun = func(_ context.Context, name string, args []string, input []byte) ([]byte, error) {
		if contains(args, "-S") {
			return []byte("-A " + bypassChain + " -j DROP"), nil
		}
		return nil, nil
	}
	if err := a.applyBypassConfig(c, raw); err == nil {
		t.Fatal("foreign chain overwritten")
	}
}

func TestBypassDeviceParsingRetainsOfflineAndSeparatesAdapters(t *testing.T) {
	var input any
	_ = json.Unmarshal([]byte(`{"hosts":[{"mac":"02:00:00:00:00:01","name":"PC","ip":"192.168.1.7","active":true},{"mac":"02:00:00:00:00:02","name":"PC Wi-Fi","ip":"0.0.0.0","active":false}]}`), &input)
	d := parseBypassDevices(input)
	if len(d) != 2 || !d[0].Online || d[1].IP != "" {
		t.Fatal(d)
	}
}

func TestBypassKernelFailureRollsBackAndCollectsPartialSets(t *testing.T) {
	a := &App{authPath: filepath.Join(t.TempDir(), "auth.json")}
	a.bypassHook = filepath.Join(filepath.Dir(a.authPath), "hook.sh")
	c, _ := normalizeBypass(bypassFixture())
	old, _ := json.Marshal(c)
	_ = atomicWrite(a.bypassPath(), old)
	sets := map[string]bool{}
	marker := ""
	fail := false
	a.bypassRun = func(_ context.Context, name string, args []string, input []byte) ([]byte, error) {
		if name == "ipset" {
			if contains(args, "restore") {
				for _, line := range strings.Split(string(input), "\n") {
					fields := strings.Fields(line)
					if len(fields) > 1 && fields[0] == "create" {
						sets[fields[1]] = true
					}
				}
			} else if contains(args, "destroy") {
				delete(sets, args[1])
			} else if contains(args, "-name") {
				var names []string
				for set := range sets {
					names = append(names, set)
				}
				return []byte(strings.Join(names, "\n")), nil
			}
			return nil, nil
		}
		if strings.HasSuffix(name, "-restore") {
			if fail {
				fail = false
				return nil, errors.New("kernel rejected candidate")
			}
			start := strings.Index(string(input), bypassMarker)
			marker = string(input)[start : start+len(bypassMarker)+12]
			return nil, nil
		}
		if contains(args, "-S") && args[len(args)-1] == bypassChain {
			if marker == "" {
				return nil, errors.New("missing")
			}
			return []byte(marker), nil
		}
		return nil, nil
	}
	if err := a.restoreBypass(); err != nil {
		t.Fatal(err)
	}
	c.Rules[0].Name = "Changed"
	fail = true
	if err := a.commitBypass(bypassRevision(old), c.Rules); err == nil {
		t.Fatal("kernel failure ignored")
	}
	_, restored, err := a.readBypass()
	if err != nil || string(restored) != string(old) {
		t.Fatal("old config not restored", err)
	}
	want := renderBypass(c, bypassRevision(old), []int{4, 6})
	if len(sets) != len(want.Sets) {
		t.Fatal("partial generation leaked", sets)
	}
	for _, set := range want.Sets {
		if !sets[set] {
			t.Fatal("old set missing", set)
		}
	}
	if a.bypassStatus().Error != "" {
		t.Fatal("successful recovery left failure status")
	}
}

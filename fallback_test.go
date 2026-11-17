package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func fallbackHealth(at int64, primary, reserve bool) exitHealth {
	return exitHealth{Enabled: true, Checked: at, StaleAfter: 360, Mode: "tcp", Outbounds: []exitStatus{
		{Tag: "exit-a", Supported: true, Scope: "server", Alive: primary, LastTry: at},
		{Tag: "exit-b", Supported: true, Scope: "server", Alive: reserve, LastTry: at},
	}}
}

func TestFallbackRequiresContinuousFailureAndHealthyReserve(t *testing.T) {
	settings := fallbackConfig{Enabled: true, Outbound: "exit-b", AfterMinutes: 10}
	r := fallbackRuntime{}
	for at := int64(1000); at <= 1600; at += 120 {
		if got := r.observe(settings, "exit-a", "direct", fallbackHealth(at, false, true), at); got != (at == 1600) {
			t.Fatalf("unexpected decision at %d: %v", at, got)
		}
	}
	if r.observe(settings, "exit-a", "direct", fallbackHealth(1720, false, false), 1720) {
		t.Fatal("unavailable reserve selected")
	}
	r.LastAttempt = 1720
	if r.observe(settings, "exit-a", "direct", fallbackHealth(1840, false, true), 1840) {
		t.Fatal("retry restart storm")
	}
	if r.observe(settings, "exit-b", "direct", fallbackHealth(1960, false, true), 1960) {
		t.Fatal("auto return/repeated reserve selection")
	}
	if r.DownSince != 0 {
		t.Fatal("timer survived switch")
	}
}

func TestFallbackResetsTimerOnRecoveryUnknownAndGaps(t *testing.T) {
	for _, mode := range []string{"recovery", "stale", "missing", "unsupported", "local", "error", "gap", "future", "clock-backwards", "disabled", "direct"} {
		t.Run(mode, func(t *testing.T) {
			r := fallbackRuntime{}
			settings := fallbackConfig{Enabled: true, Outbound: "exit-b", AfterMinutes: 10}
			r.observe(settings, "exit-a", "direct", fallbackHealth(1000, false, true), 1000)
			h := fallbackHealth(1120, false, true)
			now, current := int64(1120), "exit-a"
			switch mode {
			case "recovery":
				h.Outbounds[0].Alive = true
			case "stale":
				now = 2000
			case "missing":
				h.Outbounds = h.Outbounds[1:]
			case "unsupported":
				h.Outbounds[0].Supported = false
			case "local":
				h.Outbounds[0].Scope = "local"
			case "error":
				h.Error = "no results"
			case "gap":
				now = 2000
				h = fallbackHealth(now, false, true)
			case "future":
				h.Outbounds[0].LastTry = 1200
			case "clock-backwards":
				now = 900
				h = fallbackHealth(now, false, true)
			case "disabled":
				settings.Enabled = false
			case "direct":
				current = "direct"
			}
			if r.observe(settings, current, "direct", h, now) {
				t.Fatal("unsafe failover")
			}
			if r.DownSince == 1000 {
				t.Fatal("old failure window retained")
			}
		})
	}
}

func fallbackApp(t *testing.T) (*App, managementConfig) {
	t.Helper()
	a := authApp(t)
	mc := fixtureManagement()
	mc.Source = filepath.Join(filepath.Dir(a.authPath), "source.json")
	mc.Xray = os.Args[0]
	mc.Restart = []string{os.Args[0], "restart"}
	b, _ := json.Marshal(mc)
	for p, data := range map[string][]byte{filepath.Join(filepath.Dir(a.authPath), "management.json"): b, a.configPath: []byte(managementFixture), mc.Source: []byte(managementFixture)} {
		if err := os.WriteFile(p, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	// Не запускать настоящие фоновые сетевые проверки из транзакционного sample().
	a.lastHealthAttempt = time.Now().Add(time.Hour)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Grpc-Status", "0")
		_, _ = w.Write(make([]byte, 5))
	}))
	t.Cleanup(server.Close)
	a.rpc, a.apiAddress = server.Client(), strings.TrimPrefix(server.URL, "http://")
	return a, mc
}

func TestFallbackSettingsAuthorizationCASAndNoRestart(t *testing.T) {
	a, _ := fallbackApp(t)
	a.managementExec = func(managementConfig, []string, string) error { t.Fatal("saving reserve restarted Xray"); return nil }
	_, revision, err := a.readFallback()
	if err != nil {
		t.Fatal(err)
	}
	body := map[string]any{"revision": configRevision([]byte(managementFixture)), "fallback_revision": revision, "enabled": true, "outbound": "exit-b", "after_minutes": 10}
	cookie := loggedInCookie(t, a)
	for _, request := range []struct {
		cookie *http.Cookie
		origin string
		code   int
	}{{nil, "http://" + a.listen, 401}, {cookie, "https://evil.example", 403}, {cookie, "http://" + a.listen, 200}} {
		w := managementRequest(a, "/api/manage/fallback", body, request.cookie, request.origin)
		if w.Code != request.code {
			t.Fatal(w.Code, w.Body)
		}
	}
	if managementRequest(a, "/api/manage/fallback", body, cookie, "http://"+a.listen).Code != 409 {
		t.Fatal("stale settings overwrote newer choice")
	}
	c, revision, err := a.readFallback()
	if err != nil || !c.Enabled || c.Outbound != "exit-b" || c.AfterMinutes != 10 {
		t.Fatal(c, err)
	}
	if fresh := (&App{authPath: a.authPath}).fallbackSnapshot(); fresh.Outbound != "exit-b" {
		t.Fatal("settings lost on service restart")
	}
	body["fallback_revision"] = revision
	for key, value := range map[string]any{"after_minutes": 0, "outbound": "blocked"} {
		bad := map[string]any{}
		for k, v := range body {
			bad[k] = v
		}
		bad[key] = value
		if managementRequest(a, "/api/manage/fallback", bad, cookie, "http://"+a.listen).Code != 409 {
			t.Fatal("invalid settings accepted", key)
		}
	}
	b, _ := os.ReadFile(a.configPath)
	if !bytes.Equal(b, []byte(managementFixture)) {
		t.Fatal("saving reserve changed VPN config")
	}
}

func TestAutomaticFallbackUsesTransactionAndPreservesRemoteRoutes(t *testing.T) {
	for _, failure := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "rollback"}[failure], func(t *testing.T) {
			a, mc := fallbackApp(t)
			_, rev, _ := a.readFallback()
			if err := a.saveFallback(mc, fixtureConfig(t), rev, fallbackConfig{Enabled: true, Outbound: "exit-b", AfterMinutes: 10}); err != nil {
				t.Fatal(err)
			}
			restarts := 0
			a.managementExec = func(_ managementConfig, args []string, _ string) error {
				if len(args) > 1 && args[1] == "run" {
					return nil
				}
				restarts++
				if failure && restarts == 1 {
					return errors.New("restart failed")
				}
				return nil
			}
			for at := int64(1000); at <= 1600; at += 120 {
				a.exitHealth = fallbackHealth(at, false, true)
				a.evaluateFallback(time.Unix(at, 0))
			}
			actual, b, err := loadManagedConfig(a.configPath)
			if err != nil {
				t.Fatal(err)
			}
			original := fixtureConfig(t)
			if !reflect.DeepEqual(actual["inbounds"], original["inbounds"]) || !reflect.DeepEqual(actual["outbounds"], original["outbounds"]) {
				t.Fatal("remote clients or endpoints changed")
			}
			if failure {
				if !jsonEqual(b, []byte(managementFixture)) || a.fallbackRuntime.Error == "" || restarts != 2 {
					t.Fatal("rollback failed", a.fallbackRuntime, restarts)
				}
			} else {
				if a.managementSnapshot(mc, actual, b).LANExit != "exit-b" || restarts != 1 {
					t.Fatal("reserve not applied", restarts)
				}
				var remote []any
				for _, v := range array(object(actual["routing"])["rules"]) {
					if !managedLANRule(mc, str(object(v)["ruleTag"])) {
						remote = append(remote, v)
					}
				}
				if !reflect.DeepEqual(remote, object(original["routing"])["rules"]) {
					t.Fatal("original routes changed")
				}
				a.exitHealth = fallbackHealth(1720, false, false)
				a.evaluateFallback(time.Unix(1720, 0))
				if restarts != 1 {
					t.Fatal("repeated automatic switch")
				}
			}
			source, _ := os.ReadFile(mc.Source)
			if !jsonEqual(source, b) {
				t.Fatal("source not synchronized")
			}
		})
	}
}

func TestManualFallbackSwitchWorksWithAutomationDisabled(t *testing.T) {
	a, mc := fallbackApp(t)
	_, rev, _ := a.readFallback()
	if err := a.saveFallback(mc, fixtureConfig(t), rev, fallbackConfig{Outbound: "exit-b", AfterMinutes: 10}); err != nil {
		t.Fatal(err)
	}
	_, rev, _ = a.readFallback()
	restarts := 0
	a.managementExec = func(_ managementConfig, args []string, _ string) error {
		if len(args) > 1 && args[1] == "restart" {
			restarts++
		}
		return nil
	}
	body := map[string]any{"revision": configRevision([]byte(managementFixture)), "fallback_revision": rev}
	w := managementRequest(a, "/api/manage/fallback/switch", body, loggedInCookie(t, a), "http://"+a.listen)
	if w.Code != 200 || restarts != 1 {
		t.Fatal(w.Code, w.Body, restarts)
	}
}

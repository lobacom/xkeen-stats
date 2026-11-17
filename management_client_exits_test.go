package main

import (
	"path/filepath"
	"reflect"
	"testing"
)

func TestClientExitsIncludeConfiguredOutputsWithoutInventingProfiles(t *testing.T) {
	a := &App{authPath: filepath.Join(t.TempDir(), "auth.json")}
	cfg := fixtureConfig(t)
	mc := fixtureManagement()
	for _, region := range []string{"a", "b"} {
		tag := "exit-" + region + "-v4"
		cfg["outbounds"] = append(array(cfg["outbounds"]), jsonObject{"tag": tag, "protocol": "vless"})
		mc.LAN.Outbounds = append(mc.LAN.Outbounds, tag)
	}
	before := cloneObject(cfg)
	s := a.managementSnapshot(mc, cfg, []byte("snapshot"))
	if len(s.ClientExits) != 4 || len(s.Inputs) != 2 {
		t.Fatal("outputs missing or fake inputs created", s.ClientExits)
	}
	if !reflect.DeepEqual(s.ClientExits[0].Inputs, []string{"region-a"}) || !reflect.DeepEqual(s.ClientExits[1].Inputs, []string{"region-b"}) {
		t.Fatal("wrong exit binding", s.ClientExits)
	}
	if len(s.ClientExits[2].Inputs) != 0 || len(s.ClientExits[3].Inputs) != 0 {
		t.Fatal("missing IPv4 endpoints treated as ready")
	}
	if !reflect.DeepEqual(cfg, before) {
		t.Fatal("reading choices changed Xray config")
	}
	// Отдельные IPv4-входы получают собственные UUID и маршруты; имена выходов
	// произвольные: модель панели не зависит от страны, транспорта и суффикса тега.
	for _, region := range []string{"a", "b"} {
		tag := "region-" + region + "-v4"
		input := cloneObject(configuredTags(cfg, "inbounds")["region-"+region])
		input["tag"] = tag
		cfg["inbounds"] = append(array(cfg["inbounds"]), input)
		mc.Profiles[tag] = mc.Profiles["region-"+region]
		rules := array(object(cfg["routing"])["rules"])
		rule := jsonObject{"inboundTag": []any{tag}, "outboundTag": "exit-" + region + "-v4"}
		object(cfg["routing"])["rules"] = append([]any{rule}, rules...)
	}
	s = a.managementSnapshot(mc, cfg, []byte("snapshot2"))
	if len(s.ClientExits) != 4 || len(s.Inputs) != 4 || len(s.Clients[0].Inputs) != 4 {
		t.Fatal("four exits not exposed", s)
	}
	for _, exit := range s.ClientExits {
		if len(exit.Inputs) != 1 {
			t.Fatal("configured exit missing profile", exit)
		}
	}
	for _, tag := range s.Clients[0].Inputs {
		if _, err := makeProfile(cfg, mc, "alice", tag); err != nil {
			t.Fatal("profile export failed", tag, err)
		}
	}
}

func TestClientExitBindingUsesRoutingOrderAndRejectsAmbiguousNetworks(t *testing.T) {
	cfg := fixtureConfig(t)
	if clientDefaultOutbound(cfg, "region-b") != "exit-b" {
		t.Fatal("domain/IP exceptions changed default exit")
	}
	rules := array(object(cfg["routing"])["rules"])
	object(cfg["routing"])["rules"] = append([]any{jsonObject{"network": "tcp", "inboundTag": []any{"region-b"}, "outboundTag": "exit-a"}}, rules...)
	if clientDefaultOutbound(cfg, "region-b") != "" {
		t.Fatal("different TCP/UDP exits collapsed into one")
	}
	object(cfg["routing"])["rules"] = append([]any{jsonObject{"inboundTag": []any{"region-b"}, "balancerTag": "pool"}}, rules...)
	if clientDefaultOutbound(cfg, "region-b") != "" {
		t.Fatal("balancer falsely mapped to later fallback")
	}
	object(cfg["routing"])["rules"] = append([]any{jsonObject{"network": "tcp,udp", "outboundTag": "exit-a"}}, rules...)
	if clientDefaultOutbound(cfg, "region-b") != "exit-a" {
		t.Fatal("first global rule ignored")
	}
}

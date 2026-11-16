package main

import (
	"encoding/binary"
	"path/filepath"
	"testing"
	"time"
)

func TestXrayCommandIdentity(t *testing.T) {
	for _, cmd := range []string{"xray\x00api\x00statsquery\x00", "xray\x00run\x00-test\x00", "xray\x00run\x00-test=true\x00", "xray\x00version\x00"} {
		if isXrayServer([]byte(cmd)) {
			t.Fatalf("CLI helper mistaken for server: %q", cmd)
		}
	}
	if !isXrayServer([]byte("/opt/sbin/xray\x00run\x00")) {
		t.Fatal("server not recognized")
	}
}

func protoString(tag byte, s string) []byte {
	out := []byte{tag}
	out = binary.AppendUvarint(out, uint64(len(s)))
	return append(out, []byte(s)...)
}

func TestCounterDecode(t *testing.T) {
	stat := protoString(10, "user>>>demo-phone>>>traffic>>>downlink")
	stat = append(stat, 16)
	stat = binary.AppendUvarint(stat, 123456)
	data := protoString(10, string(stat))
	got, err := parseCounters(data)
	if err != nil || got["user:demo-phone"].Down != 123456 {
		t.Fatalf("%v %v", got, err)
	}
	if _, err = fields([]byte{10, 255}); err == nil {
		t.Fatal("truncated protobuf accepted")
	}
}

func TestOnlineDecode(t *testing.T) {
	ip := protoString(10, "203.0.113.9")
	u := protoString(10, "demo-phone")
	u = append(u, protoString(18, string(ip))...)
	result, err := parseOnline(protoString(10, string(u)))
	if err != nil || len(result["user:demo-phone"]) != 1 || result["user:demo-phone"][0] != "203.0.113.9" {
		t.Fatalf("%v %v", result, err)
	}
}

func TestAccumulationRestartAndPersistence(t *testing.T) {
	a := &App{statePath: filepath.Join(t.TempDir(), "state.json")}
	if err := a.load(); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, moscow)
	put := func(v int64, session string) {
		a.merge(map[string]Traffic{"user:test": {Down: v}}, nil, session, now)
		now = now.Add(5 * time.Second)
	}
	put(100, "boot:1")
	put(150, "boot:1")
	if a.state.Entries["user:test"].Total.Down != 150 || a.live["user:test"].Down != 10 {
		t.Fatal("same-session delta incorrect")
	}
	if err := a.save(); err != nil {
		t.Fatal(err)
	}
	b := &App{statePath: a.statePath}
	if err := b.load(); err != nil {
		t.Fatal(err)
	}
	b.merge(map[string]Traffic{"user:test": {Down: 180}}, nil, "boot:1", now)
	if b.state.Entries["user:test"].Total.Down != 180 {
		t.Fatal("collector restart double-counted")
	}
	a = b
	put(220, "boot:2")
	if a.state.Entries["user:test"].Total.Down != 400 {
		t.Fatal("Xray restart with larger counter lost traffic")
	}
	put(10, "boot:2")
	if a.state.Entries["user:test"].Total.Down != 410 {
		t.Fatal("counter reset lost traffic")
	}
}

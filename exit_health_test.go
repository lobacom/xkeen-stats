package main

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestObservatoryStatusDecode(t *testing.T) {
	v := []byte{8, 1, 16}
	v = binary.AppendUvarint(v, 217)
	v = append(v, protoString(26, "private server error must not be exposed")...)
	v = append(v, protoString(34, "vpn-a")...)
	v = append(v, 40)
	v = binary.AppendUvarint(v, 1700000000)
	v = append(v, 48)
	v = binary.AppendUvarint(v, 1700000010)
	response := protoString(10, string(protoString(10, string(v))))
	s, err := parseExitStatuses(response)
	if err != nil {
		t.Fatal(err)
	}
	if !s["vpn-a"].Alive || s["vpn-a"].Delay != 217 || s["vpn-a"].LastTry != 1700000010 {
		t.Fatal(s)
	}
	if _, err := parseExitStatuses([]byte{10, 255}); err == nil {
		t.Fatal("malformed message accepted")
	}
}

func TestTCPExitProbeAndChainedEndpoint(t *testing.T) {
	outs := map[string]jsonObject{"vpn": {"protocol": "vless", "settings": jsonObject{"vnext": []any{jsonObject{"address": "example.test", "port": 443}}}}, "chain": {"protocol": "freedom", "proxySettings": jsonObject{"tag": "vpn"}}}
	if address := exitTCPAddress("chain", outs, map[string]bool{}); address != "example.test:443" {
		t.Fatal(address)
	}
	outs["vpn"]["streamSettings"] = jsonObject{"network": "quic"}
	if exitTCPAddress("vpn", outs, map[string]bool{}) != "" {
		t.Fatal("UDP treated as TCP")
	}
	outs["chain"]["proxySettings"] = jsonObject{"tag": "chain"}
	if exitTCPAddress("chain", outs, map[string]bool{}) != "" {
		t.Fatal("proxy loop not bounded")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	s := probeTCPExit("test", address)
	if !s.Alive || !s.Supported || s.LastTry == 0 {
		t.Fatal("live server not detected", s)
	}
	_ = listener.Close()
	s = probeTCPExit("test", address)
	if s.Alive || !s.Supported || s.LastTry == 0 {
		t.Fatal("closed server not detected", s)
	}
	s = probeTCPExit("unsupported", "")
	if s.Alive || s.Supported || s.LastTry != 0 {
		t.Fatal("unsupported endpoint marked down")
	}
}

func TestProbeTargetOverridesAndLocalRelayScope(t *testing.T) {
	for _, address := range []string{"127.0.0.1:18443", "[::1]:18444", "localhost:443"} {
		if tcpExitScope(address) != "local" {
			t.Fatal("local relay presented as external", address)
		}
	}
	if tcpExitScope("[2001:db8::1]:443") != "server" {
		t.Fatal("IPv6 server not recognized")
	}
	dir := t.TempDir()
	auth := filepath.Join(dir, "auth.json")
	if err := os.WriteFile(filepath.Join(dir, "probes.json"), []byte(`{"vpn":"[2001:db8::1]:443"}`), 0600); err != nil {
		t.Fatal(err)
	}
	targets, err := readExitProbeTargets(auth)
	if err != nil || targets["vpn"] != "[2001:db8::1]:443" {
		t.Fatal(targets, err)
	}
	_ = os.WriteFile(filepath.Join(dir, "probes.json"), []byte(`{"vpn":"bad:99999"}`), 0600)
	if _, err := readExitProbeTargets(auth); err == nil {
		t.Fatal("invalid target accepted")
	}
}

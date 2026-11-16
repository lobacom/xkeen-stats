package main

import (
	"encoding/binary"
	"reflect"
	"testing"
)

func TestObservatoryEnablePreservesVPNAndExistingMonitor(t *testing.T) {
	c := jsonObject{"api": jsonObject{"services": []any{"StatsService"}}, "outbounds": []any{jsonObject{"tag": "direct", "protocol": "freedom"}, jsonObject{"tag": "vpn", "protocol": "vless"}, jsonObject{"tag": "chain", "protocol": "freedom", "proxySettings": jsonObject{"tag": "vpn"}}}}
	before := cloneObject(c)["outbounds"]
	if err := enableExitProbes(c); err != nil {
		t.Fatal(err)
	}
	obs := object(c["observatory"])
	if len(array(obs["subjectSelector"])) != 2 || !reflect.DeepEqual(before, c["outbounds"]) {
		t.Fatal("VPN config changed")
	}
	obs["probeInterval"] = "2m"
	if err := enableExitProbes(c); err != nil || object(c["observatory"])["probeInterval"] != "2m" || len(array(object(c["api"])["services"])) != 2 {
		t.Fatal("existing monitor changed")
	}
}

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

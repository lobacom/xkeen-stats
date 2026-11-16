package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestStatisticsInstallPreservesConfigurationAndIsIdempotent(t *testing.T) {
	c, err := decodeXrayObject([]byte(`{
 // комментарии Xray
 "api":{"tag":"existing-api","listen":"127.0.0.1:12345","services":["HandlerService"]},
 "inbounds":[{"tag":"vless","protocol":"vless","settings":{"clients":[{"id":"unchanged-id","email":"test","level":7}]}}],
 "outbounds":[{"tag":"vpn","protocol":"vless","settings":{"url":"https://example.test/a//b"}}],
 "policy":{"levels":{"7":{"handshake":8}},"system":{"statsInboundUplink":false}},
 "routing":{"rules":[{"outboundTag":"vpn"}]},"custom":9007199254740993
}`))
	if err != nil {
		t.Fatal(err)
	}
	next, api, err := statsSettings(c, "127.0.0.1:10085")
	if err != nil || api != "127.0.0.1:12345" {
		t.Fatal(api, err)
	}
	for _, key := range []string{"inbounds", "outbounds", "routing", "custom"} {
		if !reflect.DeepEqual(c[key], next[key]) {
			t.Fatalf("changed existing %s", key)
		}
	}
	if object(object(object(next["policy"])["levels"])["7"])["handshake"] != json.Number("8") {
		t.Fatal("existing policy lost")
	}
	services := array(object(next["api"])["services"])
	if len(services) != 2 || services[0] != "HandlerService" {
		t.Fatal("existing API service lost")
	}
	again, _, err := statsSettings(next, "127.0.0.1:10085")
	if err != nil || !reflect.DeepEqual(next, again) {
		t.Fatal("second install changes ready config", err)
	}
	object(next["api"])["listen"] = "0.0.0.0:10085"
	if _, _, err := statsSettings(next, ""); err == nil {
		t.Fatal("public API accepted")
	}
}

func TestSplitConfigViewAndComments(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{"01.json": `{"inbounds":[{"tag":"local","protocol":"socks"}],"outbounds":[{"tag":"direct","protocol":"freedom"}],"policy":{"levels":{"0":{"handshake":8}}}}`, "02.json": `{/* comment */ "inbounds":[{"tag":"local","protocol":"http"},{"tag":"remote","protocol":"vless"}],"outbounds":[{"tag":"vpn","protocol":"vless"}]}`, "03_tail.json": `{"outbounds":[{"tag":"last","protocol":"blackhole"}]}`}
	for file, b := range files {
		if err := os.WriteFile(filepath.Join(dir, file), []byte(b), 0600); err != nil {
			t.Fatal(err)
		}
	}
	c, _, err := readXrayObjects(dir)
	if err != nil {
		t.Fatal(err)
	}
	ins, outs := array(c["inbounds"]), array(c["outbounds"])
	if len(ins) != 2 || str(object(ins[0])["protocol"]) != "http" || len(outs) != 3 || str(object(outs[0])["tag"]) != "vpn" || str(object(outs[2])["tag"]) != "last" {
		t.Fatal("incorrect multi-file merge")
	}
	if _, err := decodeXrayObject([]byte(`{} {}`)); err == nil {
		t.Fatal("trailing JSON accepted")
	}
	if _, err := uncommentJSON([]byte(`{/* never ends`)); err == nil {
		t.Fatal("unterminated comment accepted")
	}
}

func TestSingleConfigPreservesDefaultOutboundAndSourceComparison(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	raw := []byte(`{"outbounds":[{"tag":"first","protocol":"freedom"},{"tag":"second","protocol":"vless"},{"tag":"third","protocol":"blackhole"}]}`)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	want, _ := decodeXrayObject(raw)
	got, _, err := readXrayObjects(path)
	if err != nil || !reflect.DeepEqual(want, got) {
		t.Fatal("outbound order or source comparison changed", err)
	}
}

func TestInstallationRollbackAndBackupIndex(t *testing.T) {
	dir := t.TempDir()
	backup := filepath.Join(dir, "backup")
	_ = os.Mkdir(backup, 0700)
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	_ = os.WriteFile(a, []byte("old"), 0600)
	files := map[string][]byte{a: []byte("new"), b: []byte("created")}
	modes := map[string]os.FileMode{a: 0600, b: 0600}
	backups, err := installFilesWithWriter(files, modes, backup, func(path string, data []byte) error {
		if path == b {
			return errors.New("simulated full disk")
		}
		return atomicWrite(path, data)
	})
	if err == nil {
		t.Fatal("write failure ignored")
	}
	if err := restoreInstallFiles(backups); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(a)
	if !bytes.Equal(got, []byte("old")) {
		t.Fatal("original not restored")
	}
	if _, err := os.Stat(b); !os.IsNotExist(err) {
		t.Fatal("created file remains")
	}
	if _, err := os.Stat(filepath.Join(backup, "files.json")); err != nil {
		t.Fatal("backup index missing")
	}
}

func TestLANConfigurationRejectsUnrestrictedAccess(t *testing.T) {
	for _, c := range [][2]string{{"0.0.0.0:1001", "10.0.0.0/24"}, {"10.0.0.1:1001", "0.0.0.0/0"}, {"10.0.0.1:1001", "192.168.1.0/24"}, {"10.0.0.1:99999", "10.0.0.0/24"}} {
		if _, err := validateLAN(c[0], c[1]); err == nil {
			t.Fatal("unsafe network accepted", c)
		}
	}
	if _, err := validateLAN("10.33.7.1:1001", "10.33.7.0/24"); err != nil {
		t.Fatal(err)
	}
}

func TestDetectXrayCommandPaths(t *testing.T) {
	args := augmentXrayArgs([]string{"xray", "run"}, []byte("XRAY_LOCATION_CONFDIR=/opt/etc/xray/configs\x00XRAY_LOCATION_ASSET=/opt/etc/xray/dat\x00"))
	if p, e := detectXrayPath(args); e != nil || p != "/opt/etc/xray/configs" {
		t.Fatal("environment config not detected", p, e)
	}
	for _, args := range [][]string{{"xray", "run", "-confdir", "/opt/etc/xray/configs"}, {"xray", "run", "-confdir=/opt/etc/xray/configs"}} {
		if p, e := detectXrayPath(args); e != nil || p != "/opt/etc/xray/configs" {
			t.Fatal(p, e)
		}
	}
	if _, e := detectXrayPath([]string{"xray", "run", "-c", "/one.json", "-c", "/two.json"}); e == nil {
		t.Fatal("ambiguous configs accepted")
	}
}

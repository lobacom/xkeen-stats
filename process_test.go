package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProcessTrackerRestartAndPIDReuse(t *testing.T) {
	root := t.TempDir()
	write := func(path, value string) {
		t.Helper()
		path = filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	proc := func(pid, start string) {
		write(pid+"/comm", "xray\n")
		write(pid+"/cmdline", "xray\x00run\x00")
		fs := strings.Fields(strings.Repeat("0 ", 22))
		fs[19] = start
		write(pid+"/stat", pid+" (xray) "+strings.Join(fs, " "))
	}
	write("sys/kernel/random/boot_id", "boot\n")
	proc("10", "100")
	p := processTracker{root: root}
	if p.session() != "boot:10:100" {
		t.Fatal("missing initial process")
	}
	proc("2", "50")
	if p.session() != "boot:10:100" {
		t.Fatal("cached live server was lost")
	}
	proc("10", "200")
	if p.session() != "boot:10:200" {
		t.Fatal("PID reuse hid a restart")
	}
	write("10/cmdline", "xray\x00run\x00-test\x00")
	if p.session() != "boot:2:50" {
		t.Fatal("test process mistaken for server")
	}
	_ = os.RemoveAll(filepath.Join(root, "2"))
	if p.session() != "" {
		t.Fatal("stopped server still present")
	}
}

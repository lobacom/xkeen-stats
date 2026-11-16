package main

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Между опросами проверяем найденный PID, а не перечитываем весь /proc дважды.
// Время старта защищает от повторного использования PID после перезапуска Xray.
type processTracker struct {
	mu              sync.Mutex
	root, boot, pid string
}

func (p *processTracker) identity(pid string) string {
	dir := filepath.Join(p.root, pid)
	comm, err := os.ReadFile(filepath.Join(dir, "comm"))
	if err != nil || strings.TrimSpace(string(comm)) != "xray" {
		return ""
	}
	cmd, err := os.ReadFile(filepath.Join(dir, "cmdline"))
	if err != nil || !isXrayServer(cmd) {
		return ""
	}
	stat, err := os.ReadFile(filepath.Join(dir, "stat"))
	if err != nil {
		return ""
	}
	_, tail, ok := strings.Cut(string(stat), ") ")
	fs := strings.Fields(tail)
	if !ok || len(fs) <= 19 {
		return ""
	}
	return p.boot + ":" + pid + ":" + fs[19]
}

func (p *processTracker) session() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.boot == "" {
		b, err := os.ReadFile(filepath.Join(p.root, "sys/kernel/random/boot_id"))
		if err != nil {
			return ""
		}
		p.boot = strings.TrimSpace(string(b))
	}
	if p.pid != "" {
		if id := p.identity(p.pid); id != "" {
			return id
		}
		p.pid = ""
	}
	dirs, _ := filepath.Glob(filepath.Join(p.root, "[0-9]*", "comm"))
	for _, path := range dirs {
		pid := filepath.Base(filepath.Dir(path))
		if id := p.identity(pid); id != "" {
			p.pid = pid
			return id
		}
	}
	return ""
}

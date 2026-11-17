package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type exitStatus struct {
	Tag       string `json:"tag"`
	Alive     bool   `json:"alive"`
	Delay     int64  `json:"delay_ms"`
	LastSeen  int64  `json:"last_seen"`
	LastTry   int64  `json:"last_try"`
	Supported bool   `json:"supported"`
	Scope     string `json:"scope,omitempty"`
}

type exitHealth struct {
	Enabled    bool         `json:"enabled"`
	Checked    int64        `json:"checked"`
	StaleAfter int64        `json:"stale_after"`
	Error      string       `json:"error"`
	Outbounds  []exitStatus `json:"outbounds"`
	Mode       string       `json:"mode"`
}

func isVPNExit(c jsonObject) bool {
	switch str(c["protocol"]) {
	case "", "blackhole", "dns", "loopback":
		return false
	case "freedom":
		return str(object(c["proxySettings"])["tag"]) != "" || str(object(object(c["streamSettings"])["sockopt"])["dialerProxy"]) != ""
	default:
		return true
	}
}

// Проверяется только открытие TCP, без TLS, авторизации и передачи VPN-трафика.
// Ничего не добавляется в конфигурацию Xray. UDP-ядра не объявляются недоступными.
func exitTCPAddress(tag string, outs map[string]jsonObject, seen map[string]bool) string {
	if seen[tag] {
		return ""
	}
	seen[tag] = true
	c := outs[tag]
	if str(c["protocol"]) == "freedom" {
		upstream := str(object(c["proxySettings"])["tag"])
		if upstream == "" {
			upstream = str(object(object(c["streamSettings"])["sockopt"])["dialerProxy"])
		}
		return exitTCPAddress(upstream, outs, seen)
	}
	switch str(c["protocol"]) {
	case "vless", "vmess", "trojan", "shadowsocks", "socks", "http":
	default:
		return ""
	}
	network := str(object(c["streamSettings"])["network"])
	switch network {
	case "quic", "kcp", "mkcp", "hysteria", "hysteria2":
		return ""
	}
	settings := object(c["settings"])
	for _, key := range []string{"vnext", "servers"} {
		for _, v := range array(settings[key]) {
			server := object(v)
			host := str(server["address"])
			port, err := strconv.Atoi(fmt.Sprint(server["port"]))
			if host != "" && err == nil && port > 0 && port <= 65535 {
				return net.JoinHostPort(host, strconv.Itoa(port))
			}
		}
	}
	return ""
}

func probeTCPExit(tag, address string) exitStatus {
	s := exitStatus{Tag: tag, Supported: address != "", Scope: tcpExitScope(address)}
	if !s.Supported {
		return s
	}
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	s.LastTry = time.Now().Unix()
	if err == nil {
		_ = conn.Close()
		s.Alive = true
		s.Delay = time.Since(start).Milliseconds()
		s.LastSeen = s.LastTry
	}
	return s
}

func tcpExitScope(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return ""
	}
	ip := net.ParseIP(host)
	if (ip != nil && (ip.IsLoopback() || ip.IsUnspecified())) || strings.TrimSuffix(strings.ToLower(host), ".") == "localhost" || strings.HasSuffix(strings.TrimSuffix(strings.ToLower(host), "."), ".localhost") {
		return "local"
	}
	return "server"
}

func readExitProbeTargets(authPath string) (map[string]string, error) {
	b, err := os.ReadFile(filepath.Join(filepath.Dir(authPath), "probes.json"))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(b) > 65536 {
		return nil, errors.New("probe settings too large")
	}
	var targets map[string]string
	if err := json.Unmarshal(b, &targets); err != nil {
		return nil, err
	}
	if len(targets) > 64 {
		return nil, errors.New("too many probe targets")
	}
	for tag, address := range targets {
		host, port, e := net.SplitHostPort(address)
		n, _ := strconv.Atoi(port)
		if e != nil || host == "" || n < 1 || n > 65535 || tag == "" || strings.ContainsAny(host, "\r\n\t ") {
			return nil, errors.New("invalid TCP probe target")
		}
	}
	return targets, nil
}

func parseExitStatuses(data []byte) (map[string]exitStatus, error) {
	result := map[string]exitStatus{}
	outer, err := fields(data)
	if err != nil {
		return nil, err
	}
	for _, f := range outer {
		if f.Number != 1 || f.Wire != 2 {
			continue
		}
		observations, err := fields(f.Bytes)
		if err != nil {
			return nil, err
		}
		for _, ob := range observations {
			if ob.Number != 1 || ob.Wire != 2 {
				continue
			}
			fs, err := fields(ob.Bytes)
			if err != nil {
				return nil, err
			}
			s := exitStatus{Supported: true}
			for _, v := range fs {
				switch v.Number {
				case 1:
					s.Alive = v.Int != 0
				case 2:
					s.Delay = int64(v.Int)
				case 4:
					s.Tag = string(v.Bytes)
				case 5:
					s.LastSeen = int64(v.Int)
				case 6:
					s.LastTry = int64(v.Int)
				}
			}
			if s.Tag != "" {
				result[s.Tag] = s
			}
		}
	}
	return result, nil
}

func (a *App) sampleExitHealth() {
	a.mu.Lock()
	if a.healthWorking || time.Since(a.lastHealthAttempt) < 2*time.Minute {
		a.mu.Unlock()
		return
	}
	a.healthWorking = true
	a.lastHealthAttempt = time.Now()
	a.mu.Unlock()
	go a.collectExitHealth()
}

func (a *App) collectExitHealth() {
	h := exitHealth{StaleAfter: 360, Outbounds: []exitStatus{}, Mode: "tcp"}
	defer func() {
		a.mu.Lock()
		a.exitHealth = h
		a.healthWorking = false
		a.mu.Unlock()
		a.evaluateFallback(time.Now())
	}()
	c, _, err := readXrayObjects(a.configPath)
	if err != nil {
		h.Error = "Не удалось прочитать настройки проверки выходов"
		return
	}
	obs := object(c["observatory"])
	if obs == nil {
		targets, err := readExitProbeTargets(a.authPath)
		if err != nil {
			h.Enabled = true
			h.Error = "Не удалось прочитать настройки проверки серверов"
			return
		}
		a.mu.Lock()
		previous := map[string]int64{}
		for _, s := range a.exitHealth.Outbounds {
			previous[s.Tag] = s.LastSeen
		}
		a.mu.Unlock()
		outs := configuredTags(c, "outbounds")
		var tags []string
		for tag, o := range outs {
			if isVPNExit(o) {
				tags = append(tags, tag)
			}
		}
		sort.Strings(tags)
		h.Enabled = len(tags) > 0
		// Один запрос за раз, не более трёх секунд на сервер и 15 секунд на цикл.
		deadline := time.Now().Add(15 * time.Second)
		for _, tag := range tags {
			address := exitTCPAddress(tag, outs, map[string]bool{})
			if target := targets[tag]; target != "" {
				address = target
			}
			if time.Now().After(deadline) {
				h.Outbounds = append(h.Outbounds, exitStatus{Tag: tag, Supported: address != "", Scope: tcpExitScope(address)})
				continue
			}
			s := probeTCPExit(tag, address)
			if !s.Alive {
				s.LastSeen = previous[tag]
			}
			h.Outbounds = append(h.Outbounds, s)
		}
		h.Checked = time.Now().Unix()
		return
	}
	h.Mode = "observatory"
	h.StaleAfter = 180
	h.Enabled = true
	if interval, err := time.ParseDuration(str(obs["probeInterval"])); err == nil && interval > time.Minute {
		h.StaleAfter = int64((interval * 3) / time.Second)
	}
	wanted := map[string]bool{}
	for _, v := range array(c["outbounds"]) {
		tag := str(object(v)["tag"])
		if tag == "" {
			continue
		}
		for _, s := range array(obs["subjectSelector"]) {
			if strings.HasPrefix(tag, str(s)) {
				wanted[tag] = true
			}
		}
	}
	for tag := range wanted {
		h.Outbounds = append(h.Outbounds, exitStatus{Tag: tag})
	}
	sort.Slice(h.Outbounds, func(i, j int) bool { return h.Outbounds[i].Tag < h.Outbounds[j].Tag })
	data, err := a.rpcCall("xray.core.app.observatory.command.ObservatoryService", "GetOutboundStatus")
	if err != nil {
		h.Error = "Не удалось получить результаты проверки VPN-выходов"
		return
	}
	statuses, err := parseExitStatuses(data)
	if err != nil {
		h.Error = "Не удалось прочитать результаты проверки выходов"
		return
	}
	for i, s := range h.Outbounds {
		if value, ok := statuses[s.Tag]; ok {
			h.Outbounds[i] = value
		}
	}
	h.Checked = time.Now().Unix()
}

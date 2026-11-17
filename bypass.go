package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

type bypassDevice struct {
	MAC    string `json:"mac"`
	Name   string `json:"name"`
	IP     string `json:"ip,omitempty"`
	Online bool   `json:"online,omitempty"`
}
type bypassRule struct {
	ID           string         `json:"id"`
	Name         string         `json:"name"`
	Enabled      bool           `json:"enabled"`
	Network      string         `json:"network"`
	Ports        string         `json:"ports"`
	Scope        string         `json:"scope"`
	Destinations []string       `json:"destinations"`
	Devices      []bypassDevice `json:"devices"`
}
type bypassConfig struct {
	Version   int          `json:"version"`
	Interface string       `json:"interface"`
	Rules     []bypassRule `json:"rules"`
}
type bypassPending struct {
	Old          []byte `json:"old"`
	NextRevision string `json:"next_revision"`
}
type bypassStatus struct {
	Revision string   `json:"revision"`
	Applied  int64    `json:"applied"`
	Error    string   `json:"error,omitempty"`
	Boot     string   `json:"boot"`
	Sets     []string `json:"sets"`
	Families []int    `json:"families"`
}

var bypassID = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)
var bypassInterfaceName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}$`)

func normalizeBypass(c bypassConfig) (bypassConfig, error) {
	if c.Version != 1 || !bypassInterfaceName.MatchString(c.Interface) || len(c.Rules) > 32 {
		return c, errors.New("Некорректные настройки обхода: до 32 правил")
	}
	ids := map[string]bool{}
	total := 0
	for i := range c.Rules {
		r := &c.Rules[i]
		r.Name = strings.TrimSpace(r.Name)
		if !bypassID.MatchString(r.ID) || ids[r.ID] || !utf8.ValidString(r.Name) || len([]rune(r.Name)) < 1 || len([]rune(r.Name)) > 80 || strings.ContainsAny(r.Name, "\x00\r\n") {
			return c, errors.New("У правила должны быть уникальный идентификатор и название до 80 символов")
		}
		ids[r.ID] = true
		if r.Network != "all" && r.Network != "tcp" && r.Network != "udp" {
			return c, errors.New("Протокол должен быть TCP, UDP или все")
		}
		ports, err := normalizeBypassPorts(r.Ports)
		if err != nil || (r.Network == "all" && ports != "") {
			return c, errors.New("Для портов выберите TCP или UDP; используйте числа, запятые и диапазоны 1-65535")
		}
		r.Ports = ports
		if len(r.Destinations) == 0 || len(r.Destinations) > 2048 || len(r.Devices) > 64 {
			return c, errors.New("Укажите 1–2048 адресов и не более 64 устройств на правило")
		}
		if r.Scope != "all" && r.Scope != "devices" || r.Scope == "all" && len(r.Devices) != 0 || r.Scope == "devices" && len(r.Devices) == 0 {
			return c, errors.New("Выберите все LAN-устройства или хотя бы одно устройство по MAC")
		}
		dest := map[string]bool{}
		for _, value := range r.Destinations {
			value = strings.TrimSpace(value)
			p, e := netip.ParsePrefix(value)
			if e != nil {
				ip, e := netip.ParseAddr(value)
				if e != nil {
					return c, fmt.Errorf("Некорректный IP или подсеть: %s", value)
				}
				p = netip.PrefixFrom(ip, ip.BitLen())
			}
			if p.Addr().Is4In6() || p.Bits() == 0 || !p.Addr().IsGlobalUnicast() || p.Addr().IsLoopback() || p.Addr().Zone() != "" {
				return c, errors.New("Укажите отдельные адреса или подсети; маршрут по умолчанию и специальные адреса не поддерживаются")
			}
			dest[p.Masked().String()] = true
		}
		r.Destinations = nil
		for value := range dest {
			r.Destinations = append(r.Destinations, value)
		}
		sort.Strings(r.Destinations)
		total += len(r.Destinations)
		if total > 4096 {
			return c, errors.New("Суммарно разрешено до 4096 адресов и подсетей")
		}
		macs := map[string]bool{}
		for j := range r.Devices {
			d := &r.Devices[j]
			m, e := net.ParseMAC(d.MAC)
			if e != nil || len(m) != 6 || m[0]&1 != 0 || m.String() == "00:00:00:00:00:00" {
				return c, errors.New("Некорректный MAC-адрес устройства")
			}
			d.MAC = m.String()
			if macs[d.MAC] {
				return c, errors.New("Устройство выбрано повторно")
			}
			macs[d.MAC] = true
			d.Name = strings.TrimSpace(d.Name)
			if !utf8.ValidString(d.Name) || len([]rune(d.Name)) > 80 || strings.ContainsAny(d.Name, "\x00\r\n") {
				return c, errors.New("Некорректное имя устройства")
			}
			d.IP, d.Online = "", false
		}
		if r.Devices == nil {
			r.Devices = []bypassDevice{}
		}
	}
	if c.Rules == nil {
		c.Rules = []bypassRule{}
	}
	return c, nil
}

func normalizeBypassPorts(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	parts := strings.Split(value, ",")
	if len(parts) > 15 {
		return "", errors.New("too many ports")
	}
	for i, part := range parts {
		bounds := strings.Split(strings.TrimSpace(part), "-")
		if len(bounds) > 2 {
			return "", errors.New("invalid range")
		}
		numbers := []int{}
		for _, b := range bounds {
			if b == "" || strings.Trim(b, "0123456789") != "" {
				return "", errors.New("invalid port")
			}
			n, err := strconv.Atoi(b)
			if err != nil || n < 1 || n > 65535 {
				return "", errors.New("invalid port")
			}
			numbers = append(numbers, n)
		}
		if len(numbers) == 2 && numbers[0] > numbers[1] {
			return "", errors.New("reversed range")
		}
		parts[i] = strconv.Itoa(numbers[0])
		if len(numbers) == 2 {
			parts[i] += "-" + strconv.Itoa(numbers[1])
		}
	}
	// multiport считает диапазон за два элемента.
	slots := len(parts) + strings.Count(strings.Join(parts, ","), "-")
	if slots > 15 {
		return "", errors.New("too many port slots")
	}
	return strings.Join(parts, ","), nil
}

func (a *App) bypassPath() string { return filepath.Join(filepath.Dir(a.authPath), "bypass.json") }
func (a *App) bypassDir() string  { return filepath.Join(filepath.Dir(a.authPath), "bypass") }
func (a *App) readBypass() (bypassConfig, []byte, error) {
	iface := a.bypassInterface
	if iface == "" {
		iface = "br0"
	}
	c := bypassConfig{Version: 1, Interface: iface, Rules: []bypassRule{}}
	b, err := os.ReadFile(a.bypassPath())
	if os.IsNotExist(err) {
		return c, nil, nil
	}
	if err != nil {
		return c, nil, err
	}
	if len(b) > 256<<10 {
		return c, nil, errors.New("Файл правил слишком большой")
	}
	if err = json.Unmarshal(b, &c); err != nil {
		return c, nil, err
	}
	c, err = normalizeBypass(c)
	return c, b, err
}
func bypassRevision(b []byte) string { return configRevision(b) }
func (a *App) bypassStatus() bypassStatus {
	var s bypassStatus
	b, _ := os.ReadFile(filepath.Join(a.bypassDir(), "status.json"))
	_ = json.Unmarshal(b, &s)
	return s
}
func (a *App) bypassSnapshot(c bypassConfig, b []byte) map[string]any {
	s := a.bypassStatus()
	boot, _ := os.ReadFile("/proc/sys/kernel/random/boot_id")
	return map[string]any{"available": runtime.GOOS == "linux" || a.bypassApply != nil, "revision": bypassRevision(b), "rules": c.Rules, "templates": builtinBypassTemplates,
		"configured": len(b) > 0, "applied": s.Applied, "active": s.Revision == bypassRevision(b) && s.Error == "" && s.Boot == strings.TrimSpace(string(boot)), "error": s.Error}
}

func (a *App) commitBypass(revision string, rules []bypassRule) error {
	unlock, err := lockBypass(filepath.Join(a.bypassDir(), "apply.lock"))
	if err != nil {
		return err
	}
	defer unlock()
	if err = a.recoverBypassLocked(); err != nil {
		return err
	}
	c, old, err := a.readBypass()
	if err != nil {
		return err
	}
	if revision == "" || revision != bypassRevision(old) {
		return errors.New("Правила изменились. Обновите список перед сохранением")
	}
	c.Rules = rules
	c, err = normalizeBypass(c)
	if err != nil {
		return err
	}
	next, _ := json.MarshalIndent(c, "", "  ")
	next = append(next, '\n')
	if string(old) == string(next) {
		return nil
	}
	backup := filepath.Join(filepath.Dir(a.authPath), "backups", "bypass-"+time.Now().UTC().Format("20060102T150405.000000000Z"))
	if err = atomicWrite(filepath.Join(backup, "previous.json"), old); err != nil {
		return err
	}
	if err = atomicWrite(filepath.Join(backup, "next.json"), next); err != nil {
		return err
	}
	journal, _ := json.Marshal(bypassPending{old, bypassRevision(next)})
	if err = atomicWrite(filepath.Join(a.bypassDir(), "pending.json"), journal); err != nil {
		return err
	}
	if err = atomicWrite(a.bypassPath(), next); err == nil {
		err = a.applyBypassConfig(c, next)
	}
	if err != nil {
		if rollback := a.recoverBypassLocked(); rollback != nil {
			return fmt.Errorf("Не удалось применить правила (%v); восстановление: %v", err, rollback)
		}
		return fmt.Errorf("Правила не применены, прежние настройки восстановлены: %w", err)
	}
	return os.Remove(filepath.Join(a.bypassDir(), "pending.json"))
}

func (a *App) recoverBypassLocked() error {
	path := filepath.Join(a.bypassDir(), "pending.json")
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var p bypassPending
	if len(b) > 600<<10 || json.Unmarshal(b, &p) != nil {
		return errors.New("Повреждён журнал изменения обхода")
	}
	_, current, err := a.readBypass()
	if err != nil {
		return err
	}
	if bypassRevision(current) != p.NextRevision && string(current) != string(p.Old) {
		return errors.New("Настройки обхода изменены извне; автоматический откат остановлен")
	}
	if len(p.Old) == 0 {
		if err = os.Remove(a.bypassPath()); err != nil && !os.IsNotExist(err) {
			return err
		}
	} else if err = atomicWrite(a.bypassPath(), p.Old); err != nil {
		return err
	}
	c, old, err := a.readBypass()
	if err != nil {
		return err
	}
	if err = a.applyBypassConfig(c, old); err != nil {
		return err
	}
	return os.Remove(path)
}

func (a *App) restoreBypass() error {
	if _, err := os.Stat(a.bypassPath()); os.IsNotExist(err) {
		if _, err = os.Stat(filepath.Join(a.bypassDir(), "pending.json")); os.IsNotExist(err) {
			return nil
		}
	}
	unlock, err := lockBypass(filepath.Join(a.bypassDir(), "apply.lock"))
	if err != nil {
		return err
	}
	defer unlock()
	if err = a.recoverBypassLocked(); err != nil {
		return err
	}
	c, raw, err := a.readBypass()
	if err != nil {
		return err
	}
	return a.applyBypassConfig(c, raw)
}

func (a *App) bypassHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if !a.authorized(r) {
		authReply(w, 401, "Требуется вход")
		return
	}
	if r.Method != "GET" && !a.sameOriginPost(r) {
		authReply(w, 403, "Недопустимый источник запроса")
		return
	}
	if r.URL.Path == "/api/bypass/devices" && r.Method == "GET" {
		devices, err := readBypassDevices(r.Context())
		if err != nil {
			authReply(w, 503, "Не удалось получить устройства роутера; сохранённые MAC можно редактировать вручную")
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"devices": devices})
		return
	}
	if r.URL.Path != "/api/bypass" {
		http.NotFound(w, r)
		return
	}
	if !a.managementMu.TryLock() {
		authReply(w, 409, "Другое изменение уже применяется")
		return
	}
	defer a.managementMu.Unlock()
	c, raw, err := a.readBypass()
	if err != nil {
		authReply(w, 503, "Не удалось прочитать правила обхода")
		return
	}
	if r.Method == "GET" {
		_ = json.NewEncoder(w).Encode(a.bypassSnapshot(c, raw))
		return
	}
	if r.Method != "POST" {
		authReply(w, 405, "Метод не поддерживается")
		return
	}
	if runtime.GOOS != "linux" && a.bypassApply == nil {
		authReply(w, 503, "Управление обходом доступно на Linux/Entware")
		return
	}
	if a.updater != nil && activePending(a.updater.dir) {
		authReply(w, 409, "Дождитесь обновления панели")
		return
	}
	var input struct {
		Revision string       `json:"revision"`
		Rules    []bypassRule `json:"rules"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10))
	dec.DisallowUnknownFields()
	if dec.Decode(&input) != nil || dec.Decode(new(any)) != io.EOF {
		authReply(w, 400, "Некорректный запрос правил")
		return
	}
	if err = a.commitBypass(input.Revision, input.Rules); err != nil {
		authReply(w, 409, err.Error())
		return
	}
	c, raw, err = a.readBypass()
	if err != nil {
		authReply(w, 503, "Не удалось перечитать правила")
		return
	}
	_ = json.NewEncoder(w).Encode(a.bypassSnapshot(c, raw))
}

func readBypassDevices(ctx context.Context) ([]bypassDevice, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", "http://127.0.0.1:79/rci/show/ip/hotspot", nil)
	client := &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil || resp.StatusCode != 200 {
		return nil, errors.New("router unavailable")
	}
	var value any
	if json.Unmarshal(b, &value) != nil {
		return nil, errors.New("invalid router response")
	}
	return parseBypassDevices(value), nil
}

func parseBypassDevices(value any) []bypassDevice {
	devices := map[string]bypassDevice{}
	var walk func(any)
	walk = func(value any) {
		switch v := value.(type) {
		case []any:
			for _, item := range v {
				walk(item)
			}
		case map[string]any:
			if mac, err := net.ParseMAC(str(v["mac"])); err == nil && len(mac) == 6 && mac[0]&1 == 0 {
				name := str(v["name"])
				if name == "" {
					name = str(v["hostname"])
				}
				if len([]rune(name)) > 80 {
					name = string([]rune(name)[:80])
				}
				ip := str(v["ip"])
				if ip == "0.0.0.0" {
					ip = ""
				}
				online, _ := v["active"].(bool)
				device := bypassDevice{MAC: mac.String(), Name: name, IP: ip, Online: online}
				if old, ok := devices[device.MAC]; !ok || device.Online && !old.Online {
					devices[device.MAC] = device
				}
			}
			for _, item := range v {
				if _, ok := item.(map[string]any); ok {
					walk(item)
				}
				if _, ok := item.([]any); ok {
					walk(item)
				}
			}
		}
	}
	walk(value)
	out := []bypassDevice{}
	for _, device := range devices {
		out = append(out, device)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Online != out[j].Online {
			return out[i].Online
		}
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].MAC < out[j].MAC
	})
	return out
}

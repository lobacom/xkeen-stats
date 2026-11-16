package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	qrcode "github.com/skip2/go-qrcode"
)

type jsonObject = map[string]any

func object(v any) jsonObject { m, _ := v.(map[string]any); return m }
func atomicWrite(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".manage-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(b)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	if runtime.GOOS == "linux" {
		dir, err := os.Open(filepath.Dir(path))
		if err != nil {
			return err
		}
		defer dir.Close()
		return dir.Sync()
	}
	return nil
}
func array(v any) []any { a, _ := v.([]any); return a }
func str(v any) string  { s, _ := v.(string); return s }
func cloneObject(v jsonObject) jsonObject {
	b, _ := json.Marshal(v)
	var m jsonObject
	_ = json.Unmarshal(b, &m)
	return m
}

type profileEndpoint struct {
	Address    string            `json:"address"`
	Port       int               `json:"port"`
	NamePrefix string            `json:"name_prefix,omitempty"`
	Parameters map[string]string `json:"parameters"`
}
type managementConfig struct {
	Source   string                     `json:"source_config"`
	Xray     string                     `json:"xray_binary"`
	Assets   string                     `json:"assets"`
	Restart  []string                   `json:"restart"`
	Profiles map[string]profileEndpoint `json:"profiles"`
	LAN      struct {
		Inbounds       []string `json:"inbounds"`
		Outbounds      []string `json:"outbounds"`
		BaseOutbound   string   `json:"base_outbound"`
		DirectOutbound string   `json:"direct_outbound,omitempty"`
		LegacyRuleTags []string `json:"legacy_rule_tags"`
		RuleTags       []string `json:"managed_rule_tags"`
	} `json:"lan"`
}
type managedInput struct {
	Tag        string `json:"tag"`
	Title      string `json:"title"`
	Export     bool   `json:"export_ready"`
	NamePrefix string `json:"name_prefix"`
}
type managedClient struct {
	Name   string   `json:"name"`
	Inputs []string `json:"inbounds"`
}
type managedOutput struct {
	Tag    string `json:"tag"`
	Title  string `json:"title"`
	Direct bool   `json:"direct"`
}
type managementSnapshot struct {
	Enabled          bool            `json:"enabled"`
	Revision         string          `json:"revision"`
	SettingsRevision string          `json:"settings_revision"`
	Inputs           []managedInput  `json:"inbounds"`
	Clients          []managedClient `json:"clients"`
	Outputs          []managedOutput `json:"outbounds"`
	LANExit          string          `json:"lan_exit"`
	LANEnabled       bool            `json:"lan_enabled"`
}

func (a *App) managementDir() string { return filepath.Join(filepath.Dir(a.authPath), "management") }
func (a *App) managementConfig() (managementConfig, error) {
	var cfg managementConfig
	b, err := os.ReadFile(filepath.Join(filepath.Dir(a.authPath), "management.json"))
	if err != nil {
		return cfg, err
	}
	if len(b) > 65536 {
		return cfg, errors.New("management settings too large")
	}
	if err = json.Unmarshal(b, &cfg); err != nil {
		return cfg, err
	}
	if cfg.Source == "" {
		cfg.Source = a.configPath
	}
	if cfg.Xray == "" {
		cfg.Xray = "/opt/sbin/xray"
	}
	if cfg.Assets == "" {
		cfg.Assets = "/opt/etc/xray/dat"
	}
	if len(cfg.Restart) == 0 || !filepath.IsAbs(cfg.Restart[0]) || !filepath.IsAbs(cfg.Source) || !filepath.IsAbs(cfg.Xray) {
		return cfg, errors.New("invalid management paths")
	}
	if filepath.Clean(cfg.Source) == filepath.Clean(a.authPath) || filepath.Clean(a.configPath) == filepath.Clean(a.authPath) {
		return cfg, errors.New("configuration overlaps authentication")
	}
	return cfg, nil
}
func loadManagedConfig(path string) (jsonObject, []byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	if len(b) > 8<<20 {
		return nil, nil, errors.New("configuration too large")
	}
	var cfg jsonObject
	if err = json.Unmarshal(b, &cfg); err != nil {
		return nil, nil, err
	}
	if cfg == nil {
		return nil, nil, errors.New("empty configuration")
	}
	return cfg, b, nil
}
func configRevision(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
func configuredTags(cfg jsonObject, key string) map[string]jsonObject {
	m := map[string]jsonObject{}
	for _, v := range array(cfg[key]) {
		i := object(v)
		m[str(i["tag"])] = i
	}
	return m
}

func (a *App) managementSnapshot(mc managementConfig, cfg jsonObject, b []byte) managementSnapshot {
	s := managementSnapshot{Enabled: true, Revision: configRevision(b), SettingsRevision: managementSettingsRevision(mc), Inputs: []managedInput{}, Clients: []managedClient{}, Outputs: []managedOutput{}}
	labels, _ := readChannelLabels(a.authPath)
	clients := map[string][]string{}
	for _, v := range array(cfg["inbounds"]) {
		i := object(v)
		tag := str(i["tag"])
		if str(i["protocol"]) != "vless" || tag == "" {
			continue
		}
		title := labels["inbound:"+tag].Title
		if title == "" {
			title = tag
		}
		e, ok := mc.Profiles[tag]
		s.Inputs = append(s.Inputs, managedInput{Tag: tag, Title: title, Export: ok && e.Address != "" && e.Port > 0 && e.Port <= 65535, NamePrefix: e.NamePrefix})
		for _, cv := range array(object(i["settings"])["clients"]) {
			name := str(object(cv)["email"])
			if name != "" {
				clients[name] = append(clients[name], tag)
			}
		}
	}
	for name, tags := range clients {
		sort.Strings(tags)
		s.Clients = append(s.Clients, managedClient{name, tags})
	}
	sort.Slice(s.Clients, func(i, j int) bool { return s.Clients[i].Name < s.Clients[j].Name })
	directTag := lanDirectOutbound(cfg, mc)
	for _, v := range array(cfg["outbounds"]) {
		o := object(v)
		tag := str(o["tag"])
		if !contains(mc.LAN.Outbounds, tag) || tag == directTag {
			continue
		}
		title := labels["outbound:"+tag].Title
		if title == "" {
			title = tag
		}
		s.Outputs = append(s.Outputs, managedOutput{Tag: tag, Title: title})
	}
	if directTag != "" {
		s.Outputs = append(s.Outputs, managedOutput{Tag: directTag, Title: "Без VPN — напрямую", Direct: true})
	}
	s.LANEnabled = len(mc.LAN.Inbounds) > 0 && len(s.Outputs) > 0 && mc.LAN.BaseOutbound != ""
	for _, v := range array(object(cfg["routing"])["rules"]) {
		r := object(v)
		if managedLANRule(mc, str(r["ruleTag"])) {
			s.LANExit = str(r["outboundTag"])
		}
	}
	if s.LANExit == "" {
		s.LANExit = mc.LAN.BaseOutbound
	}
	return s
}

func validClientName(name string) bool {
	return strings.TrimSpace(name) == name && name != "" && utf8.RuneCountInString(name) <= 96 && !strings.ContainsFunc(name, unicode.IsControl)
}
func randomUUID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}

// Существующая запись в каждом входе сохраняет свой UUID и дополнительные поля.
func changeClient(cfg jsonObject, original, name string, inputs []string, remove bool) error {
	if !validClientName(name) || (!remove && len(inputs) == 0) {
		return errors.New("Укажите имя и хотя бы один VPN-вход")
	}
	all := configuredTags(cfg, "inbounds")
	seen := map[string]bool{}
	for _, tag := range inputs {
		if seen[tag] || str(all[tag]["protocol"]) != "vless" {
			return errors.New("Недопустимый VPN-вход")
		}
		seen[tag] = true
	}
	found := false
	for _, v := range array(cfg["inbounds"]) {
		i := object(v)
		if str(i["protocol"]) != "vless" {
			continue
		}
		for _, cv := range array(object(i["settings"])["clients"]) {
			cl := object(cv)
			email := str(cl["email"])
			if original != "" && email == original {
				found = true
			}
			if email == name && (original == "" || name != original) {
				return errors.New("Клиент с таким именем уже существует")
			}
		}
	}
	if original != "" && !found {
		return errors.New("Клиент уже изменён или удалён; обновите список")
	}
	if remove && original == "" {
		return errors.New("Не выбран клиент")
	}
	for _, v := range array(cfg["inbounds"]) {
		i := object(v)
		if str(i["protocol"]) != "vless" {
			continue
		}
		settings := object(i["settings"])
		if settings == nil {
			settings = jsonObject{}
			i["settings"] = settings
		}
		list := []any{}
		var existing jsonObject
		for _, cv := range array(settings["clients"]) {
			cl := object(cv)
			if original != "" && str(cl["email"]) == original {
				if existing != nil {
					return errors.New("Дублирующееся имя клиента во входе")
				}
				existing = cloneObject(cl)
			} else {
				list = append(list, cv)
			}
		}
		if !remove && seen[str(i["tag"])] {
			if existing == nil {
				id, err := randomUUID()
				if err != nil {
					return err
				}
				existing = jsonObject{"id": id}
			}
			existing["email"] = name
			list = append(list, existing)
		}
		settings["clients"] = list
	}
	return nil
}

func switchLAN(cfg jsonObject, mc managementConfig, selected string) error {
	direct := lanDirectOutbound(cfg, mc)
	directMode := direct != "" && selected == direct
	outs := configuredTags(cfg, "outbounds")
	if (!contains(mc.LAN.Outbounds, selected) && !directMode) || outs[selected] == nil {
		return errors.New("Недопустимый выход LAN")
	}
	in := configuredTags(cfg, "inbounds")
	if len(mc.LAN.Inbounds) == 0 {
		return errors.New("Домашние входы не настроены")
	}
	for _, tag := range mc.LAN.Inbounds {
		if in[tag] == nil {
			return errors.New("Домашний вход отсутствует в конфигурации")
		}
	}
	routing := object(cfg["routing"])
	if routing == nil {
		return errors.New("Правила маршрутизации отсутствуют")
	}
	rules := []any{}
	matched := 0
	fallback := false
	for _, v := range array(routing["rules"]) {
		r := object(v)
		if managedLANRule(mc, str(r["ruleTag"])) {
			continue
		}
		global := len(array(r["inboundTag"])) == 0 && r["inboundTag"] == nil
		baseRule := global && str(r["outboundTag"]) == mc.LAN.BaseOutbound
		vpnRule := isVPNExit(outs[str(r["outboundTag"])]) || str(r["balancerTag"]) != ""
		tags := []any{}
		for _, tag := range mc.LAN.Inbounds {
			if global || containsJSONStrings(array(r["inboundTag"]), tag) {
				tags = append(tags, tag)
			}
		}
		if baseRule || (directMode && vpnRule && len(tags) > 0) {
			copy := cloneObject(r)
			copy["inboundTag"] = tags
			copy["outboundTag"] = selected
			delete(copy, "balancerTag")
			copy["ruleTag"] = fmt.Sprintf("xkeen-stats-lan-%d", matched)
			if matched < len(mc.LAN.RuleTags) {
				copy["ruleTag"] = mc.LAN.RuleTags[matched]
			}
			rules = append(rules, copy)
			matched++
			if unqualifiedLANFallback(r) {
				fallback = true
			}
		}
		rules = append(rules, v)
	}
	if matched == 0 || !fallback {
		return errors.New("Не найдено однозначное правило выхода LAN; настройки не изменены")
	}
	routing["rules"] = rules
	return nil
}

func containsJSONStrings(values []any, want string) bool {
	for _, v := range values {
		if str(v) == want {
			return true
		}
	}
	return false
}

func plainDirectOutbound(o jsonObject) bool {
	return str(o["protocol"]) == "freedom" && str(object(o["proxySettings"])["tag"]) == "" && str(object(object(o["streamSettings"])["sockopt"])["dialerProxy"]) == "" && str(object(o["settings"])["redirect"]) == ""
}

// При нескольких прямых выходах выбор задаётся владельцем, без угадывания маршрута.
func lanDirectOutbound(cfg jsonObject, mc managementConfig) string {
	outs := configuredTags(cfg, "outbounds")
	if mc.LAN.DirectOutbound != "" {
		if plainDirectOutbound(outs[mc.LAN.DirectOutbound]) {
			return mc.LAN.DirectOutbound
		}
		return ""
	}
	found := ""
	for tag, o := range outs {
		if plainDirectOutbound(o) {
			if found != "" {
				return ""
			}
			found = tag
		}
	}
	return found
}

func managedLANRule(mc managementConfig, tag string) bool {
	return strings.HasPrefix(tag, "xkeen-stats-lan-") || contains(mc.LAN.LegacyRuleTags, tag) || contains(mc.LAN.RuleTags, tag)
}
func unqualifiedLANFallback(r jsonObject) bool {
	if str(r["network"]) != "tcp,udp" {
		return false
	}
	for k := range r {
		if k != "type" && k != "network" && k != "outboundTag" && k != "ruleTag" {
			return false
		}
	}
	return true
}

func encodeManagedConfig(cfg jsonObject) ([]byte, error) {
	b, e := json.MarshalIndent(cfg, "", "  ")
	return append(b, '\n'), e
}
func (a *App) managementCommand(mc managementConfig, args []string, logPath string) error {
	if a.managementExec != nil {
		return a.managementExec(mc, args, logPath)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Env = append(os.Environ(), "XRAY_LOCATION_ASSET="+mc.Assets)
	cmd.Stdout = f
	cmd.Stderr = f
	return cmd.Run()
}

type managementPending struct {
	Active    string `json:"active"`
	Source    string `json:"source"`
	Directory string `json:"directory"`
}

func (a *App) recoverManagement() error {
	path := filepath.Join(a.managementDir(), "pending.json")
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var p managementPending
	if json.Unmarshal(b, &p) != nil {
		return errors.New("invalid pending management transaction")
	}
	mc, err := a.managementConfig()
	if err != nil {
		return err
	}
	if p.Active != a.configPath || p.Source != mc.Source || filepath.Dir(p.Directory) != filepath.Join(a.managementDir(), "backups") {
		return errors.New("invalid management backup paths")
	}
	active, err := os.ReadFile(filepath.Join(p.Directory, "active.json"))
	if err != nil {
		return err
	}
	source, err := os.ReadFile(filepath.Join(p.Directory, "source.json"))
	if err != nil {
		return err
	}
	if err = atomicWrite(p.Active, active); err != nil {
		return err
	}
	if p.Source != p.Active {
		if err = atomicWrite(p.Source, source); err != nil {
			return err
		}
	}
	if err = a.managementCommand(mc, mc.Restart, filepath.Join(p.Directory, "recovery.log")); err != nil {
		return err
	}
	if !a.managementReady() {
		return errors.New("previous Xray configuration did not become healthy")
	}
	return removeManagementPending(path)
}

func removeManagementPending(path string) error {
	if err := os.Remove(path); err != nil {
		return err
	}
	if runtime.GOOS == "linux" {
		dir, err := os.Open(filepath.Dir(path))
		if err != nil {
			return err
		}
		defer dir.Close()
		return dir.Sync()
	}
	return nil
}
func (a *App) managementReady() bool {
	for n := 0; n < 4; n++ {
		if _, e := a.call("QueryStats"); e == nil {
			return true
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}

func (a *App) commitManagedConfig(mc managementConfig, revision string, original []byte, next jsonObject) error {
	current, err := os.ReadFile(a.configPath)
	if err != nil || !bytes.Equal(current, original) || configRevision(current) != revision {
		return errors.New("Конфигурация уже изменена. Обновите список и повторите")
	}
	source, err := os.ReadFile(mc.Source)
	if err != nil {
		return errors.New("Не удалось прочитать исходный конфиг")
	}
	if !jsonEqual(original, source) {
		return errors.New("Активный и исходный конфиги различаются; изменения не применены")
	}
	nextBytes, err := encodeManagedConfig(next)
	if err != nil {
		return err
	}
	root := a.managementDir()
	backup := filepath.Join(root, "backups", time.Now().UTC().Format("20060102T150405.000000000"))
	if err = os.MkdirAll(backup, 0700); err != nil {
		return err
	}
	for name, data := range map[string][]byte{"active.json": original, "source.json": source, "candidate.json": nextBytes} {
		if err = atomicWrite(filepath.Join(backup, name), data); err != nil {
			return err
		}
	}
	if err = a.managementCommand(mc, []string{mc.Xray, "run", "-test", "-config", filepath.Join(backup, "candidate.json")}, filepath.Join(backup, "validate.log")); err != nil {
		return errors.New("Xray отклонил изменения; действующий конфиг сохранён")
	}
	// Проверка после длительной валидации защищает от стороннего редактора.
	current, err = os.ReadFile(a.configPath)
	if err != nil || !bytes.Equal(current, original) {
		return errors.New("Конфигурация изменена другим приложением")
	}
	checkSource, err := os.ReadFile(mc.Source)
	if err != nil || !bytes.Equal(source, checkSource) {
		return errors.New("Исходный конфиг изменён другим приложением")
	}
	pending := managementPending{a.configPath, mc.Source, backup}
	pbytes, _ := json.Marshal(pending)
	pendingPath := filepath.Join(root, "pending.json")
	if err = atomicWrite(pendingPath, pbytes); err != nil {
		return err
	}
	rollback := func() error {
		if e := a.recoverManagement(); e != nil {
			return errors.New("Изменения не применены. Не удалось завершить откат; проверьте Xray")
		}
		return errors.New("Изменения не применены; предыдущая конфигурация восстановлена")
	}
	a.sample()
	err = a.save()
	if err != nil {
		_ = removeManagementPending(pendingPath)
		return errors.New("Не удалось сохранить статистику перед применением")
	}
	if atomicWrite(a.configPath, nextBytes) != nil {
		return rollback()
	}
	if mc.Source != a.configPath && atomicWrite(mc.Source, nextBytes) != nil {
		return rollback()
	}
	if a.managementCommand(mc, mc.Restart, filepath.Join(backup, "apply.log")) != nil {
		return rollback()
	}
	if !a.managementReady() {
		return rollback()
	}
	if err = removeManagementPending(pendingPath); err != nil {
		return errors.New("Настройки применены, но не удалось завершить транзакцию")
	}
	a.sample()
	return nil
}
func jsonEqual(a, b []byte) bool {
	var x, y any
	return json.Unmarshal(a, &x) == nil && json.Unmarshal(b, &y) == nil && reflect.DeepEqual(x, y)
}

func profileDisplayName(endpoint profileEndpoint, name, tag string) string {
	if endpoint.NamePrefix != "" {
		return endpoint.NamePrefix + name
	}
	return tag + "-" + name
}

func managementSettingsRevision(mc managementConfig) string {
	b, _ := json.Marshal(mc)
	return configRevision(b)
}
func (a *App) changeProfilePrefix(mc managementConfig, revision, tag, prefix string) (managementConfig, error) {
	if revision == "" || revision != managementSettingsRevision(mc) {
		return mc, errors.New("Настройки профилей изменились. Обновите список")
	}
	if utf8.RuneCountInString(prefix) > 80 || strings.ContainsFunc(prefix, unicode.IsControl) {
		return mc, errors.New("Приставка должна содержать до 80 символов без переводов строк")
	}
	if _, ok := mc.Profiles[tag]; !ok {
		return mc, errors.New("Экспорт профиля этого входа не настроен")
	}
	path := filepath.Join(filepath.Dir(a.authPath), "management.json")
	settings, original, err := loadManagedConfig(path)
	if err != nil {
		return mc, errors.New("Не удалось прочитать настройки профилей")
	}
	latest, err := a.managementConfig()
	if err != nil || managementSettingsRevision(latest) != revision {
		return mc, errors.New("Настройки профилей изменились. Обновите список")
	}
	endpoint := object(object(settings["profiles"])[tag])
	if endpoint == nil {
		return mc, errors.New("Не найдены настройки выбранного входа")
	}
	endpoint["name_prefix"] = prefix
	next, err := encodeManagedConfig(settings)
	if err != nil {
		return mc, err
	}
	current, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(current, original) {
		return mc, errors.New("Настройки изменены другим приложением")
	}
	if err = atomicWrite(path, next); err != nil {
		return mc, errors.New("Не удалось сохранить приставку")
	}
	updated := mc.Profiles[tag]
	updated.NamePrefix = prefix
	mc.Profiles[tag] = updated
	return mc, nil
}

func makeProfile(cfg jsonObject, mc managementConfig, name, tag string) (string, error) {
	i := configuredTags(cfg, "inbounds")[tag]
	if i == nil || str(i["protocol"]) != "vless" {
		return "", errors.New("Профиль этого входа не поддерживается")
	}
	endpoint, ok := mc.Profiles[tag]
	if !ok || endpoint.Address == "" || endpoint.Port < 1 || endpoint.Port > 65535 || strings.ContainsAny(endpoint.Address, "/@?# \r\n") {
		return "", errors.New("Публичный адрес профиля для этого входа ещё не настроен")
	}
	var cl jsonObject
	for _, v := range array(object(i["settings"])["clients"]) {
		c := object(v)
		if str(c["email"]) == name {
			cl = c
			break
		}
	}
	if cl == nil {
		return "", errors.New("Клиент не подключён к этому входу")
	}
	params := url.Values{}
	params.Set("encryption", "none")
	stream := object(i["streamSettings"])
	network := str(stream["network"])
	if network == "" || network == "raw" {
		network = "tcp"
	}
	params.Set("type", network)
	security := str(stream["security"])
	if security == "" {
		security = "none"
	}
	params.Set("security", security)
	if flow := str(cl["flow"]); flow != "" {
		params.Set("flow", flow)
	}
	transport := object(stream[network+"Settings"])
	if network == "xhttp" && transport == nil {
		transport = object(stream["splithttpSettings"])
	}
	for _, k := range []string{"path", "host", "mode"} {
		if v := str(transport[k]); v != "" {
			params.Set(k, v)
		}
	}
	if network == "grpc" {
		if v := str(transport["serviceName"]); v != "" {
			params.Set("serviceName", v)
		}
	}
	for k, v := range endpoint.Parameters {
		if len(k) > 64 || len(v) > 4096 {
			return "", errors.New("Слишком длинные параметры профиля")
		}
		params.Set(k, v)
	}
	if (params.Get("security") == "tls" || params.Get("security") == "reality") && params.Get("sni") == "" {
		return "", errors.New("В настройках экспорта не указан SNI")
	}
	if params.Get("security") == "reality" && params.Get("pbk") == "" {
		return "", errors.New("В настройках экспорта не указан публичный ключ REALITY")
	}
	u := url.URL{Scheme: "vless", User: url.User(str(cl["id"])), Host: net.JoinHostPort(endpoint.Address, strconv.Itoa(endpoint.Port)), RawQuery: params.Encode(), Fragment: profileDisplayName(endpoint, name, tag)}
	if len(u.String()) > 6000 {
		return "", errors.New("Профиль слишком большой для QR")
	}
	return u.String(), nil
}

func (a *App) managementHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if !a.authorized(r) {
		authReply(w, 401, "Требуется вход")
		return
	}
	if r.Method != "GET" && !a.sameOriginPost(r) {
		authReply(w, 403, "Недопустимый источник запроса")
		return
	}
	if !a.managementMu.TryLock() {
		authReply(w, 409, "Другое изменение уже применяется")
		return
	}
	defer a.managementMu.Unlock()
	mc, err := a.managementConfig()
	if os.IsNotExist(err) && r.Method == "GET" {
		_ = json.NewEncoder(w).Encode(managementSnapshot{})
		return
	}
	if err != nil {
		authReply(w, 503, "Управление VPN не настроено или настройки повреждены")
		return
	}
	if _, err = os.Stat(filepath.Join(a.managementDir(), "pending.json")); err == nil {
		authReply(w, 503, "Не завершено предыдущее изменение. Перезапустите сервис для восстановления")
		return
	}
	cfg, b, err := loadManagedConfig(a.configPath)
	if err != nil {
		authReply(w, 503, "Не удалось прочитать конфигурацию Xray")
		return
	}
	if r.Method == "GET" && r.URL.Path == "/api/manage" {
		_ = json.NewEncoder(w).Encode(a.managementSnapshot(mc, cfg, b))
		return
	}
	if r.Method != "POST" {
		authReply(w, 405, "Метод не поддерживается")
		return
	}
	var in struct {
		Revision         string   `json:"revision"`
		SettingsRevision string   `json:"settings_revision"`
		Prefix           string   `json:"prefix"`
		Original         string   `json:"original_name"`
		Name             string   `json:"name"`
		Inputs           []string `json:"inbounds"`
		Inbound          string   `json:"inbound"`
		Outbound         string   `json:"outbound"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384))
	if dec.Decode(&in) != nil {
		authReply(w, 400, "Некорректный запрос")
		return
	}
	if r.URL.Path == "/api/manage/profile" {
		uri, e := makeProfile(cfg, mc, in.Name, in.Inbound)
		if e != nil {
			authReply(w, 400, e.Error())
			return
		}
		png, e := qrcode.Encode(uri, qrcode.Medium, 384)
		if e != nil {
			authReply(w, 400, "Не удалось создать QR: профиль слишком большой")
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"name": profileDisplayName(mc.Profiles[in.Inbound], in.Name, in.Inbound), "name_prefix": mc.Profiles[in.Inbound].NamePrefix, "settings_revision": managementSettingsRevision(mc), "uri": uri, "qr": "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)})
		return
	}
	if a.updater != nil && activePending(a.updater.dir) {
		authReply(w, 409, "Дождитесь завершения обновления программы")
		return
	}
	if r.URL.Path == "/api/manage/profile-name" {
		if str(configuredTags(cfg, "inbounds")[in.Inbound]["protocol"]) != "vless" {
			authReply(w, 400, "Недопустимый вход")
			return
		}
		updated, e := a.changeProfilePrefix(mc, in.SettingsRevision, in.Inbound, in.Prefix)
		if e != nil {
			authReply(w, 409, e.Error())
			return
		}
		_ = json.NewEncoder(w).Encode(a.managementSnapshot(updated, cfg, b))
		return
	}
	if in.Revision == "" || in.Revision != configRevision(b) {
		authReply(w, 409, "Конфигурация изменилась. Обновите список")
		return
	}
	next := cloneObject(cfg)
	switch r.URL.Path {
	case "/api/manage/client":
		err = changeClient(next, in.Original, in.Name, in.Inputs, false)
	case "/api/manage/client/delete":
		err = changeClient(next, in.Name, in.Name, nil, true)
	case "/api/manage/lan":
		err = switchLAN(next, mc, in.Outbound)
	default:
		http.NotFound(w, r)
		return
	}
	if err != nil {
		authReply(w, 400, err.Error())
		return
	}
	if err = a.commitManagedConfig(mc, in.Revision, b, next); err != nil {
		authReply(w, 409, err.Error())
		return
	}
	_ = json.NewEncoder(w).Encode(a.managementSnapshot(mc, next, mustEncode(next)))
}
func mustEncode(cfg jsonObject) []byte { b, _ := encodeManagedConfig(cfg); return b }

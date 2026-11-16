package main

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

//go:embed index.html
var page []byte

//go:embed management.js
var managementScript []byte

type Traffic struct {
	Up   int64 `json:"up"`
	Down int64 `json:"down"`
}

type Entry struct {
	Total    Traffic            `json:"total"`
	Daily    map[string]Traffic `json:"daily"`
	LastSeen int64              `json:"last_seen"`
}

type State struct {
	Version int                `json:"version"`
	Since   int64              `json:"since"`
	Saved   int64              `json:"saved"`
	Session string             `json:"session"`
	Last    map[string]Traffic `json:"last"`
	Entries map[string]*Entry  `json:"entries"`
}

type Live struct {
	Up   float64  `json:"up"`
	Down float64  `json:"down"`
	IPs  []string `json:"ips"`
}

type Row struct {
	Key        string       `json:"key"`
	Name       string       `json:"name"`
	Kind       string       `json:"kind"`
	Routes     []string     `json:"routes"`
	Configured bool         `json:"configured"`
	Total      Traffic      `json:"total"`
	Today      Traffic      `json:"today"`
	Month      Traffic      `json:"month"`
	LastSeen   int64        `json:"last_seen"`
	Live       Live         `json:"live"`
	Channel    *channelInfo `json:"channel,omitempty"`
}

type App struct {
	mu                                                  sync.Mutex
	state                                               State
	live                                                map[string]Live
	lastSample                                          time.Time
	lastOK                                              int64
	lastError                                           string
	saveError                                           string
	labelsError                                         string
	managementMu                                        sync.Mutex
	managementExec                                      func(managementConfig, []string, string) error
	sampleMu                                            sync.Mutex
	configPath, authPath, statePath, apiAddress, listen string
	rpc                                                 *http.Client
	authMu                                              sync.Mutex
	loginGate                                           chan struct{}
	failures                                            map[string]loginFailure
	allowSetup                                          bool
	setupTokenPath                                      string
	updater                                             *updater
}

// Минимальный protobuf-декодер читает только документированные поля StatsService.
type Field struct {
	Number, Wire int
	Bytes        []byte
	Int          uint64
}

func fields(data []byte) ([]Field, error) {
	var out []Field
	for len(data) > 0 {
		tag, n := binary.Uvarint(data)
		if n <= 0 {
			return nil, errors.New("invalid protobuf tag")
		}
		data = data[n:]
		f := Field{Number: int(tag >> 3), Wire: int(tag & 7)}
		switch f.Wire {
		case 0:
			v, n := binary.Uvarint(data)
			if n <= 0 {
				return nil, errors.New("invalid protobuf integer")
			}
			f.Int = v
			data = data[n:]
		case 1:
			if len(data) < 8 {
				return nil, io.ErrUnexpectedEOF
			}
			data = data[8:]
		case 2:
			size, n := binary.Uvarint(data)
			if n <= 0 || size > uint64(len(data)-n) {
				return nil, io.ErrUnexpectedEOF
			}
			data = data[n:]
			f.Bytes = data[:int(size)]
			data = data[int(size):]
		case 5:
			if len(data) < 4 {
				return nil, io.ErrUnexpectedEOF
			}
			data = data[4:]
		default:
			return nil, errors.New("unsupported protobuf field")
		}
		if f.Number == 0 {
			return nil, errors.New("invalid protobuf field")
		}
		out = append(out, f)
	}
	return out, nil
}

func (a *App) call(method string) ([]byte, error) {
	req, err := http.NewRequest("POST", "http://"+a.apiAddress+"/xray.app.stats.command.StatsService/"+method, bytes.NewReader(make([]byte, 5)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("TE", "trailers")
	req.Header.Set("Grpc-Timeout", "3S")
	resp, err := a.rpc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	status := resp.Trailer.Get("Grpc-Status")
	if status == "" {
		status = resp.Header.Get("Grpc-Status")
	}
	if resp.StatusCode != 200 || status != "0" {
		return nil, fmt.Errorf("StatsService %s: HTTP %d / gRPC %s", method, resp.StatusCode, status)
	}
	if len(body) < 5 || body[0] != 0 || int(binary.BigEndian.Uint32(body[1:5])) != len(body)-5 {
		return nil, errors.New("invalid gRPC response")
	}
	return body[5:], nil
}

func parseCounters(data []byte) (map[string]Traffic, error) {
	result := map[string]Traffic{}
	fs, err := fields(data)
	if err != nil {
		return nil, err
	}
	for _, f := range fs {
		if f.Number != 1 {
			continue
		}
		sf, err := fields(f.Bytes)
		if err != nil {
			return nil, err
		}
		var name string
		var value int64
		for _, s := range sf {
			if s.Number == 1 {
				name = string(s.Bytes)
			}
			if s.Number == 2 {
				value = int64(s.Int)
			}
		}
		parts := strings.Split(name, ">>>")
		if len(parts) != 4 || parts[2] != "traffic" || value < 0 {
			continue
		}
		if parts[0] != "user" && parts[0] != "inbound" && parts[0] != "outbound" {
			continue
		}
		key := parts[0] + ":" + parts[1]
		t := result[key]
		if parts[3] == "uplink" {
			t.Up = value
		}
		if parts[3] == "downlink" {
			t.Down = value
		}
		result[key] = t
	}
	return result, nil
}

func parseOnline(data []byte) (map[string][]string, error) {
	result := map[string][]string{}
	fs, err := fields(data)
	if err != nil {
		return nil, err
	}
	for _, f := range fs {
		if f.Number != 1 {
			continue
		}
		uf, err := fields(f.Bytes)
		if err != nil {
			return nil, err
		}
		name := ""
		ips := []string{}
		for _, u := range uf {
			if u.Number == 1 {
				name = string(u.Bytes)
			}
			if u.Number == 2 {
				ipf, err := fields(u.Bytes)
				if err != nil {
					return nil, err
				}
				for _, ip := range ipf {
					if ip.Number == 1 {
						ips = append(ips, string(ip.Bytes))
					}
				}
			}
		}
		if name != "" {
			sort.Strings(ips)
			result["user:"+name] = ips
		}
	}
	return result, nil
}

func isXrayServer(cmdline []byte) bool {
	args := strings.Split(strings.TrimRight(string(cmdline), "\x00"), "\x00")
	if len(args) < 2 || args[1] != "run" {
		return false
	}
	for _, arg := range args[2:] {
		if arg == "-test" || arg == "--test" || strings.HasPrefix(arg, "-test=") || strings.HasPrefix(arg, "--test=") {
			return false
		}
	}
	return true
}

func xraySession() string {
	boot, _ := os.ReadFile("/proc/sys/kernel/random/boot_id")
	dirs, _ := filepath.Glob("/proc/[0-9]*/comm")
	for _, p := range dirs {
		b, err := os.ReadFile(p)
		if err != nil || strings.TrimSpace(string(b)) != "xray" {
			continue
		}
		cmdline, err := os.ReadFile(filepath.Join(filepath.Dir(p), "cmdline"))
		if err != nil || !isXrayServer(cmdline) {
			continue
		}
		stat, err := os.ReadFile(filepath.Join(filepath.Dir(p), "stat"))
		if err != nil {
			continue
		}
		_, tail, ok := strings.Cut(string(stat), ") ")
		fs := strings.Fields(tail)
		if ok && len(fs) > 19 {
			return strings.TrimSpace(string(boot)) + ":" + filepath.Base(filepath.Dir(p)) + ":" + fs[19]
		}
	}
	return ""
}

var moscow = time.FixedZone("MSK", 3*3600)

func (a *App) merge(current map[string]Traffic, online map[string][]string, session string, now time.Time) {
	seconds := now.Sub(a.lastSample).Seconds()
	same := session != "" && session == a.state.Session
	a.live = map[string]Live{}
	for key, t := range current {
		e := a.state.Entries[key]
		if e == nil {
			e = &Entry{Daily: map[string]Traffic{}}
			a.state.Entries[key] = e
		}
		if e.Daily == nil {
			e.Daily = map[string]Traffic{}
		}
		prev, existed := a.state.Last[key]
		delta := t
		if same && existed {
			if t.Up >= prev.Up {
				delta.Up -= prev.Up
			}
			if t.Down >= prev.Down {
				delta.Down -= prev.Down
			}
		}
		// При первом запуске после перезапуска сборщика скорость ещё неизвестна.
		live := Live{IPs: online[key]}
		if same && existed && seconds > 0 && !a.lastSample.IsZero() {
			live.Up = float64(delta.Up) / seconds
			live.Down = float64(delta.Down) / seconds
		}
		e.Total.Up += delta.Up
		e.Total.Down += delta.Down
		day := now.In(moscow).Format("2006-01-02")
		d := e.Daily[day]
		d.Up += delta.Up
		d.Down += delta.Down
		e.Daily[day] = d
		if delta.Up > 0 || delta.Down > 0 || len(live.IPs) > 0 {
			e.LastSeen = now.Unix()
		}
		for date := range e.Daily {
			if date < now.In(moscow).AddDate(0, 0, -400).Format("2006-01-02") {
				delete(e.Daily, date)
			}
		}
		a.live[key] = live
	}
	for key, ips := range online {
		if _, ok := a.live[key]; !ok {
			a.live[key] = Live{IPs: ips}
		}
	}
	a.state.Last = current
	a.state.Session = session
	a.lastSample = now
	a.lastOK = now.Unix()
	a.lastError = ""
}

func (a *App) sample() {
	a.sampleMu.Lock()
	defer a.sampleMu.Unlock()
	session := xraySession()
	if session == "" {
		a.failed(errors.New("Xray process not found"))
		return
	}
	c, err := a.call("QueryStats")
	if err != nil {
		a.failed(err)
		return
	}
	counters, err := parseCounters(c)
	if err != nil {
		a.failed(err)
		return
	}
	o, err := a.call("GetUsersStats")
	if err != nil {
		a.failed(err)
		return
	}
	online, err := parseOnline(o)
	if err != nil {
		a.failed(err)
		return
	}
	if session != xraySession() {
		a.failed(errors.New("Xray restarted during sampling; retrying"))
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.merge(counters, online, session, time.Now())
}

func (a *App) failed(err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.lastError = err.Error()
	a.live = map[string]Live{}
}

func (a *App) save() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.state.Saved = time.Now().Unix()
	b, err := json.Marshal(a.state)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(a.statePath), 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(a.statePath+".tmp", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(a.statePath+".tmp", a.statePath)
	}
	if err != nil {
		a.saveError = err.Error()
		return err
	}
	a.saveError = ""
	return nil
}

func (a *App) load() error {
	a.state = State{Version: 1, Since: time.Now().Unix(), Last: map[string]Traffic{}, Entries: map[string]*Entry{}}
	b, err := os.ReadFile(a.statePath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if err = json.Unmarshal(b, &a.state); err != nil {
		return fmt.Errorf("cannot read saved statistics: %w", err)
	}
	if a.state.Version != 1 || a.state.Entries == nil || a.state.Last == nil {
		return errors.New("invalid statistics state")
	}
	return nil
}

func (a *App) rows() ([]Row, error) {
	var config struct {
		Inbounds  []channelConfig `json:"inbounds"`
		Outbounds []channelConfig `json:"outbounds"`
	}
	b, err := os.ReadFile(a.configPath)
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(b, &config); err != nil {
		return nil, err
	}
	names := map[string][]string{}
	descriptions := map[string]channelInfo{}
	labels, labelsErr := readChannelLabels(a.authPath)
	a.labelsError = ""
	if labelsErr != nil {
		a.labelsError = "Не удалось прочитать labels.json. Показаны автоматические пояснения каналов."
	}
	for _, i := range config.Inbounds {
		names["inbound:"+i.Tag] = nil
		descriptions["inbound:"+i.Tag] = applyChannelLabel(describeChannel("inbound", i), labels["inbound:"+i.Tag])
		for _, c := range i.Settings.Clients {
			if c.Email != "" {
				key := "user:" + c.Email
				names[key] = append(names[key], i.Tag)
			}
		}
	}
	for _, o := range config.Outbounds {
		names["outbound:"+o.Tag] = nil
		descriptions["outbound:"+o.Tag] = applyChannelLabel(describeChannel("outbound", o), labels["outbound:"+o.Tag])
	}
	for key := range a.state.Entries {
		if _, ok := names[key]; !ok {
			names[key] = nil
		}
	}
	rows := []Row{}
	now := time.Now().In(moscow)
	today := now.Format("2006-01-02")
	month := now.Format("2006-01")
	for key, routes := range names {
		kind, name, _ := strings.Cut(key, ":")
		e := a.state.Entries[key]
		if e == nil {
			e = &Entry{Daily: map[string]Traffic{}}
		}
		m := Traffic{}
		for day, t := range e.Daily {
			if strings.HasPrefix(day, month) {
				m.Up += t.Up
				m.Down += t.Down
			}
		}
		sort.Strings(routes)
		row := Row{Key: key, Name: name, Kind: kind, Routes: routes, Configured: kind != "user" || len(routes) > 0, Total: e.Total, Today: e.Daily[today], Month: m, LastSeen: e.LastSeen, Live: a.live[key]}
		if info, ok := descriptions[key]; ok {
			row.Channel = &info
		}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Key < rows[j].Key })
	return rows, nil
}

func (a *App) handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	if r.Host != a.listen {
		http.Error(w, "Invalid host", http.StatusForbidden)
		return
	}
	addr, _, err := net.SplitHostPort(r.RemoteAddr)
	ip := net.ParseIP(addr)
	_, lan, _ := net.ParseCIDR("192.168.1.0/24")
	if err != nil || (!lan.Contains(ip) && !ip.IsLoopback()) {
		http.Error(w, "LAN only", http.StatusForbidden)
		return
	}
	if r.URL.Path == "/auth/login" {
		a.login(w, r)
		return
	}
	if r.URL.Path == "/auth/logout" {
		a.logout(w, r)
		return
	}
	if r.URL.Path == "/auth/status" {
		a.authStatus(w, r)
		return
	}
	if r.URL.Path == "/auth/setup" {
		a.setup(w, r)
		return
	}
	if r.URL.Path == "/api/manage" || strings.HasPrefix(r.URL.Path, "/api/manage/") {
		a.managementHandler(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/update") {
		a.updateHandler(w, r)
		return
	}
	if r.Method == "GET" && r.URL.Path == "/healthz" {
		a.mu.Lock()
		ready := a.lastOK > 0
		a.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if !ready {
			w.WriteHeader(503)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"version": version, "ready": ready})
		return
	}
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", 405)
		return
	}
	if r.URL.Path == "/" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(page)
		return
	}
	if r.URL.Path == "/management.js" {
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		_, _ = w.Write(managementScript)
		return
	}
	if r.URL.Path != "/api/stats" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if !a.authorized(r) {
		w.WriteHeader(401)
		_, _ = w.Write([]byte(`{"error":"Требуется вход в статистику"}`))
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	rows, err := a.rows()
	if err != nil {
		http.Error(w, `{"error":"Не удалось прочитать список профилей"}`, 503)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"rows": rows, "since": a.state.Since, "updated": a.lastOK, "saved": a.state.Saved, "error": a.lastError, "save_error": a.saveError, "labels_error": a.labelsError, "now": time.Now().Unix(), "interval": 5})
}

func main() {
	a := &App{live: map[string]Live{}, loginGate: make(chan struct{}, 1), failures: map[string]loginFailure{}}
	flag.StringVar(&a.listen, "listen", "192.168.1.1:1001", "LAN address")
	flag.StringVar(&a.configPath, "config", "/opt/etc/xray/configs/00_cascade.json", "Xray configuration")
	flag.StringVar(&a.authPath, "auth", "/opt/etc/xkeen-stats/auth.json", "Private password hash and sessions")
	flag.StringVar(&a.setupTokenPath, "setup-token", "/opt/etc/xkeen-stats/setup-token", "Private one-time setup token")
	flag.StringVar(&a.statePath, "state", "/opt/var/lib/xkeen-stats/state.json", "Statistics state")
	flag.StringVar(&a.apiAddress, "api", "127.0.0.1:10085", "Xray StatsService")
	setPassword := flag.Bool("set-password", false, "Read a new password from stdin; run with the service stopped")
	checkAuth := flag.Bool("check-auth", false, "Validate the private authentication file and exit")
	prepareAuth := flag.Bool("prepare-auth", false, "Prepare first-run access and print its private setup link")
	showSetupLink := flag.Bool("setup-link", false, "Print the private first-run setup link")
	checkAccess := flag.Bool("check-access", false, "Validate configured login or protected first-run access")
	showVersion := flag.Bool("version", false, "Print version and exit")
	checkInstall := flag.Bool("check-install", false, "Check compatibility with current configuration and data")
	updateDir := flag.String("update-dir", "/opt/var/lib/xkeen-stats/update", "Private update directory")
	applyJob := flag.String("apply-update", "", "Internal update worker")
	recoverJob := flag.Bool("recover-update", false, "Recover an interrupted binary update")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	if *applyJob != "" {
		if err := applyUpdate(*applyJob); err != nil {
			log.Fatal(err)
		}
		return
	}
	if *recoverJob {
		if err := recoverUpdate(*updateDir); err != nil {
			log.Fatal(err)
		}
		return
	}
	if *setPassword {
		if err := setPasswordFromInput(a.authPath, os.Stdin); err != nil {
			log.Fatal(err)
		}
		fmt.Println("Password saved; all statistics sessions revoked")
		return
	}
	if *checkAuth || *checkInstall {
		if _, err := readAuth(a.authPath); err != nil {
			log.Fatalf("Authentication unavailable: %v", err)
		}
	}
	if *checkAuth {
		return
	}
	if *prepareAuth || *showSetupLink || *checkAccess {
		required, err := initialAccess(a.authPath, a.setupTokenPath, !*checkAccess)
		if err != nil {
			log.Fatal(err)
		}
		if required && !*checkAccess {
			token, err := readSetupToken(a.setupTokenPath)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Println("Initial setup: http://" + a.listen + "/#setup=" + token)
		} else if *showSetupLink {
			fmt.Println("Password is already configured")
		}
		return
	}
	if !*checkInstall {
		required, err := initialAccess(a.authPath, a.setupTokenPath, true)
		if err != nil {
			log.Fatalf("Authentication unavailable: %v", err)
		}
		a.allowSetup = required
		if required {
			log.Print("Initial password setup required; use -setup-link to obtain the private link")
		}
	}
	p := new(http.Protocols)
	p.SetUnencryptedHTTP2(true)
	a.rpc = &http.Client{Timeout: 4 * time.Second, Transport: &http.Transport{Protocols: p}}
	if err := a.load(); err != nil {
		log.Fatal(err)
	}
	if *checkInstall {
		if _, err := a.rows(); err != nil {
			log.Fatal(err)
		}
		return
	}
	if err := a.recoverManagement(); err != nil {
		log.Fatalf("VPN management recovery failed: %v", err)
	}
	a.updater = &updater{app: a, dir: *updateDir, client: newUpdateClient()}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		tick := time.NewTicker(5 * time.Second)
		defer tick.Stop()
		a.sample()
		n := 0
		for range tick.C {
			a.sample()
			n++
			if n%12 == 0 {
				if err := a.save(); err != nil {
					log.Print(err)
				}
			}
		}
	}()
	server := &http.Server{Addr: a.listen, Handler: http.HandlerFunc(a.handle), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 120 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16384}
	go func() {
		<-stop
		if err := a.save(); err != nil {
			log.Print(err)
		}
		_ = server.Close()
	}()
	log.Printf("XKeen statistics listening on %s", a.listen)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

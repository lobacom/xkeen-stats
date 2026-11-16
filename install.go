package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

//go:embed S99xkeen-stats
var initScript []byte

//go:embed 051-xkeen-stats-lan.sh
var firewallScript []byte

type installOptions struct {
	PlanOnly, AllowRestart        bool
	Interface, Init, Xray, Source string
	Explicit                      map[string]bool
}

type installPlan struct {
	Service   serviceConfig `json:"service"`
	Xray      string        `json:"xray_binary"`
	Assets    string        `json:"xray_assets"`
	Restart   []string      `json:"restart"`
	Files     []string      `json:"config_files"`
	Changed   bool          `json:"xray_restart_required"`
	Target    string        `json:"statistics_config,omitempty"`
	Source    string        `json:"source_config,omitempty"`
	next      []byte
	originals map[string][]byte
}

func processArgs(name string) ([]string, error) {
	files, _ := filepath.Glob("/proc/[0-9]*/comm")
	for _, p := range files {
		b, err := os.ReadFile(p)
		if err != nil || strings.TrimSpace(string(b)) != name {
			continue
		}
		b, err = os.ReadFile(filepath.Join(filepath.Dir(p), "cmdline"))
		if err != nil {
			continue
		}
		if name == "xray" && !isXrayServer(b) {
			continue
		}
		args := strings.Split(strings.TrimRight(string(b), "\x00"), "\x00")
		if name == "xray" {
			if env, e := os.ReadFile(filepath.Join(filepath.Dir(p), "environ")); e == nil {
				args = augmentXrayArgs(args, env)
			}
		}
		if name == "xkeen-stats" {
			skip := false
			for _, arg := range args[1:] {
				if arg == "-install" || arg == "-install-plan" || arg == "-version" {
					skip = true
				}
			}
			if skip {
				continue
			}
		}
		return args, nil
	}
	return nil, fmt.Errorf("running %s not found", name)
}

func augmentXrayArgs(args []string, env []byte) []string {
	values := map[string]string{}
	for _, entry := range strings.Split(string(env), "\x00") {
		k, v, ok := strings.Cut(entry, "=")
		if ok {
			values[strings.ToUpper(strings.ReplaceAll(k, ".", "_"))] = v
		}
	}
	args = append([]string(nil), args...)
	if v, _ := commandOption(args, "-confdir", "--confdir"); v == "" && values["XRAY_LOCATION_CONFDIR"] != "" {
		args = append(args, "-confdir", values["XRAY_LOCATION_CONFDIR"])
	}
	if dir, _ := commandOption(args, "-confdir", "--confdir"); dir == "" {
		if v, _ := commandOption(args, "-config", "--config", "-c"); v == "" && values["XRAY_LOCATION_CONFIG"] != "" {
			args = append(args, "-config", values["XRAY_LOCATION_CONFIG"])
		}
	}
	if values["XRAY_LOCATION_ASSET"] != "" {
		args = append(args, "-xks-assets", values["XRAY_LOCATION_ASSET"])
	}
	return args
}

func commandOption(args []string, names ...string) (string, error) {
	value := ""
	for i := 0; i < len(args); i++ {
		for _, name := range names {
			v := ""
			if args[i] == name {
				if i+1 >= len(args) {
					return "", errors.New("missing process option value")
				}
				v = args[i+1]
			} else if strings.HasPrefix(args[i], name+"=") {
				v = strings.TrimPrefix(args[i], name+"=")
			}
			if v != "" {
				if value != "" && value != v {
					return "", errors.New("multiple Xray configuration paths; specify -config explicitly")
				}
				value = v
			}
		}
	}
	return value, nil
}

func detectXrayPath(args []string) (string, error) {
	dir, err := commandOption(args, "-confdir", "--confdir")
	if err != nil {
		return "", err
	}
	file, err := commandOption(args, "-config", "--config", "-c")
	if err != nil {
		return "", err
	}
	if dir != "" && file != "" {
		return "", errors.New("Xray uses both -config and -confdir; specify -config explicitly")
	}
	if dir != "" {
		return dir, nil
	}
	if file != "" {
		return file, nil
	}
	return "", errors.New("cannot detect Xray configuration; specify -config /path/file.json or /path/configs")
}

type lanCandidate struct{ iface, listen, cidr string }

func detectLAN(wanted, listen, cidr string) (serviceConfig, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return serviceConfig{}, err
	}
	host, port, _ := net.SplitHostPort(listen)
	if port == "" {
		port = "1001"
	}
	var found []lanCandidate
	for _, i := range interfaces {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 || (wanted != "" && i.Name != wanted) {
			continue
		}
		addrs, _ := i.Addrs()
		for _, addr := range addrs {
			ip, network, e := net.ParseCIDR(addr.String())
			if e != nil || ip.To4() == nil || !ip.IsPrivate() {
				continue
			}
			if host != "" && host != ip.String() {
				continue
			}
			lan := network.String()
			if cidr != "" {
				lan = cidr
			}
			found = append(found, lanCandidate{i.Name, net.JoinHostPort(ip.String(), port), lan})
		}
	}
	if len(found) > 1 && wanted == "" && host == "" {
		for _, preferred := range []string{"br0", "br-lan"} {
			var subset []lanCandidate
			for _, c := range found {
				if c.iface == preferred {
					subset = append(subset, c)
				}
			}
			if len(subset) == 1 {
				found = subset
				break
			}
		}
	}
	if len(found) != 1 {
		return serviceConfig{}, errors.New("LAN is ambiguous or not found; specify -interface br0 -listen ROUTER_IP:1001 -lan SUBNET/CIDR")
	}
	f := found[0]
	if _, err := validateLAN(f.listen, f.cidr); err != nil {
		return serviceConfig{}, err
	}
	return serviceConfig{Listen: f.listen, LAN: f.cidr, Interface: f.iface}, nil
}

func statsSettings(c jsonObject, requestedAPI string) (jsonObject, string, error) {
	raw, err := json.Marshal(c)
	if err != nil {
		return nil, "", err
	}
	next, err := decodeXrayObject(raw)
	if err != nil {
		return nil, "", err
	}
	api := object(next["api"])
	if api == nil {
		if next["api"] != nil {
			return nil, "", errors.New("invalid Xray api object")
		}
		api = jsonObject{"tag": "xkeen-stats-api", "listen": requestedAPI}
	}
	address := str(api["listen"])
	if address == "" {
		// Классическая схема API: отдельный loopback-вход и правило к api.tag.
		for _, v := range array(next["inbounds"]) {
			in := object(v)
			for _, r := range array(object(next["routing"])["rules"]) {
				rule := object(r)
				if str(rule["outboundTag"]) != str(api["tag"]) {
					continue
				}
				for _, t := range array(rule["inboundTag"]) {
					if t == in["tag"] {
						address = net.JoinHostPort(str(in["listen"]), fmt.Sprint(in["port"]))
					}
				}
			}
		}
		if address == "" {
			return nil, "", errors.New("existing API routing cannot be detected safely")
		}
	}
	host, port, err := net.SplitHostPort(address)
	ip := net.ParseIP(host)
	n, _ := strconv.Atoi(port)
	if err != nil || ip == nil || !ip.IsLoopback() || n < 1 || n > 65535 {
		return nil, "", errors.New("StatsService API must listen on a loopback IP and valid port")
	}
	services := array(api["services"])
	hasStats := false
	for _, v := range services {
		if v == "StatsService" {
			hasStats = true
		}
	}
	if !hasStats {
		api["services"] = append(services, "StatsService")
	}
	next["api"] = api
	if next["stats"] == nil {
		next["stats"] = jsonObject{}
	} else if object(next["stats"]) == nil {
		return nil, "", errors.New("invalid Xray stats object")
	}
	policy := object(next["policy"])
	if policy == nil {
		policy = jsonObject{}
	}
	levels := object(policy["levels"])
	if levels == nil {
		levels = jsonObject{}
	}
	used := map[string]bool{"0": true}
	for _, v := range array(next["inbounds"]) {
		for _, u := range array(object(object(v)["settings"])["clients"]) {
			level := object(u)["level"]
			if level != nil {
				used[fmt.Sprint(level)] = true
			}
		}
	}
	for level := range used {
		p := object(levels[level])
		if p == nil {
			p = jsonObject{}
		}
		for _, k := range []string{"statsUserUplink", "statsUserDownlink", "statsUserOnline"} {
			p[k] = true
		}
		levels[level] = p
	}
	policy["levels"] = levels
	system := object(policy["system"])
	if system == nil {
		system = jsonObject{}
	}
	for _, k := range []string{"statsInboundUplink", "statsInboundDownlink", "statsOutboundUplink", "statsOutboundDownlink"} {
		system[k] = true
	}
	policy["system"] = system
	next["policy"] = policy
	return next, address, nil
}

func makeInstallPlan(a *App, o installOptions) (installPlan, error) {
	p := installPlan{originals: map[string][]byte{}}
	args, err := processArgs("xray")
	if err != nil {
		return p, err
	}
	path := a.configPath
	if !o.Explicit["config"] {
		path, err = detectXrayPath(args)
		if err != nil {
			return p, err
		}
		if old, e := processArgs("xkeen-stats"); e == nil {
			if saved, _ := commandOption(old, "-config"); saved != "" {
				path = saved
			} else if _, e := os.Stat(serviceConfigPath); e == nil {
				path = a.configPath
			} else if fs, e := xrayConfigFiles(path); e == nil && len(fs) == 1 && fs[0] == a.configPath {
				path = a.configPath
			}
		}
	}
	path, err = filepath.EvalSymlinks(path)
	if err != nil {
		return p, err
	}
	if !filepath.IsAbs(path) {
		return p, errors.New("Xray config path must be absolute")
	}
	c, files, err := readXrayObjects(path)
	if err != nil {
		return p, err
	}
	p.Files = files
	p.Assets, _ = commandOption(args, "-xks-assets")
	if p.Assets == "" {
		p.Assets = "/opt/etc/xray/dat"
	}
	for _, f := range files {
		b, e := os.ReadFile(f)
		if e != nil {
			return p, e
		}
		p.originals[f] = b
	}
	p.Xray = o.Xray
	if p.Xray == "" {
		p.Xray = args[0]
	}
	if !filepath.IsAbs(p.Xray) {
		p.Xray, err = exec.LookPath(p.Xray)
		if err != nil {
			return p, err
		}
	}
	init := o.Init
	if init == "" {
		matches, _ := filepath.Glob("/opt/etc/init.d/S*xkeen")
		if len(matches) != 1 {
			return p, errors.New("XKeen init script not found or ambiguous; specify -xkeen-init /opt/etc/init.d/S...xkeen")
		}
		init = matches[0]
	}
	if !filepath.IsAbs(init) {
		return p, errors.New("XKeen init script must be absolute")
	}
	if st, e := os.Stat(init); e != nil || st.Mode()&0111 == 0 {
		return p, errors.New("XKeen init script is not executable")
	}
	p.Restart = []string{init, "restart"}
	// Существующие настройки управления могут содержать обязательные аргументы restart.
	mc := managementConfig{}
	if b, e := os.ReadFile(filepath.Join(filepath.Dir(a.authPath), "management.json")); e == nil {
		if e = json.Unmarshal(b, &mc); e != nil {
			return p, e
		}
		if o.Init == "" && len(mc.Restart) > 0 {
			p.Restart = mc.Restart
		}
		if o.Source == "" {
			o.Source = mc.Source
		}
	}
	listen, lan := "", ""
	state := a.statePath
	auth := a.authPath
	token := a.setupTokenPath
	if old, e := processArgs("xkeen-stats"); e == nil {
		for name, target := range map[string]*string{"-listen": &listen, "-state": &state, "-auth": &auth, "-setup-token": &token, "-lan": &lan} {
			if v, _ := commandOption(old, name); v != "" {
				*target = v
			}
		}
	}
	if _, err := os.Stat(serviceConfigPath); err == nil {
		listen = a.listen
		lan = a.lanCIDR
	}
	if o.Explicit["listen"] {
		listen = a.listen
	}
	if o.Explicit["lan"] {
		lan = a.lanCIDR
	}
	if o.Explicit["state"] {
		state = a.statePath
	}
	if o.Explicit["auth"] {
		auth = a.authPath
	}
	if o.Explicit["setup-token"] {
		token = a.setupTokenPath
	}
	network, err := detectLAN(o.Interface, listen, lan)
	if err != nil {
		return p, err
	}
	network.Config = path
	network.State = state
	network.Auth = auth
	network.SetupToken = token
	for _, f := range []string{state, auth, token} {
		if !filepath.IsAbs(f) || !strings.HasPrefix(filepath.Clean(f), "/opt/") {
			return p, errors.New("state and authentication paths must be inside /opt")
		}
	}
	next, api, err := statsSettings(c, a.apiAddress)
	if err != nil {
		return p, err
	}
	network.API = api
	p.Service = network
	// Сравниваем JSON с единой моделью чисел, чтобы готовая конфигурация не менялась.
	normalized, _ := json.Marshal(c)
	nb, _ := json.Marshal(next)
	p.Changed = !bytes.Equal(normalized, nb)
	if p.Changed {
		st, _ := os.Stat(path)
		if st.IsDir() {
			p.Target = filepath.Join(path, "zzzz_xkeen_stats.json")
			if files[len(files)-1] > p.Target {
				return p, errors.New("statistics fragment must sort last in confdir")
			}
			fragment := jsonObject{}
			for _, k := range []string{"stats", "api", "policy", "observatory"} {
				if next[k] == nil {
					continue
				}
				fragment[k] = next[k]
			}
			p.next, _ = json.MarshalIndent(fragment, "", "  ")
		} else {
			p.Target = path
			p.next, _ = json.MarshalIndent(next, "", "  ")
		}
		p.next = append(p.next, '\n')
		if o.Source != "" && o.Source != path {
			if st.IsDir() {
				return p, errors.New("generator source for split configuration requires manual integration; no files changed")
			}
			source, e := filepath.EvalSymlinks(o.Source)
			if e != nil {
				return p, e
			}
			raw, e := os.ReadFile(source)
			if e != nil {
				return p, e
			}
			sourceConfig, e := decodeXrayObject(raw)
			if e != nil {
				return p, e
			}
			if !reflect.DeepEqual(c, sourceConfig) {
				return p, errors.New("source and active Xray config differ; no files changed")
			}
			p.Source = source
			p.originals[source] = raw
		}
	}
	return p, nil
}

func installerCommand(args []string, logPath string, env ...string) error {
	if len(args) == 0 || !filepath.IsAbs(args[0]) {
		return errors.New("command requires an absolute executable path")
	}
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Stdout = f
	cmd.Stderr = f
	cmd.Env = append(os.Environ(), env...)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("command %s failed; inspect private log %s", filepath.Base(args[0]), logPath)
	}
	return nil
}

type installBackup struct {
	Path   string
	Data   []byte
	Mode   os.FileMode
	Exists bool
}

func installFiles(files map[string][]byte, modes map[string]os.FileMode, backupDir string) ([]installBackup, error) {
	return installFilesWithWriter(files, modes, backupDir, atomicWrite)
}

func installFilesWithWriter(files map[string][]byte, modes map[string]os.FileMode, backupDir string, write func(string, []byte) error) ([]installBackup, error) {
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	backups := make([]installBackup, 0, len(paths))
	for i, path := range paths {
		b := installBackup{Path: path}
		st, e := os.Lstat(path)
		if e == nil {
			if !st.Mode().IsRegular() {
				return nil, fmt.Errorf("refusing to replace non-regular file %s", path)
			}
			b.Data, e = os.ReadFile(path)
			if e != nil {
				return nil, e
			}
			b.Mode = st.Mode().Perm()
			b.Exists = true
			if e = atomicWrite(filepath.Join(backupDir, fmt.Sprintf("%02d.previous", i)), b.Data); e != nil {
				return nil, e
			}
		} else if !os.IsNotExist(e) {
			return nil, e
		}
		backups = append(backups, b)
	}
	index := make([]map[string]any, 0, len(backups))
	for i, b := range backups {
		index = append(index, map[string]any{"path": b.Path, "exists": b.Exists, "mode": b.Mode, "backup": fmt.Sprintf("%02d.previous", i)})
	}
	b, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := atomicWrite(filepath.Join(backupDir, "files.json"), b); err != nil {
		return nil, err
	}
	// Все предыдущие файлы сохранены до первой замены.
	for _, path := range paths {
		if e := write(path, files[path]); e != nil {
			return backups, e
		}
		if e := os.Chmod(path, modes[path]); e != nil {
			return backups, e
		}
	}
	return backups, nil
}

func restoreInstallFiles(backups []installBackup) error {
	var errs []error
	for i := len(backups) - 1; i >= 0; i-- {
		b := backups[i]
		if b.Exists {
			if e := atomicWrite(b.Path, b.Data); e != nil {
				errs = append(errs, e)
			} else if e = os.Chmod(b.Path, b.Mode); e != nil {
				errs = append(errs, e)
			}
		} else if e := os.Remove(b.Path); e != nil && !os.IsNotExist(e) {
			errs = append(errs, e)
		}
	}
	return errors.Join(errs...)
}

func applyInstall(p installPlan, allowRestart bool) (result error) {
	if p.Changed && !allowRestart {
		return errors.New("statistics need enabling: repeat with -allow-xray-restart; this briefly restarts Xray")
	}
	backupDir, err := os.MkdirTemp("/opt/etc/xkeen-stats/install-backups", "install-")
	if err != nil {
		return err
	}
	logPath := filepath.Join(backupDir, "install.log")
	meta, _ := json.MarshalIndent(p, "", "  ")
	if err := atomicWrite(filepath.Join(backupDir, "plan.json"), meta); err != nil {
		return err
	}
	// Проверка кандидата выполняется до остановки сервиса и изменений активного конфига.
	if p.Changed {
		testPath := filepath.Join(backupDir, "candidate.json")
		testArgs := []string{p.Xray, "run", "-test", "-config", testPath}
		if st, _ := os.Stat(p.Service.Config); st.IsDir() {
			stage := filepath.Join(backupDir, "configs")
			if err := os.Mkdir(stage, 0700); err != nil {
				return err
			}
			for _, f := range p.Files {
				if err := atomicWrite(filepath.Join(stage, filepath.Base(f)), p.originals[f]); err != nil {
					return err
				}
			}
			testPath = filepath.Join(stage, filepath.Base(p.Target))
			testArgs = []string{p.Xray, "run", "-test", "-confdir", stage}
		}
		if err := atomicWrite(testPath, p.next); err != nil {
			return err
		}
		if err := installerCommand(testArgs, logPath, "XRAY_LOCATION_ASSET="+p.Assets); err != nil {
			return err
		}
	}
	const service = "/opt/etc/init.d/S99xkeen-stats"
	_, oldServiceErr := os.Stat(service)
	_, wasRunningErr := processArgs("xkeen-stats")
	if wasRunningErr == nil && oldServiceErr != nil {
		return errors.New("existing statistics process has no managed init script")
	}
	if oldServiceErr == nil {
		if err := installerCommand([]string{service, "stop"}, logPath); err != nil {
			return err
		}
	}
	var backups []installBackup
	changed := false
	defer func() {
		if result == nil {
			return
		}
		var rollback []error
		if changed {
			_ = installerCommand([]string{service, "stop"}, logPath)
			rollback = append(rollback, restoreInstallFiles(backups))
			if p.Changed {
				rollback = append(rollback, installerCommand(p.Restart, logPath))
			}
			if oldServiceErr == nil {
				rollback = append(rollback, installerCommand([]string{service, "start"}, logPath))
			}
		} else if wasRunningErr == nil {
			rollback = append(rollback, installerCommand([]string{service, "start"}, logPath))
		}
		result = errors.Join(result, errors.Join(rollback...), fmt.Errorf("installation backup: %s", backupDir))
	}()
	for f, before := range p.originals {
		current, e := os.ReadFile(f)
		if e != nil || !bytes.Equal(current, before) {
			return errors.New("Xray configuration changed during installation; retry")
		}
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	binary, err := os.ReadFile(self)
	if err != nil {
		return err
	}
	config, _ := json.MarshalIndent(p.Service, "", "  ")
	files := map[string][]byte{"/opt/sbin/xkeen-stats": binary, service: initScript, "/opt/etc/ndm/netfilter.d/051-xkeen-stats-lan.sh": firewallScript, serviceConfigPath: append(config, '\n')}
	modes := map[string]os.FileMode{service: 0700, "/opt/sbin/xkeen-stats": 0700, "/opt/etc/ndm/netfilter.d/051-xkeen-stats-lan.sh": 0700, serviceConfigPath: 0600}
	if p.Changed {
		files[p.Target] = p.next
		modes[p.Target] = 0600
		if p.Source != "" {
			files[p.Source] = p.next
			modes[p.Source] = 0600
		}
	}
	backups, err = installFiles(files, modes, backupDir)
	changed = len(backups) > 0
	if err != nil {
		return err
	}
	if p.Changed {
		if err := installerCommand(p.Restart, logPath); err != nil {
			return err
		}
	}
	if err := installerCommand([]string{service, "start"}, logPath); err != nil {
		return err
	}
	if err := healthyVersion(p.Service.Listen, version); err != nil {
		return err
	}
	link, err := exec.Command("/opt/sbin/xkeen-stats", "-setup-link").Output()
	if err != nil {
		return err
	}
	if err := atomicWrite(filepath.Join(backupDir, "committed"), []byte("ok\n")); err != nil {
		return err
	}
	fmt.Printf("Установлено %s. Страница: http://%s/\nРезервная копия: %s\n", version, p.Service.Listen, backupDir)
	fmt.Print(string(link))
	return nil
}

func runInstaller(a *App, o installOptions) error {
	if runtime.GOOS != "linux" {
		return errors.New("installer requires Keenetic Linux with Entware")
	}
	if _, err := os.Stat("/opt/etc/init.d/rc.func"); err != nil {
		return errors.New("Entware rc.func not found; install Entware and XKeen first")
	}
	if !o.PlanOnly && os.Geteuid() != 0 {
		return errors.New("installation requires root")
	}
	if !o.PlanOnly {
		self, err := os.Executable()
		if err != nil {
			return err
		}
		if filepath.Base(self) == "xkeen-stats" {
			return errors.New("run install.sh: installer must have a different process name so the service stop cannot terminate it")
		}
	}
	p, err := makeInstallPlan(a, o)
	if err != nil {
		return err
	}
	b, _ := json.MarshalIndent(p, "", "  ")
	fmt.Println(string(b))
	if o.PlanOnly {
		return nil
	}
	if err := os.MkdirAll("/opt/etc/xkeen-stats/install-backups", 0700); err != nil {
		return err
	}
	lock := "/opt/etc/xkeen-stats/install.lock"
	if err := os.Mkdir(lock, 0700); err != nil {
		return errors.New("installation already running or interrupted: inspect install.lock and install-backups before retry")
	}
	defer os.Remove(lock)
	return applyInstall(p, o.AllowRestart)
}

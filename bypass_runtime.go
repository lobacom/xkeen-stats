package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const bypassChain = "XKSTATS_BYPASS"
const bypassMarker = "xkst-bypass-revision:"
const bypassHookPath = "/opt/etc/ndm/netfilter.d/zz-xkeen-stats-bypass.sh"
const bypassHookContent = `#!/opt/bin/sh
# Managed by XKeen Stats: LAN bypass.
case "${table:-}" in filter|raw) exit 0 ;; esac
PATH=/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
export GOMEMLIMIT=16MiB
export GOGC=100
exec /opt/sbin/xkeen-stats -bypass-firewall
`

type bypassPlan struct {
	Sets    []string
	SetData []byte
	Restore map[int][]byte
}

func renderBypass(c bypassConfig, revision string, families []int) bypassPlan {
	p := bypassPlan{Restore: map[int][]byte{}}
	gen := revision[:12]
	var sets strings.Builder
	rules := map[int][]string{4: {}, 6: {}}
	for i, r := range c.Rules {
		if !r.Enabled {
			continue
		}
		prefix := "xsb_" + gen + "_" + strconv.Itoa(i)
		deviceSet := ""
		if len(r.Devices) > 0 {
			deviceSet = prefix + "m"
			p.Sets = append(p.Sets, deviceSet)
			fmt.Fprintf(&sets, "create %s hash:mac hashsize 64 maxelem 256\n", deviceSet)
			for _, d := range r.Devices {
				fmt.Fprintf(&sets, "add %s %s\n", deviceSet, d.MAC)
			}
		}
		for _, family := range []int{4, 6} {
			addresses := []string{}
			for _, value := range r.Destinations {
				ip, _ := netip.ParsePrefix(value)
				if ip.Addr().Is4() == (family == 4) {
					addresses = append(addresses, value)
				}
			}
			if len(addresses) == 0 {
				continue
			}
			name := prefix + strconv.Itoa(family)
			p.Sets = append(p.Sets, name)
			inet := "inet"
			if family == 6 {
				inet = "inet6"
			}
			fmt.Fprintf(&sets, "create %s hash:net family %s hashsize 64 maxelem 4096\n", name, inet)
			for _, value := range addresses {
				fmt.Fprintf(&sets, "add %s %s\n", name, value)
			}
			args := "-i " + c.Interface + " -m connmark ! --mark 0x111"
			if r.Network != "all" {
				args += " -p " + r.Network
			}
			if r.Ports != "" {
				args += " -m multiport --dports " + strings.ReplaceAll(r.Ports, "-", ":")
			}
			if deviceSet != "" {
				args += " -m set --match-set " + deviceSet + " src"
			}
			args += " -m set --match-set " + name + " dst -m comment --comment xkst-bypass-rule:" + r.ID + " -j ACCEPT"
			rules[family] = append(rules[family], "-A "+bypassChain+" "+args+"\n")
		}
	}
	p.SetData = []byte(sets.String())
	for _, family := range families {
		var restore strings.Builder
		for _, table := range []string{"nat", "mangle"} {
			fmt.Fprintf(&restore, "*%s\n:%s - [0:0]\n-F %s\n", table, bypassChain, bypassChain)
			for _, rule := range rules[family] {
				restore.WriteString(rule)
			}
			fmt.Fprintf(&restore, "-A %s -m comment --comment %s%s -j RETURN\nCOMMIT\n", bypassChain, bypassMarker, gen)
		}
		p.Restore[family] = []byte(restore.String())
	}
	return p
}

func (a *App) bypassCommand(ctx context.Context, name string, args []string, input []byte) ([]byte, error) {
	if a.bypassRun != nil {
		return a.bypassRun(ctx, name, args, input)
	}
	if runtime.GOOS != "linux" {
		return nil, errors.New("Управление обходом доступно на Linux/Entware")
	}
	command := exec.CommandContext(ctx, name, args...)
	command.Stdin = bytes.NewReader(input)
	out, err := command.CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(string(out))
		if len(message) > 400 {
			message = message[:400]
		}
		return out, fmt.Errorf("%s: %s (%w)", name, message, err)
	}
	return out, nil
}

func (a *App) applyBypassConfig(c bypassConfig, raw []byte) (result error) {
	if a.bypassApply != nil {
		return a.bypassApply(c, bypassRevision(raw))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	previous := a.bypassStatus()
	var plan bypassPlan
	defer func() {
		if result != nil {
			previous.Error = result.Error()
			// Сохраняем также частично созданное поколение: успешный откат
			// или следующий restore удалит его после замены ссылок в цепочках.
			for _, set := range plan.Sets {
				if !contains(previous.Sets, set) {
					previous.Sets = append(previous.Sets, set)
				}
			}
			data, _ := json.Marshal(previous)
			_ = atomicWrite(filepath.Join(a.bypassDir(), "status.json"), data)
		}
	}()
	hook := a.bypassHook
	if hook == "" {
		hook = bypassHookPath
	}
	if b, err := os.ReadFile(hook); err == nil && string(b) != bypassHookContent {
		return errors.New("Хук обхода изменён извне; автоматическая перезапись остановлена")
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	boot, _ := os.ReadFile("/proc/sys/kernel/random/boot_id")
	families := []int{4}
	for _, r := range c.Rules {
		for _, v := range r.Destinations {
			p, _ := netip.ParsePrefix(v)
			if r.Enabled && p.Addr().Is6() && !containsInt(families, 6) {
				families = append(families, 6)
			}
		}
	}
	if containsInt(previous.Families, 6) && !containsInt(families, 6) {
		families = append(families, 6)
	}
	previous.Families = families
	revision := bypassRevision(raw)
	plan = renderBypass(c, revision, families)
	ready := previous.Revision == revision && previous.Boot == strings.TrimSpace(string(boot)) && previous.Error == ""
	if ready && len(plan.Sets) > 0 {
		out, err := a.bypassCommand(ctx, "ipset", []string{"list", "-name"}, nil)
		if err != nil {
			ready = false
		} else {
			names := map[string]bool{}
			for _, n := range strings.Fields(string(out)) {
				names[n] = true
			}
			for _, n := range plan.Sets {
				if !names[n] {
					ready = false
				}
			}
		}
	}
	if !ready && len(plan.SetData) > 0 {
		if _, err := a.bypassCommand(ctx, "ipset", []string{"-exist", "restore"}, plan.SetData); err != nil {
			return err
		}
	}
	for _, family := range families {
		binary := "iptables"
		if family == 6 {
			binary = "ip6tables"
		}
		needsRestore := !ready
		for _, table := range []string{"nat", "mangle"} {
			out, err := a.bypassCommand(ctx, binary, []string{"-w", "-t", table, "-S", bypassChain}, nil)
			if err == nil && !strings.Contains(string(out), bypassMarker) {
				return errors.New("Обнаружена посторонняя цепочка с именем " + bypassChain)
			}
			if err != nil || !strings.Contains(string(out), bypassMarker+revision[:12]) {
				needsRestore = true
			}
		}
		if needsRestore {
			// Старый iptables-restore Keenetic не поддерживает -w. Меняются только
			// наши цепочки; при занятой xtables-блокировке повторяем ограниченно.
			var err error
			for attempt := 0; attempt < 8; attempt++ {
				_, err = a.bypassCommand(ctx, binary+"-restore", []string{"--noflush"}, plan.Restore[family])
				if err == nil {
					break
				}
				message := strings.ToLower(err.Error())
				if !strings.Contains(message, "lock") && !strings.Contains(message, "temporarily unavailable") {
					return err
				}
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(150 * time.Millisecond):
				}
			}
			if err != nil {
				return err
			}
		}
		for _, table := range []string{"nat", "mangle"} {
			if _, err := a.bypassCommand(ctx, binary, []string{"-w", "-t", table, "-C", "xkeen", "-j", bypassChain}, nil); err != nil {
				if _, err = a.bypassCommand(ctx, binary, []string{"-w", "-t", table, "-S", "xkeen"}, nil); err != nil {
					if bytes.Contains(plan.Restore[family], []byte("-j ACCEPT")) {
						return fmt.Errorf("Не найдена цепочка XKeen для %s/%s", binary, table)
					}
					continue
				}
				if _, err = a.bypassCommand(ctx, binary, []string{"-w", "-t", table, "-I", "xkeen", "1", "-j", bypassChain}, nil); err != nil {
					return err
				}
			}
		}
	}
	if len(raw) > 0 {
		if err := writeBypassHook(hook); err != nil {
			return err
		}
	} else if b, err := os.ReadFile(hook); err == nil && string(b) == bypassHookContent {
		if err = os.Remove(hook); err != nil {
			return err
		}
	}
	status := bypassStatus{Revision: revision, Applied: time.Now().Unix(), Boot: strings.TrimSpace(string(boot)), Sets: plan.Sets, Families: families}
	data, _ := json.Marshal(status)
	if err := atomicWrite(filepath.Join(a.bypassDir(), "status.json"), data); err != nil {
		return err
	}
	// Старые наборы удаляются лишь после переключения всех собственных цепочек.
	for _, set := range previous.Sets {
		if !contains(plan.Sets, set) && strings.HasPrefix(set, "xsb_") {
			_, _ = a.bypassCommand(ctx, "ipset", []string{"destroy", set}, nil)
		}
	}
	return nil
}

func containsInt(values []int, value int) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}

func writeBypassHook(path string) error {
	if b, err := os.ReadFile(path); err == nil {
		if string(b) != bypassHookContent {
			return errors.New("Хук обхода изменён извне; автоматическая перезапись остановлена")
		}
		return os.Chmod(path, 0700)
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := atomicWrite(path, []byte(bypassHookContent)); err != nil {
		return err
	}
	return os.Chmod(path, 0700)
}

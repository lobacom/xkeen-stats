package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"time"
)

func applyFirewall(c serviceConfig) error {
	if _, err := validateLAN(c.Listen, c.LAN); err != nil {
		return err
	}
	if _, err := net.InterfaceByName(c.Interface); err != nil {
		return errors.New("LAN interface not found")
	}
	_, port, _ := net.SplitHostPort(c.Listen)
	p, _ := strconv.Atoi(port)
	if p < 1 || p > 65535 {
		return errors.New("invalid firewall port")
	}
	ip, _, _ := net.SplitHostPort(c.Listen)
	iptab, err := exec.LookPath("iptables")
	if err != nil {
		return err
	}
	run := func(args ...string) error {
		// На Keenetic правила параллельно обновляет NDMS. Старый iptables
		// поддерживает только -w без числа секунд; предел задаём контекстом.
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if out, e := exec.CommandContext(ctx, iptab, append([]string{"-w"}, args...)...).CombinedOutput(); e != nil {
			return fmt.Errorf("iptables %v: %s", args, out)
		}
		return nil
	}
	first, second := "XKS_"+port+"_A", "XKS_"+port+"_B"
	if run("-C", "INPUT", "-p", "tcp", "--dport", port, "-j", first) == nil {
		first, second = second, first
	}
	// Заполняем неактивную цепочку; INPUT переключается только после её подготовки.
	if run("-nL", first) != nil {
		if err := run("-N", first); err != nil {
			return err
		}
	}
	if err := run("-F", first); err != nil {
		return err
	}
	if err := run("-A", first, "-i", "lo", "-j", "ACCEPT"); err != nil {
		return err
	}
	_, accessErr := initialAccess(c.Auth, c.SetupToken, false)
	if accessErr == nil {
		if err := run("-A", first, "-i", c.Interface, "-s", c.LAN, "-d", ip, "-j", "ACCEPT"); err != nil {
			return err
		}
	}
	if err := run("-A", first, "-p", "tcp", "-j", "REJECT", "--reject-with", "tcp-reset"); err != nil {
		return err
	}
	if err := run("-I", "INPUT", "1", "-p", "tcp", "--dport", port, "-j", first); err != nil {
		return err
	}
	for _, old := range []string{second, "XKSTATS_LAN"} {
		for run("-C", "INPUT", "-p", "tcp", "--dport", port, "-j", old) == nil {
			if err := run("-D", "INPUT", "-p", "tcp", "--dport", port, "-j", old); err != nil {
				return err
			}
		}
	}
	return accessErr
}

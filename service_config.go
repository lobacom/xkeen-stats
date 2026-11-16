package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
)

const serviceConfigPath = "/opt/etc/xkeen-stats/service.json"

type serviceConfig struct {
	Listen     string `json:"listen"`
	LAN        string `json:"lan"`
	Interface  string `json:"interface"`
	Config     string `json:"config"`
	API        string `json:"api"`
	State      string `json:"state"`
	Auth       string `json:"auth"`
	SetupToken string `json:"setup_token"`
}

func defaultServiceConfig() serviceConfig {
	return serviceConfig{"192.168.1.1:1001", "192.168.1.0/24", "br0", "/opt/etc/xray/configs/00_cascade.json", "127.0.0.1:10085", "/opt/var/lib/xkeen-stats/state.json", "/opt/etc/xkeen-stats/auth.json", "/opt/etc/xkeen-stats/setup-token"}
}

func readServiceConfig() (serviceConfig, error) {
	c := defaultServiceConfig()
	b, err := os.ReadFile(serviceConfigPath)
	if os.IsNotExist(err) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	if len(b) > 65536 {
		return c, errors.New("service.json too large")
	}
	err = json.Unmarshal(b, &c)
	return c, err
}

func validateLAN(listen, cidr string) (*net.IPNet, error) {
	host, port, err := net.SplitHostPort(listen)
	if err != nil || port == "" {
		return nil, errors.New("listen must be an IPv4 address and port")
	}
	ip := net.ParseIP(host)
	_, lan, err := net.ParseCIDR(cidr)
	if err != nil || lan.IP.To4() == nil || ip.To4() == nil || !lan.Contains(ip) || !ip.IsPrivate() {
		return nil, errors.New("listen must be a private IPv4 address inside the LAN subnet")
	}
	ones, bits := lan.Mask.Size()
	if ones < 8 || bits != 32 {
		return nil, errors.New("LAN subnet must be IPv4 /8 or narrower")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return nil, fmt.Errorf("invalid listen port %q", port)
	}
	return lan, nil
}

func (a *App) permitsIP(ip net.IP) bool {
	if ip.IsLoopback() {
		return true
	}
	cidr := a.lanCIDR
	if cidr == "" {
		cidr = "192.168.1.0/24"
	}
	_, lan, err := net.ParseCIDR(cidr)
	return err == nil && lan.Contains(ip)
}

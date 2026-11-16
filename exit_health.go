package main

import (
	"errors"
	"sort"
	"strings"
	"time"
)

type exitStatus struct {
	Tag      string `json:"tag"`
	Alive    bool   `json:"alive"`
	Delay    int64  `json:"delay_ms"`
	LastSeen int64  `json:"last_seen"`
	LastTry  int64  `json:"last_try"`
}

type exitHealth struct {
	Enabled    bool         `json:"enabled"`
	Checked    int64        `json:"checked"`
	StaleAfter int64        `json:"stale_after"`
	Error      string       `json:"error"`
	Outbounds  []exitStatus `json:"outbounds"`
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

func enableExitProbes(c jsonObject) error {
	if c["observatory"] == nil {
		if c["burstObservatory"] != nil {
			return errors.New("burstObservatory already configured; existing monitoring left unchanged")
		}
		var tags []any
		for _, v := range array(c["outbounds"]) {
			o := object(v)
			if isVPNExit(o) && str(o["tag"]) != "" {
				tags = append(tags, o["tag"])
			}
		}
		if len(tags) == 0 {
			return errors.New("no tagged VPN outbounds found for probes")
		}
		c["observatory"] = jsonObject{"subjectSelector": tags, "probeUrl": "https://www.gstatic.com/generate_204", "probeInterval": "1m", "enableConcurrency": true}
	}
	api := object(c["api"])
	if api == nil {
		return errors.New("API required for ObservatoryService")
	}
	for _, v := range array(api["services"]) {
		if v == "ObservatoryService" {
			return nil
		}
	}
	api["services"] = append(array(api["services"]), "ObservatoryService")
	return nil
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
			s := exitStatus{}
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
	if time.Since(a.lastHealthAttempt) < 15*time.Second {
		return
	}
	a.lastHealthAttempt = time.Now()
	h := exitHealth{StaleAfter: 180, Outbounds: []exitStatus{}}
	defer func() { a.mu.Lock(); a.exitHealth = h; a.mu.Unlock() }()
	c, _, err := readXrayObjects(a.configPath)
	if err != nil {
		h.Error = "Не удалось прочитать настройки проверки выходов"
		return
	}
	obs := object(c["observatory"])
	if obs == nil {
		return
	}
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

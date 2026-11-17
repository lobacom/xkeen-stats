package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

type fallbackConfig struct {
	Enabled      bool   `json:"enabled"`
	Outbound     string `json:"outbound"`
	AfterMinutes int    `json:"after_minutes"`
}

type fallbackRuntime struct {
	Current     string `json:"current"`
	DownSince   int64  `json:"down_since"`
	LastSample  int64  `json:"last_sample"`
	LastAttempt int64  `json:"last_attempt"`
	LastSwitch  int64  `json:"last_switch"`
	SwitchedTo  string `json:"switched_to"`
	Error       string `json:"error"`
}

type fallbackSnapshot struct {
	fallbackConfig
	Revision string          `json:"revision"`
	Runtime  fallbackRuntime `json:"runtime"`
	Error    string          `json:"error"`
}

func (a *App) fallbackPath() string {
	return filepath.Join(filepath.Dir(a.authPath), "lan-fallback.json")
}

func (a *App) readFallback() (fallbackConfig, string, error) {
	c := fallbackConfig{AfterMinutes: 10}
	b, err := os.ReadFile(a.fallbackPath())
	if os.IsNotExist(err) {
		return c, configRevision(nil), nil
	}
	if err != nil {
		return c, "", err
	}
	if len(b) > 4096 || json.Unmarshal(b, &c) != nil || c.AfterMinutes < 1 || c.AfterMinutes > 1440 || (c.Enabled && c.Outbound == "") {
		return c, "", errors.New("Некорректные настройки резервного выхода")
	}
	return c, configRevision(b), nil
}

func (a *App) fallbackSnapshot() fallbackSnapshot {
	c, revision, err := a.readFallback()
	s := fallbackSnapshot{fallbackConfig: c, Revision: revision}
	if err != nil {
		s.Error = "Не удалось прочитать настройки резервного выхода"
	}
	a.mu.Lock()
	s.Runtime = a.fallbackRuntime
	a.mu.Unlock()
	return s
}

func validFallbackTarget(cfg jsonObject, mc managementConfig, target string) bool {
	if target == "" {
		return false
	}
	if direct := lanDirectOutbound(cfg, mc); direct != "" && target == direct {
		return true
	}
	return contains(mc.LAN.Outbounds, target) && isVPNExit(configuredTags(cfg, "outbounds")[target])
}

func (a *App) saveFallback(mc managementConfig, cfg jsonObject, revision string, settings fallbackConfig) error {
	_, current, err := a.readFallback()
	if err != nil || revision == "" || revision != current {
		return errors.New("Настройки резерва изменились. Обновите список")
	}
	if settings.AfterMinutes < 1 || settings.AfterMinutes > 1440 {
		return errors.New("Задержка должна быть от 1 до 1440 минут")
	}
	if (settings.Outbound != "" && !validFallbackTarget(cfg, mc, settings.Outbound)) || (settings.Enabled && settings.Outbound == "") {
		return errors.New("Выберите доступный резервный выход")
	}
	if len(mc.LAN.Inbounds) == 0 || mc.LAN.BaseOutbound == "" {
		return errors.New("Домашние входы не настроены")
	}
	b, _ := json.MarshalIndent(settings, "", "  ")
	if err := atomicWrite(a.fallbackPath(), append(b, '\n')); err != nil {
		return errors.New("Не удалось сохранить настройки резерва")
	}
	a.resetFallback()
	return nil
}

func (a *App) resetFallback() {
	a.mu.Lock()
	a.fallbackRuntime = fallbackRuntime{}
	a.mu.Unlock()
}

// Неизвестный, локальный или просроченный результат не считается отказом VPN.
func freshFallbackStatus(h exitHealth, tag string, now int64) (exitStatus, bool) {
	if !h.Enabled || h.Error != "" || h.StaleAfter <= 0 || h.Checked <= 0 || h.Checked > now || now-h.Checked > h.StaleAfter {
		return exitStatus{}, false
	}
	for _, s := range h.Outbounds {
		if s.Tag == tag && s.Supported && s.Scope != "local" && s.LastTry > 0 && s.LastTry <= now && now-s.LastTry <= h.StaleAfter {
			return s, true
		}
	}
	return exitStatus{}, false
}

// Решение опирается на непрерывную последовательность свежих неудачных проверок.
// После перехода на резерв обратное переключение выполняется только вручную.
func (r *fallbackRuntime) observe(settings fallbackConfig, current, direct string, h exitHealth, now int64) bool {
	if r.Current != current {
		*r = fallbackRuntime{Current: current, LastSwitch: r.LastSwitch, SwitchedTo: r.SwitchedTo}
	}
	status, known := freshFallbackStatus(h, current, now)
	if !settings.Enabled || current == "" || current == settings.Outbound || current == direct || !known || status.Alive {
		r.DownSince, r.LastSample = 0, 0
		return false
	}
	if r.LastSample > 0 && (status.LastTry < r.LastSample || status.LastTry-r.LastSample > h.StaleAfter) {
		r.DownSince = 0
	}
	if r.DownSince == 0 {
		r.DownSince = status.LastTry
	}
	r.LastSample = status.LastTry
	if status.LastTry-r.DownSince < int64(settings.AfterMinutes)*60 {
		return false
	}
	if r.LastAttempt > 0 && now-r.LastAttempt < int64(settings.AfterMinutes)*60 {
		return false
	}
	if settings.Outbound != direct {
		target, known := freshFallbackStatus(h, settings.Outbound, now)
		if !known || !target.Alive {
			return false
		}
	}
	return true
}

func (a *App) evaluateFallback(now time.Time) {
	// Тот же mutex и транзакция, что и у ручного управления/редактирования клиентов.
	if !a.managementMu.TryLock() {
		return
	}
	defer a.managementMu.Unlock()
	settings, _, err := a.readFallback()
	if err != nil || !settings.Enabled {
		a.resetFallback()
		return
	}
	if a.updater != nil && activePending(a.updater.dir) {
		a.resetFallback()
		return
	}
	if _, err = os.Stat(filepath.Join(a.managementDir(), "pending.json")); !os.IsNotExist(err) {
		a.resetFallback()
		return
	}
	mc, err := a.managementConfig()
	if err != nil {
		a.resetFallback()
		return
	}
	cfg, original, err := loadManagedConfig(a.configPath)
	if err != nil || !validFallbackTarget(cfg, mc, settings.Outbound) {
		a.resetFallback()
		return
	}
	current := a.managementSnapshot(mc, cfg, original).LANExit
	a.mu.Lock()
	switchNow := a.fallbackRuntime.observe(settings, current, lanDirectOutbound(cfg, mc), a.exitHealth, now.Unix())
	if switchNow {
		a.fallbackRuntime.LastAttempt = now.Unix()
	}
	a.mu.Unlock()
	if !switchNow {
		return
	}
	next := cloneObject(cfg)
	err = switchLAN(next, mc, settings.Outbound)
	if err == nil {
		err = a.commitManagedConfig(mc, configRevision(original), original, next)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if err != nil {
		a.fallbackRuntime.Error = err.Error()
		return
	}
	a.fallbackRuntime = fallbackRuntime{Current: settings.Outbound, LastSwitch: time.Now().Unix(), SwitchedTo: settings.Outbound}
}

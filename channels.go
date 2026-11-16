package main

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// Здесь читаются только поля, нужные для пояснений и списка пользователей.
// Адреса серверов, ключи, пароли и полные настройки в API не передаются.
type channelConfig struct {
	Tag           string `json:"tag"`
	Protocol      string `json:"protocol"`
	ProxySettings struct {
		Tag string `json:"tag"`
	} `json:"proxySettings"`
	Settings struct {
		Clients []struct {
			Email string `json:"email"`
		} `json:"clients"`
		FollowRedirect bool   `json:"followRedirect"`
		AllowedNetwork string `json:"allowedNetwork"`
		Network        string `json:"network"`
	} `json:"settings"`
	StreamSettings struct {
		Network string `json:"network"`
		Sockopt struct {
			TProxy      string `json:"tproxy"`
			DialerProxy string `json:"dialerProxy"`
		} `json:"sockopt"`
	} `json:"streamSettings"`
}

type channelInfo struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Protocol    string `json:"protocol,omitempty"`
	Transport   string `json:"transport,omitempty"`
}

type channelLabel struct {
	Title       string `json:"title"`
	Description string `json:"description"`
}

func describeChannel(kind string, c channelConfig) channelInfo {
	p := strings.ToLower(c.Protocol)
	protocol := strings.ToUpper(c.Protocol)
	d := channelInfo{Protocol: protocol, Transport: strings.ToUpper(c.StreamSettings.Network)}
	if kind == "inbound" {
		switch p {
		case "tunnel", "dokodemo-door":
			network := c.Settings.AllowedNetwork
			if network == "" {
				network = c.Settings.Network
			}
			if network == "" {
				network = "tcp"
			}
			network = strings.ToUpper(strings.ReplaceAll(network, ",", "/"))
			if c.Settings.FollowRedirect {
				d.Title = "Прозрачный прокси · " + network
				d.Description = "Перехваченный трафик. Адрес назначения берётся из исходного соединения."
				if c.StreamSettings.Sockopt.TProxy == "tproxy" {
					d.Description += " Используется TPROXY."
				}
			} else {
				d.Title = "Перенаправление · " + network
				d.Description = "Входящий трафик передаётся на заданное в конфигурации назначение."
			}
		case "socks", "http", "mixed":
			d.Title = "Прокси для приложений · " + protocol
			d.Description = "Подключения приложений, настроенных на этот прокси."
		case "tun":
			d.Title = "Виртуальный интерфейс · TUN"
			d.Description = "Трафик, поступающий в Xray через виртуальный сетевой интерфейс."
		default:
			d.Title = "Клиентский вход"
			d.Description = "Входящие подключения клиентов Xray."
			if protocol != "" {
				d.Title += " · " + protocol
			}
		}
	} else {
		switch p {
		case "freedom":
			d.Title = "Прямое подключение"
			d.Description = "Xray устанавливает соединение с назначением без прокси этого выхода."
			if c.ProxySettings.Tag != "" || c.StreamSettings.Sockopt.DialerProxy != "" {
				d.Title = "Выход Freedom через цепочку"
				d.Description = "Подключение использует другой выход Xray, указанный в настройках цепочки."
			}
		case "blackhole":
			d.Title = "Блокировка"
			d.Description = "Трафик отклоняется и не передаётся дальше."
		case "dns":
			d.Title = "Обработка DNS"
			d.Description = "Выход для обработки DNS-запросов."
		case "loopback":
			d.Title = "Повторная маршрутизация"
			d.Description = "Соединения возвращаются на обработку правил маршрутизации Xray."
		default:
			d.Title = "Прокси-выход"
			d.Description = "Соединения, направленные Xray в этот выход."
			if protocol != "" {
				d.Title += " · " + protocol
			}
		}
	}
	if d.Transport != "" {
		d.Description += " Транспорт: " + d.Transport + "."
	}
	return d
}

func readChannelLabels(authPath string) (map[string]channelLabel, error) {
	f, err := os.Open(filepath.Join(filepath.Dir(authPath), "labels.json"))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil {
		return nil, err
	}
	if len(b) > 65536 {
		return nil, errors.New("channel labels file too large")
	}
	var labels map[string]channelLabel
	if err = json.Unmarshal(b, &labels); err != nil {
		return nil, err
	}
	for key, label := range labels {
		if (!strings.HasPrefix(key, "inbound:") && !strings.HasPrefix(key, "outbound:")) || utf8.RuneCountInString(label.Title) > 160 || utf8.RuneCountInString(label.Description) > 800 {
			return nil, errors.New("invalid channel label")
		}
	}
	return labels, nil
}

func applyChannelLabel(info channelInfo, label channelLabel) channelInfo {
	if title := strings.TrimSpace(label.Title); title != "" {
		info.Title = title
	}
	if description := strings.TrimSpace(label.Description); description != "" {
		info.Description = description
	}
	return info
}

package main

import "strings"

// Все настроенные VPN-выходы видны редактору клиентов, даже когда для части
// выходов ещё не создан отдельный вход. Ненастроенный вход нельзя экспортировать.
type managedClientExit struct {
	Tag    string   `json:"tag"`
	Title  string   `json:"title"`
	Inputs []string `json:"inbounds"`
}

func clientExitChoices(cfg jsonObject, outputs []managedOutput, inputs []managedInput) []managedClientExit {
	choices := []managedClientExit{}
	for _, output := range outputs {
		if output.Direct {
			continue
		}
		choice := managedClientExit{Tag: output.Tag, Title: output.Title, Inputs: []string{}}
		for _, input := range inputs {
			if clientDefaultOutbound(cfg, input.Tag) == output.Tag {
				choice.Inputs = append(choice.Inputs, input.Tag)
			}
		}
		choices = append(choices, choice)
	}
	return choices
}

// Связь определяется по действующему маршруту без ограничений назначения,
// с учётом порядка правил. Частные доменные/IP-исключения не задают выход профиля.
// При разных выходах TCP/UDP или балансировщике общий выход не выдумывается:
// такой реальный вход остаётся доступен в редакторе отдельно.
func clientDefaultOutbound(cfg jsonObject, inbound string) string {
	tcp := clientNetworkOutbound(cfg, inbound, "tcp")
	if tcp == "" || tcp != clientNetworkOutbound(cfg, inbound, "udp") {
		return ""
	}
	return tcp
}

func clientNetworkOutbound(cfg jsonObject, inbound, network string) string {
	for _, value := range array(object(cfg["routing"])["rules"]) {
		rule := object(value)
		if networks := str(rule["network"]); networks != "" {
			matches := false
			for _, token := range strings.Split(networks, ",") {
				if strings.TrimSpace(token) == network {
					matches = true
				}
			}
			if !matches {
				continue
			}
		}
		wide := true
		for key := range rule {
			switch key {
			case "type", "ruleTag", "inboundTag", "outboundTag", "balancerTag", "network":
			default:
				wide = false
			}
		}
		if !wide {
			continue
		}
		tags := array(rule["inboundTag"])
		matches := len(tags) == 0
		for _, tag := range tags {
			if str(tag) == inbound {
				matches = true
			}
		}
		if matches {
			return str(rule["outboundTag"])
		}
	}
	return ""
}

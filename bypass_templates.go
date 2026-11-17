package main

import (
	_ "embed"
	"encoding/json"
)

// Шаблоны — снимки проверенных диапазонов, без устройств конкретной установки.
// Их выбор заполняет редактор; рабочие правила меняются только при сохранении.
type bypassTemplate struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Description  string   `json:"description"`
	Updated      string   `json:"updated"`
	Sources      []string `json:"sources"`
	Network      string   `json:"network"`
	Ports        string   `json:"ports"`
	Scope        string   `json:"scope"`
	Destinations []string `json:"destinations"`
}

//go:embed bypass_templates.json
var bypassTemplatesJSON []byte

var builtinBypassTemplates = func() []bypassTemplate {
	var templates []bypassTemplate
	if err := json.Unmarshal(bypassTemplatesJSON, &templates); err != nil {
		panic("invalid built-in bypass templates: " + err.Error())
	}
	return templates
}()

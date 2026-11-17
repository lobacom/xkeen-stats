//go:build !linux

package main

// Реальные изменения firewall доступны только на Linux; заглушка нужна тестам.
func lockBypass(path string) (func(), error) { return func() {}, nil }

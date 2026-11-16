package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type updateJob struct {
	Directory, Executable, Candidate, Previous, Service string
	Target, PreviousVersion, Checksum                   string
	Listen, Auth, State, Config, API                    string
}
type updatePending struct {
	Job       string
	PID       int
	Preparing bool
}

func writeUpdateJSON(path string, value any) error {
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".update-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

func readUpdateJSON(path string, value any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if len(b) > 65536 {
		return errors.New("update state too large")
	}
	return json.Unmarshal(b, value)
}

func setUpdateProgress(dir, phase, target, message string) error {
	return writeUpdateJSON(filepath.Join(dir, "status.json"), updateProgress{Phase: phase, Target: target, Error: message})
}

func copyUpdateFile(source, target string, mode os.FileMode) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.CreateTemp(filepath.Dir(target), ".binary-*")
	if err != nil {
		return err
	}
	name := out.Name()
	defer os.Remove(name)
	if err = out.Chmod(mode); err == nil {
		_, err = io.Copy(out, in)
	}
	if err == nil {
		err = out.Sync()
	}
	closeErr := out.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(name, target)
}

func checksumFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func validJob(dir, path string, j updateJob) bool {
	rel, err := filepath.Rel(dir, path)
	return err == nil && !strings.HasPrefix(rel, "..") && filepath.IsAbs(j.Executable) && j.Directory == filepath.Dir(path) && j.Candidate == filepath.Join(j.Directory, "candidate") && j.Previous == filepath.Join(j.Directory, "previous") && stableVersion.MatchString(j.Target)
}

func activePending(dir string) bool {
	var p updatePending
	var j updateJob
	if readUpdateJSON(filepath.Join(dir, "pending.json"), &p) != nil || readUpdateJSON(p.Job, &j) != nil || !validJob(dir, p.Job, j) {
		return false
	}
	cmd, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(p.PID), "cmdline"))
	if err != nil {
		return false
	}
	args := strings.Split(string(cmd), "\x00")
	if p.Preparing {
		return len(args) > 0 && args[0] == j.Executable
	}
	return len(args) > 2 && args[0] == filepath.Join(dir, "updater") && args[1] == "-apply-update" && args[2] == p.Job
}

func serviceCommand(j updateJob, action string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, j.Service, action)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func healthyVersion(listen, wanted string) error {
	deadline := time.Now().Add(40 * time.Second)
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil}}
	for time.Now().Before(deadline) {
		resp, err := client.Get("http://" + listen + "/healthz")
		if err == nil {
			var result struct {
				Version string `json:"version"`
				Ready   bool   `json:"ready"`
			}
			err = json.NewDecoder(io.LimitReader(resp.Body, 1024)).Decode(&result)
			resp.Body.Close()
			if err == nil && resp.StatusCode == 200 && result.Ready && result.Version == wanted {
				return nil
			}
		}
		time.Sleep(time.Second)
	}
	return errors.New("new service did not become healthy")
}

// Данные авторизации и статистики не заменяются при обновлении или откате.
func installTransaction(j updateJob, stop, start func() error, health func(string) error, progress func(string)) error {
	hash, err := checksumFile(j.Candidate)
	if err != nil || hash != j.Checksum {
		return errors.New("staged binary checksum mismatch")
	}
	if err = copyUpdateFile(j.Executable, j.Previous, 0700); err != nil {
		return err
	}
	progress("installing")
	if err = stop(); err != nil {
		_ = start()
		return fmt.Errorf("cannot stop service: %w", err)
	}
	if err = copyUpdateFile(j.Candidate, j.Executable, 0700); err == nil {
		progress("restarting")
		err = start()
	}
	if err == nil {
		err = health(j.Target)
	}
	if err == nil {
		progress("done")
		return nil
	}
	progress("rollback")
	_ = stop()
	if restoreErr := copyUpdateFile(j.Previous, j.Executable, 0700); restoreErr != nil {
		return fmt.Errorf("update failed (%v); restoring binary failed: %w", err, restoreErr)
	}
	if startErr := start(); startErr != nil {
		return fmt.Errorf("previous binary restored but service start failed: %w", startErr)
	}
	if healthErr := health(j.PreviousVersion); healthErr != nil {
		return fmt.Errorf("previous binary restored; health check failed: %w", healthErr)
	}
	return fmt.Errorf("update failed; previous version restored: %w", err)
}

func applyUpdate(jobFile string) error {
	var j updateJob
	if err := readUpdateJSON(jobFile, &j); err != nil {
		return err
	}
	dir := filepath.Dir(filepath.Dir(jobFile))
	if !validJob(dir, jobFile, j) {
		return errors.New("invalid update job")
	}
	// Даём HTTP-ответу дойти до браузера до остановки старого сервиса.
	time.Sleep(time.Second)
	defer os.Remove(filepath.Join(dir, "pending.json"))
	err := installTransaction(j, func() error { return serviceCommand(j, "stop") }, func() error { return serviceCommand(j, "start") }, func(v string) error { return healthyVersion(j.Listen, v) }, func(phase string) { _ = setUpdateProgress(dir, phase, j.Target, "") })
	if err != nil {
		_ = setUpdateProgress(dir, "failed", j.Target, err.Error())
	}
	return err
}

// Вызывается init-скриптом: восстанавливает бинарник после прерванной установки.
func recoverUpdate(dir string) error {
	var pending updatePending
	if err := readUpdateJSON(filepath.Join(dir, "pending.json"), &pending); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	if activePending(dir) {
		return nil
	}
	var j updateJob
	if err := readUpdateJSON(pending.Job, &j); err != nil {
		return err
	}
	if !validJob(dir, pending.Job, j) {
		return errors.New("invalid interrupted update")
	}
	var status updateProgress
	if err := readUpdateJSON(filepath.Join(dir, "status.json"), &status); err != nil {
		return err
	}
	if status.Phase == "installing" || status.Phase == "restarting" || status.Phase == "rollback" {
		if err := copyUpdateFile(j.Previous, j.Executable, 0700); err != nil {
			return err
		}
		_ = setUpdateProgress(dir, "failed", j.Target, "Прерванное обновление: восстановлена предыдущая версия")
	} else if status.Phase != "done" && status.Phase != "failed" {
		_ = setUpdateProgress(dir, "failed", j.Target, "Обновление было прервано до установки")
	}
	return os.Remove(filepath.Join(dir, "pending.json"))
}

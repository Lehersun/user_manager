package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const defaultConfig = "/usr/local/etc/xray/config.json"

func main() {
	configPath := flag.String("config", defaultConfig, "Xray config path")
	flag.Parse()
	if flag.NArg() != 2 || flag.Arg(0) != "add" || strings.TrimSpace(flag.Arg(1)) == "" {
		fmt.Fprintln(os.Stderr, "usage: xray-users [-config path] add NAME")
		os.Exit(2)
	}

	config, err := os.ReadFile(*configPath)
	if err != nil {
		fatal(err)
	}
	id, err := newUUID()
	if err != nil {
		fatal(err)
	}
	updated, err := addClient(config, flag.Arg(1), id)
	if err != nil {
		fatal(err)
	}
	if err := replaceFile(*configPath, updated); err != nil {
		fatal(err)
	}
	if output, err := exec.Command("systemctl", "restart", "xray").CombinedOutput(); err != nil {
		fatal(fmt.Errorf("restart xray: %w: %s", err, strings.TrimSpace(string(output))))
	}
	fmt.Printf("added %s: %s\n", flag.Arg(1), id)
}

func addClient(data []byte, name, id string) ([]byte, error) {
	var config map[string]any
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	inbounds, ok := config["inbounds"].([]any)
	if !ok {
		return nil, errors.New("config has no inbounds array")
	}
	for _, rawInbound := range inbounds {
		inbound, ok := rawInbound.(map[string]any)
		if !ok || inbound["protocol"] != "vless" {
			continue
		}
		stream, ok := inbound["streamSettings"].(map[string]any)
		if !ok || stream["security"] != "reality" {
			continue
		}
		settings, ok := inbound["settings"].(map[string]any)
		if !ok {
			return nil, errors.New("VLESS Reality inbound has no settings")
		}
		clients, ok := settings["clients"].([]any)
		if !ok {
			return nil, errors.New("VLESS Reality inbound has no clients array")
		}
		for _, rawClient := range clients {
			if client, ok := rawClient.(map[string]any); ok && client["email"] == name {
				return nil, fmt.Errorf("client %q already exists", name)
			}
		}
		settings["clients"] = append(clients, map[string]any{"id": id, "flow": "xtls-rprx-vision", "email": name})
		return json.MarshalIndent(config, "", "  ")
	}
	return nil, errors.New("no VLESS Reality inbound found")
}

func newUUID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return hex.EncodeToString(b[:4]) + "-" + hex.EncodeToString(b[4:6]) + "-" + hex.EncodeToString(b[6:8]) + "-" + hex.EncodeToString(b[8:10]) + "-" + hex.EncodeToString(b[10:]), nil
}

func replaceFile(path string, data []byte) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".xray-config-")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(info.Mode().Perm()); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "xray-users:", err)
	os.Exit(1)
}

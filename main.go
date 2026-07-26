package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	defaultConfig   = "/usr/local/etc/xray/config.json"
	defaultServerIP = "178.83.123.153"
	xrayPath        = "/usr/local/bin/xray"
)

func main() {
	configPath := flag.String("config", defaultConfig, "Xray config path")
	serverIP := flag.String("server-ip", defaultServerIP, "public server IP for the connection URI")
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
	publicKey, err := realityPublicKey(updated)
	if err != nil {
		fatal(err)
	}
	uri, err := connectionString(updated, id, *serverIP, publicKey)
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
	fmt.Println(uri)
}

func addClient(data []byte, name, id string) ([]byte, error) {
	var config map[string]any
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	inbound, err := vlessRealityInbound(config)
	if err != nil {
		return nil, err
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

func connectionString(data []byte, id, serverIP, publicKey string) (string, error) {
	var config map[string]any
	if err := json.Unmarshal(data, &config); err != nil {
		return "", fmt.Errorf("parse config: %w", err)
	}
	inbound, err := vlessRealityInbound(config)
	if err != nil {
		return "", err
	}
	port, ok := inbound["port"].(float64)
	if !ok || port != math.Trunc(port) || port < 1 || port > 65535 {
		return "", errors.New("VLESS Reality inbound has an invalid port")
	}
	settings, ok := inbound["settings"].(map[string]any)
	if !ok {
		return "", errors.New("VLESS Reality inbound has no settings")
	}
	clients, ok := settings["clients"].([]any)
	if !ok {
		return "", errors.New("VLESS Reality inbound has no clients array")
	}
	for _, rawClient := range clients {
		client, ok := rawClient.(map[string]any)
		if !ok || client["id"] != id {
			continue
		}
		flow, ok := client["flow"].(string)
		if !ok || flow == "" {
			return "", errors.New("client has no flow")
		}
		email, ok := client["email"].(string)
		if !ok || email == "" {
			return "", errors.New("client has no email")
		}
		reality, err := realitySettings(inbound)
		if err != nil {
			return "", err
		}
		sni, err := firstString(reality, "serverNames")
		if err != nil {
			return "", err
		}
		shortID, err := firstString(reality, "shortIds")
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("vless://%s@%s:%s?encryption=none&flow=%s&security=reality&sni=%s&fp=chrome&pbk=%s&sid=%s&type=tcp&headerType=none#%s", id, serverIP, strconv.Itoa(int(port)), flow, sni, publicKey, shortID, email), nil
	}
	return "", fmt.Errorf("client %q not found", id)
}

func realityPublicKey(data []byte) (string, error) {
	var config map[string]any
	if err := json.Unmarshal(data, &config); err != nil {
		return "", fmt.Errorf("parse config: %w", err)
	}
	inbound, err := vlessRealityInbound(config)
	if err != nil {
		return "", err
	}
	reality, err := realitySettings(inbound)
	if err != nil {
		return "", err
	}
	privateKey, ok := reality["privateKey"].(string)
	if !ok || privateKey == "" {
		return "", errors.New("Reality private key is missing")
	}
	output, err := exec.Command(xrayPath, "x25519", "-i", privateKey).Output()
	if err != nil {
		return "", fmt.Errorf("derive Reality public key: %w", err)
	}
	return parsePublicKey(string(output))
}

func parsePublicKey(output string) (string, error) {
	for _, line := range strings.Split(string(output), "\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 && (strings.Contains(parts[0], "Password") || strings.Contains(parts[0], "PublicKey") || strings.Contains(parts[0], "Public key")) {
			return strings.TrimSpace(parts[1]), nil
		}
	}
	return "", errors.New("Xray did not return a Reality public key")
}

func vlessRealityInbound(config map[string]any) (map[string]any, error) {
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
		if ok && stream["security"] == "reality" {
			return inbound, nil
		}
	}
	return nil, errors.New("no VLESS Reality inbound found")
}

func firstString(values map[string]any, key string) (string, error) {
	items, ok := values[key].([]any)
	if !ok || len(items) == 0 {
		return "", fmt.Errorf("Reality %s is missing", key)
	}
	value, ok := items[0].(string)
	if !ok || value == "" {
		return "", fmt.Errorf("Reality %s is invalid", key)
	}
	return value, nil
}

func realitySettings(inbound map[string]any) (map[string]any, error) {
	stream, ok := inbound["streamSettings"].(map[string]any)
	if !ok {
		return nil, errors.New("VLESS Reality inbound has no stream settings")
	}
	reality, ok := stream["realitySettings"].(map[string]any)
	if !ok {
		return nil, errors.New("VLESS Reality inbound has no reality settings")
	}
	return reality, nil
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

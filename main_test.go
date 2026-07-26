package main

import (
	"encoding/json"
	"testing"
)

func TestAddClientAppendsVisionClient(t *testing.T) {
	input := []byte(`{
		"inbounds": [{
			"protocol": "vless",
			"settings": {"clients": []},
			"streamSettings": {"security": "reality"}
		}]
	}`)

	got, err := addClient(input, "alice", "11111111-2222-4333-8444-555555555555")
	if err != nil {
		t.Fatal(err)
	}

	var config struct {
		Inbounds []struct {
			Settings struct {
				Clients []struct {
					ID    string `json:"id"`
					Flow  string `json:"flow"`
					Email string `json:"email"`
				} `json:"clients"`
			} `json:"settings"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(got, &config); err != nil {
		t.Fatal(err)
	}
	client := config.Inbounds[0].Settings.Clients[0]
	if client.ID != "11111111-2222-4333-8444-555555555555" || client.Email != "alice" || client.Flow != "xtls-rprx-vision" {
		t.Fatalf("unexpected client: %+v", client)
	}
}

func TestAddClientRejectsDuplicateName(t *testing.T) {
	input := []byte(`{"inbounds":[{"protocol":"vless","settings":{"clients":[{"email":"alice"}]},"streamSettings":{"security":"reality"}}]}`)
	if _, err := addClient(input, "alice", "11111111-2222-4333-8444-555555555555"); err == nil {
		t.Fatal("expected duplicate name error")
	}
}

func TestConnectionStringUsesRealitySettings(t *testing.T) {
	config := []byte(`{
		"inbounds": [{
			"port": 27015,
			"protocol": "vless",
			"settings": {"clients": [{"id":"client-id","email":"alice","flow":"xtls-rprx-vision"}]},
			"streamSettings": {"security":"reality","realitySettings":{"privateKey":"private","shortIds":["short-id"],"serverNames":["www.cloudflare.com"]}}
		}]
	}`)

	got, err := connectionString(config, "client-id", "178.83.123.153", "public-key")
	if err != nil {
		t.Fatal(err)
	}
	want := "vless://client-id@178.83.123.153:27015?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.cloudflare.com&fp=chrome&pbk=public-key&sid=short-id&type=tcp&headerType=none#alice"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

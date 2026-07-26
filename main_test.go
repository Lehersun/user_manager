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

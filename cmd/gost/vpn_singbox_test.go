package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildSingBoxConfigForSocksUpstream(t *testing.T) {
	profile := &proxyProfile{
		Name: "test",
		Config: baseConfig{
			route: route{
				ChainNodes: stringList{"socks5://user:pass@example.com:1080"},
			},
		},
	}

	cfg, err := buildSingBoxConfig(profile)
	if err != nil {
		t.Fatal(err)
	}

	if len(cfg.Inbounds) != 1 {
		t.Fatalf("inbounds = %d, want 1", len(cfg.Inbounds))
	}
	if cfg.Inbounds[0].Type != "tun" {
		t.Fatalf("inbound type = %q, want tun", cfg.Inbounds[0].Type)
	}
	if cfg.Inbounds[0].InterfaceName != "gost-tun" {
		t.Fatalf("interface name = %q, want gost-tun", cfg.Inbounds[0].InterfaceName)
	}
	if !cfg.Inbounds[0].AutoRoute || !cfg.Inbounds[0].StrictRoute {
		t.Fatalf("auto_route/strict_route must be enabled")
	}
	if len(cfg.Route.Rules) != 3 {
		t.Fatalf("route rules = %d, want 3", len(cfg.Route.Rules))
	}
	if cfg.Route.Rules[1].Network != "udp" || cfg.Route.Rules[1].Port != 53 || cfg.Route.Rules[1].Action != "hijack-dns" {
		t.Fatalf("missing UDP/53 hijack rule: %+v", cfg.Route.Rules[1])
	}

	var outbound singBoxSocksOutbound
	if err := json.Unmarshal(cfg.Outbounds[0], &outbound); err != nil {
		t.Fatal(err)
	}
	if outbound.Type != "socks" || outbound.Version != "5" {
		t.Fatalf("unexpected outbound: %+v", outbound)
	}
	if outbound.Server != "example.com" || outbound.ServerPort != 1080 {
		t.Fatalf("unexpected server: %+v", outbound)
	}
	if outbound.Username != "user" || outbound.Password != "pass" {
		t.Fatalf("unexpected auth: %+v", outbound)
	}
}

func TestParseProxyURLDefaultsToSocks5(t *testing.T) {
	parsed, err := parseProxyURL("user:pass@example.com:1080")
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Scheme != "socks5" {
		t.Fatalf("scheme = %q, want socks5", parsed.Scheme)
	}
	if parsed.Username != "user" || parsed.Password != "pass" {
		t.Fatalf("unexpected auth: %+v", parsed)
	}
}

func TestProtectProfileStoreRoundTrip(t *testing.T) {
	store := &profileStore{
		Version: 1,
		Profiles: []proxyProfile{
			{
				Name: "secret",
				Config: baseConfig{
					route: route{
						ServeNodes: stringList{"http://127.0.0.1:8080"},
						ChainNodes: stringList{
							"socks5://user:pass@example.com:1080",
							"user:pass@example.net:1080",
						},
					},
				},
			},
		},
	}

	protected, err := protectProfileStore(store)
	if err != nil {
		t.Fatal(err)
	}
	saved := protected.Profiles[0].Config.route.ChainNodes[0]
	if strings.Contains(saved, "user:pass") {
		t.Fatalf("protected node still contains plaintext credentials: %s", saved)
	}
	savedWithoutScheme := protected.Profiles[0].Config.route.ChainNodes[1]
	if strings.Contains(savedWithoutScheme, "user:pass") {
		t.Fatalf("protected node without scheme still contains plaintext credentials: %s", savedWithoutScheme)
	}
	if err := unprotectProfileStore(protected); err != nil {
		t.Fatal(err)
	}
	for i, got := range protected.Profiles[0].Config.route.ChainNodes {
		want := store.Profiles[0].Config.route.ChainNodes[i]
		if got != want {
			t.Fatalf("round trip[%d] = %q, want %q", i, got, want)
		}
	}
}

package main

import (
	"testing"

	"github.com/haze518/mcpshield/pkg/config"
)

// ---------------------------------------------------------------------------
// buildAuth: fail-open prevention
// ---------------------------------------------------------------------------

func TestBuildAuthEmptyTypeReturnsError(t *testing.T) {
	_, err := buildAuth(config.AuthConfig{}, false)
	if err == nil {
		t.Fatal("expected error for empty auth.type, got nil")
	}
}

func TestBuildAuthNoneRequiresInsecureFlag(t *testing.T) {
	_, err := buildAuth(config.AuthConfig{Type: "none"}, false)
	if err == nil {
		t.Fatal("expected error for auth.type='none' without insecure_allow_anonymous: true")
	}
}

func TestBuildAuthNoneSucceedsWithInsecureFlag(t *testing.T) {
	a, err := buildAuth(config.AuthConfig{Type: "none"}, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if a == nil {
		t.Fatal("expected non-nil authenticator")
	}
}

func TestBuildAuthAPIKeyRequiresKeys(t *testing.T) {
	_, err := buildAuth(config.AuthConfig{Type: "api_key"}, false)
	if err == nil {
		t.Fatal("expected error for api_key with no keys")
	}
}

func TestBuildAuthAPIKeyMissingKeyHashReturnsError(t *testing.T) {
	_, err := buildAuth(config.AuthConfig{
		Type: "api_key",
		Keys: []config.AuthKeyConfig{
			{ID: "k1", KeyHash: "", ClientID: "team"},
		},
	}, false)
	if err == nil {
		t.Fatal("expected error for missing key_hash")
	}
}

func TestBuildAuthAPIKeyMissingClientIDReturnsError(t *testing.T) {
	_, err := buildAuth(config.AuthConfig{
		Type: "api_key",
		Keys: []config.AuthKeyConfig{
			{ID: "k1", KeyHash: "sha256:abc", ClientID: ""},
		},
	}, false)
	if err == nil {
		t.Fatal("expected error for missing client_id")
	}
}

func TestBuildAuthAPIKeySucceeds(t *testing.T) {
	a, err := buildAuth(config.AuthConfig{
		Type: "api_key",
		Keys: []config.AuthKeyConfig{
			{ID: "k1", KeyHash: "sha256:abc123", ClientID: "team"},
		},
	}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if a == nil {
		t.Fatal("expected non-nil authenticator")
	}
}

func TestBuildAuthUnknownTypeReturnsError(t *testing.T) {
	_, err := buildAuth(config.AuthConfig{Type: "jwt"}, false)
	if err == nil {
		t.Fatal("expected error for unknown auth type 'jwt'")
	}
}

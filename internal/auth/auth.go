package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
)

// Authenticator validates an incoming HTTP request and returns a client ID.
type Authenticator interface {
	Authenticate(r *http.Request) (string, error)
}

// ---- AllowAll -----------------------------------------------------------

type allowAllAuthenticator struct{}

// NewAllowAll returns an Authenticator that accepts every request.
// All requests share the synthetic client id "anonymous", so any session or
// per-client policy isolation is intentionally weak in this demo mode.
func NewAllowAll() Authenticator {
	return &allowAllAuthenticator{}
}

func (a *allowAllAuthenticator) Authenticate(_ *http.Request) (string, error) {
	return "anonymous", nil
}

// ---- APIKey -------------------------------------------------------------

type apiKeyAuthenticator struct {
	// Parallel slices: hashes[i] corresponds to clientIDs[i].
	// Stored as raw [32]byte arrays so subtle.ConstantTimeCompare can be used.
	hashes    [][sha256.Size]byte
	clientIDs []string
}

// NewAPIKeyAuthenticator creates an Authenticator that validates Bearer tokens
// against SHA-256 hashed keys.
//
// keys maps a key hash string (format "sha256:<lowercase-hex>") to a client ID.
// Use NewKeyHash to produce a compliant hash from a raw token.
func NewAPIKeyAuthenticator(keys map[string]string) Authenticator {
	a := &apiKeyAuthenticator{
		hashes:    make([][sha256.Size]byte, 0, len(keys)),
		clientIDs: make([]string, 0, len(keys)),
	}
	for hashStr, clientID := range keys {
		hex64, ok := strings.CutPrefix(hashStr, "sha256:")
		if !ok {
			continue
		}
		raw, err := hex.DecodeString(hex64)
		if err != nil || len(raw) != sha256.Size {
			continue
		}
		var arr [sha256.Size]byte
		copy(arr[:], raw)
		a.hashes = append(a.hashes, arr)
		a.clientIDs = append(a.clientIDs, clientID)
	}
	return a
}

// NewKeyHash returns the canonical "sha256:<hex>" representation of a raw token.
// Use this when populating config key_hash values.
func NewKeyHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (a *apiKeyAuthenticator) Authenticate(r *http.Request) (string, error) {
	header := r.Header.Get("Authorization")
	token, ok := strings.CutPrefix(header, "Bearer ")
	if !ok || token == "" {
		return "", errors.New("missing Bearer token")
	}
	sum := sha256.Sum256([]byte(token))
	// Constant-time scan: always compare all entries to prevent timing attacks.
	found := -1
	for i, h := range a.hashes {
		if subtle.ConstantTimeCompare(sum[:], h[:]) == 1 {
			found = i
		}
	}
	if found < 0 {
		return "", errors.New("invalid API key")
	}
	return a.clientIDs[found], nil
}

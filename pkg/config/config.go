package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server        ServerConfig        `yaml:"server"`
	Auth          AuthConfig          `yaml:"auth,omitempty"`
	PolicyFile    string              `yaml:"policy_file,omitempty"`
	Upstreams     []UpstreamConfig    `yaml:"upstreams,omitempty"`
	Observability ObservabilityConfig `yaml:"observability,omitempty"`
	Audit         AuditConfig         `yaml:"audit,omitempty"`
}

type ServerConfig struct {
	Listen                 string `yaml:"listen"`
	MaxRequestBytes        int64  `yaml:"max_request_bytes,omitempty"`
	InsecureAllowAnonymous bool   `yaml:"insecure_allow_anonymous,omitempty"`
	SessionTTL             string `yaml:"session_ttl,omitempty"`         // e.g. "30m"
	SessionMaxEntries      *int   `yaml:"session_max_entries,omitempty"` // e.g. 10000
}

// ---- auth config --------------------------------------------------------

// AuthConfig selects the authentication mode.
// Type "api_key": validate Bearer tokens via SHA-256 hash comparison.
// Type "none" (default): accept all requests (demo/dev mode).
type AuthConfig struct {
	Type string        `yaml:"type,omitempty"` // "api_key" | "none"
	Keys []AuthKeyConfig `yaml:"keys,omitempty"`
}

// AuthKeyConfig is one registered API key entry.
type AuthKeyConfig struct {
	ID       string `yaml:"id"`
	KeyHash  string `yaml:"key_hash"`  // "sha256:<lowercase-hex>"
	ClientID string `yaml:"client_id"`
}

// ---- upstream config ----------------------------------------------------

type UpstreamConfig struct {
	ID      string            `yaml:"id"`
	Prefix  string            `yaml:"prefix"`
	URL     string            `yaml:"url"`
	Headers map[string]string `yaml:"headers,omitempty"`
}

// ---- observability config -----------------------------------------------

type ObservabilityConfig struct {
	Metrics MetricsConfig `yaml:"metrics,omitempty"`
}

type MetricsConfig struct {
	Enabled         bool `yaml:"enabled"`
	IncludeClientID bool `yaml:"include_client_id,omitempty"`
}

// ---- audit config -------------------------------------------------------

type AuditConfig struct {
	Enabled   bool                 `yaml:"enabled"`
	Backend   string               `yaml:"backend,omitempty"` // "sqlite" | "stdout"
	SQLite    AuditSQLiteConfig    `yaml:"sqlite,omitempty"`
	Write     AuditWriteConfig     `yaml:"write,omitempty"`
	Retention AuditRetentionConfig `yaml:"retention,omitempty"`
	Integrity AuditIntegrityConfig `yaml:"integrity,omitempty"`
}

type AuditSQLiteConfig struct {
	Path        string `yaml:"path,omitempty"`
	WAL         bool   `yaml:"wal,omitempty"`
	BusyTimeout string `yaml:"busy_timeout,omitempty"` // e.g. "5s"
	// Synchronous sets PRAGMA synchronous. Defaults to FULL when WAL is enabled
	// and write_mode is fail_closed (most durable). Accepts NORMAL or FULL.
	Synchronous string `yaml:"synchronous,omitempty"`
}

type AuditWriteConfig struct {
	BatchMaxEvents int    `yaml:"batch_max_events,omitempty"`
	BatchMaxDelay  string `yaml:"batch_max_delay,omitempty"` // e.g. "100ms"
	ChannelSize    int    `yaml:"channel_size,omitempty"`
	Mode           string `yaml:"mode,omitempty"` // "drop" | "block" | "fail_closed"
}

type AuditRetentionConfig struct {
	MaxAge         string `yaml:"max_age,omitempty"`         // e.g. "90d"
	MaxSize        string `yaml:"max_size,omitempty"`        // e.g. "10GB"
	VacuumInterval string `yaml:"vacuum_interval,omitempty"` // e.g. "24h"
}

type AuditIntegrityConfig struct {
	HashChain     bool   `yaml:"hash_chain,omitempty"`
	HashAlgorithm string `yaml:"hash_algorithm,omitempty"` // "sha256"
}

// ---- loader -------------------------------------------------------------

// Load reads a config file, expands ${ENV_VAR} references throughout, and
// returns a validated Config.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("open config: %w", err)
	}

	// Expand ${ENV_VAR} (and $ENV_VAR) in the entire file before parsing.
	// This covers URLs, headers, paths, and any other string values.
	expanded := os.ExpandEnv(string(raw))

	var cfg Config
	if err := yaml.NewDecoder(strings.NewReader(expanded)).Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}
	if cfg.Server.Listen == "" {
		cfg.Server.Listen = ":8080"
	}
	if err := validateServer(cfg.Server); err != nil {
		return nil, err
	}
	if err := validateUpstreams(cfg.Upstreams); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func validateServer(server ServerConfig) error {
	if server.SessionTTL != "" {
		ttl, err := time.ParseDuration(server.SessionTTL)
		if err != nil {
			return fmt.Errorf("server.session_ttl: %w", err)
		}
		if ttl <= 0 {
			return fmt.Errorf("server.session_ttl must be > 0")
		}
	}
	if server.SessionMaxEntries != nil && *server.SessionMaxEntries <= 0 {
		return fmt.Errorf("server.session_max_entries must be > 0 when set")
	}
	return nil
}

func validateUpstreams(upstreams []UpstreamConfig) error {
	ids := make(map[string]struct{}, len(upstreams))
	prefixes := make(map[string]struct{}, len(upstreams))

	for i := range upstreams {
		u := &upstreams[i]
		if u.ID == "" {
			return fmt.Errorf("upstream[%d]: id is required", i)
		}
		if u.Prefix == "" {
			return fmt.Errorf("upstream %q: prefix is required", u.ID)
		}
		if u.URL == "" {
			return fmt.Errorf("upstream %q: url is required", u.ID)
		}
		if _, dup := ids[u.ID]; dup {
			return fmt.Errorf("upstream id %q is not unique", u.ID)
		}
		if _, dup := prefixes[u.Prefix]; dup {
			return fmt.Errorf("upstream prefix %q is not unique", u.Prefix)
		}
		ids[u.ID] = struct{}{}
		prefixes[u.Prefix] = struct{}{}
	}
	return nil
}

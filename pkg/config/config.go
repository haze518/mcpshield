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
	MaxRequestBytes        *int64 `yaml:"max_request_bytes,omitempty"`
	InsecureAllowAnonymous bool   `yaml:"insecure_allow_anonymous,omitempty"`
	RequestTimeout         string `yaml:"request_timeout,omitempty"` // e.g. "60s"
	ReadTimeout            string `yaml:"read_timeout,omitempty"`    // e.g. "30s"
	WriteTimeout           string `yaml:"write_timeout,omitempty"`   // e.g. "30s"
	IdleTimeout            string `yaml:"idle_timeout,omitempty"`    // e.g. "120s"
	WarmupTimeout          string `yaml:"warmup_timeout,omitempty"`  // e.g. "30s"
	SessionTTL             string `yaml:"session_ttl,omitempty"`         // e.g. "30m"
	SessionMaxEntries      *int   `yaml:"session_max_entries,omitempty"` // e.g. 10000
	WarmupRetryInterval    string `yaml:"warmup_retry_interval,omitempty"` // e.g. "5s"
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
	ID               string            `yaml:"id"`
	Prefix           string            `yaml:"prefix"`
	URL              string            `yaml:"url"`
	Headers          map[string]string `yaml:"headers,omitempty"`
	RequestTimeout   string            `yaml:"request_timeout,omitempty"`   // e.g. "30s"
	MaxResponseBytes *int64            `yaml:"max_response_bytes,omitempty"`
	ToolsCacheTTL    string            `yaml:"tools_cache_ttl,omitempty"`   // e.g. "10s"
	RefreshTimeout   string            `yaml:"refresh_timeout,omitempty"`   // e.g. "30s"
}

type RuntimeConfig struct {
	Server          ServerRuntimeConfig
	Upstreams       []UpstreamRuntimeConfig
	UpstreamManager UpstreamManagerRuntimeConfig
}

type ServerRuntimeConfig struct {
	Listen              string
	MaxRequestBytes     int64
	RequestTimeout      time.Duration
	ReadTimeout         time.Duration
	WriteTimeout        time.Duration
	IdleTimeout         time.Duration
	WarmupTimeout       time.Duration
	WarmupRetryInterval time.Duration
	SessionTTL          time.Duration
	SessionMaxEntries   int
}

type UpstreamRuntimeConfig struct {
	ID               string
	Prefix           string
	URL              string
	Headers          map[string]string
	RequestTimeout   time.Duration
	MaxResponseBytes int64
	ToolsCacheTTL    time.Duration
	RefreshTimeout   time.Duration
}

type UpstreamManagerRuntimeConfig struct {
	ToolsCacheTTL  time.Duration
	RefreshTimeout time.Duration
}

const (
	defaultListen                 = ":8080"
	defaultServerRequestTimeout   = 60 * time.Second
	defaultServerReadTimeout      = 30 * time.Second
	defaultServerWriteTimeout     = 30 * time.Second
	defaultServerIdleTimeout      = 120 * time.Second
	defaultServerWarmupTimeout    = 30 * time.Second
	defaultWarmupRetryInterval    = 5 * time.Second
	defaultServerMaxRequestBytes  = 1 << 20
	defaultSessionTTL             = 30 * time.Minute
	defaultSessionMaxEntries      = 10_000
	defaultUpstreamRequestTimeout = 30 * time.Second
	defaultUpstreamMaxRespBytes   = 4 << 20
	defaultUpstreamToolsCacheTTL  = 10 * time.Second
	defaultUpstreamRefreshTimeout = 30 * time.Second
)

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
// returns the parsed raw config.
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
	return &cfg, nil
}

// BuildRuntime validates and normalizes the raw config into typed runtime
// settings with defaults applied.
func (c *Config) BuildRuntime() (RuntimeConfig, error) {
	return buildRuntime(*c)
}

func buildRuntime(cfg Config) (RuntimeConfig, error) {
	server, err := buildServerRuntime(cfg.Server)
	if err != nil {
		return RuntimeConfig{}, err
	}
	upstreams, manager, err := buildUpstreamRuntime(cfg.Upstreams)
	if err != nil {
		return RuntimeConfig{}, err
	}
	return RuntimeConfig{
		Server:          server,
		Upstreams:       upstreams,
		UpstreamManager: manager,
	}, nil
}

func buildServerRuntime(server ServerConfig) (ServerRuntimeConfig, error) {
	listen := server.Listen
	if listen == "" {
		listen = defaultListen
	}

	requestTimeout, err := parseDurationWithDefault("server.request_timeout", server.RequestTimeout, defaultServerRequestTimeout)
	if err != nil {
		return ServerRuntimeConfig{}, err
	}
	readTimeout, err := parseDurationWithDefault("server.read_timeout", server.ReadTimeout, defaultServerReadTimeout)
	if err != nil {
		return ServerRuntimeConfig{}, err
	}
	writeTimeout, err := parseDurationWithDefault("server.write_timeout", server.WriteTimeout, defaultServerWriteTimeout)
	if err != nil {
		return ServerRuntimeConfig{}, err
	}
	idleTimeout, err := parseDurationWithDefault("server.idle_timeout", server.IdleTimeout, defaultServerIdleTimeout)
	if err != nil {
		return ServerRuntimeConfig{}, err
	}
	warmupTimeout, err := parseDurationWithDefault("server.warmup_timeout", server.WarmupTimeout, defaultServerWarmupTimeout)
	if err != nil {
		return ServerRuntimeConfig{}, err
	}
	warmupRetryInterval, err := parseDurationWithDefault("server.warmup_retry_interval", server.WarmupRetryInterval, defaultWarmupRetryInterval)
	if err != nil {
		return ServerRuntimeConfig{}, err
	}
	sessionTTL, err := parseDurationWithDefault("server.session_ttl", server.SessionTTL, defaultSessionTTL)
	if err != nil {
		return ServerRuntimeConfig{}, err
	}

	maxRequestBytes, err := parseInt64WithDefault("server.max_request_bytes", server.MaxRequestBytes, defaultServerMaxRequestBytes)
	if err != nil {
		return ServerRuntimeConfig{}, err
	}
	sessionMaxEntries, err := parseIntWithDefault("server.session_max_entries", server.SessionMaxEntries, defaultSessionMaxEntries)
	if err != nil {
		return ServerRuntimeConfig{}, err
	}

	return ServerRuntimeConfig{
		Listen:              listen,
		MaxRequestBytes:     maxRequestBytes,
		RequestTimeout:      requestTimeout,
		ReadTimeout:         readTimeout,
		WriteTimeout:        writeTimeout,
		IdleTimeout:         idleTimeout,
		WarmupTimeout:       warmupTimeout,
		WarmupRetryInterval: warmupRetryInterval,
		SessionTTL:          sessionTTL,
		SessionMaxEntries:   sessionMaxEntries,
	}, nil
}

func buildUpstreamRuntime(upstreams []UpstreamConfig) ([]UpstreamRuntimeConfig, UpstreamManagerRuntimeConfig, error) {
	ids := make(map[string]struct{}, len(upstreams))
	prefixes := make(map[string]struct{}, len(upstreams))
	runtimeUpstreams := make([]UpstreamRuntimeConfig, 0, len(upstreams))

	manager := UpstreamManagerRuntimeConfig{}
	managerSet := false

	for i := range upstreams {
		u := &upstreams[i]
		if u.ID == "" {
			return nil, UpstreamManagerRuntimeConfig{}, fmt.Errorf("upstream[%d]: id is required", i)
		}
		if u.Prefix == "" {
			return nil, UpstreamManagerRuntimeConfig{}, fmt.Errorf("upstream %q: prefix is required", u.ID)
		}
		if u.URL == "" {
			return nil, UpstreamManagerRuntimeConfig{}, fmt.Errorf("upstream %q: url is required", u.ID)
		}
		if _, dup := ids[u.ID]; dup {
			return nil, UpstreamManagerRuntimeConfig{}, fmt.Errorf("upstream id %q is not unique", u.ID)
		}
		if _, dup := prefixes[u.Prefix]; dup {
			return nil, UpstreamManagerRuntimeConfig{}, fmt.Errorf("upstream prefix %q is not unique", u.Prefix)
		}
		ids[u.ID] = struct{}{}
		prefixes[u.Prefix] = struct{}{}

		requestTimeout, err := parseDurationWithDefault(fmt.Sprintf("upstream %q request_timeout", u.ID), u.RequestTimeout, defaultUpstreamRequestTimeout)
		if err != nil {
			return nil, UpstreamManagerRuntimeConfig{}, err
		}
		maxResponseBytes, err := parseInt64WithDefault(fmt.Sprintf("upstream %q max_response_bytes", u.ID), u.MaxResponseBytes, defaultUpstreamMaxRespBytes)
		if err != nil {
			return nil, UpstreamManagerRuntimeConfig{}, err
		}
		cacheTTL, err := parseDurationWithDefault(fmt.Sprintf("upstream %q tools_cache_ttl", u.ID), u.ToolsCacheTTL, defaultUpstreamToolsCacheTTL)
		if err != nil {
			return nil, UpstreamManagerRuntimeConfig{}, err
		}
		refreshTimeout, err := parseDurationWithDefault(fmt.Sprintf("upstream %q refresh_timeout", u.ID), u.RefreshTimeout, defaultUpstreamRefreshTimeout)
		if err != nil {
			return nil, UpstreamManagerRuntimeConfig{}, err
		}

		// Tool discovery cache and background refresh are shared across all
		// upstreams, so the effective manager settings use the smallest
		// configured values.
		if !managerSet {
			manager.ToolsCacheTTL = cacheTTL
			manager.RefreshTimeout = refreshTimeout
			managerSet = true
		} else {
			manager.ToolsCacheTTL = minDuration(manager.ToolsCacheTTL, cacheTTL)
			manager.RefreshTimeout = minDuration(manager.RefreshTimeout, refreshTimeout)
		}

		runtimeUpstreams = append(runtimeUpstreams, UpstreamRuntimeConfig{
			ID:               u.ID,
			Prefix:           u.Prefix,
			URL:              u.URL,
			Headers:          u.Headers,
			RequestTimeout:   requestTimeout,
			MaxResponseBytes: maxResponseBytes,
			ToolsCacheTTL:    cacheTTL,
			RefreshTimeout:   refreshTimeout,
		})
	}

	if !managerSet {
		manager = UpstreamManagerRuntimeConfig{
			ToolsCacheTTL:  defaultUpstreamToolsCacheTTL,
			RefreshTimeout: defaultUpstreamRefreshTimeout,
		}
	}
	return runtimeUpstreams, manager, nil
}

func parseDurationWithDefault(field, raw string, def time.Duration) (time.Duration, error) {
	if raw == "" {
		return def, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", field, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("%s must be > 0", field)
	}
	return d, nil
}

func parseIntWithDefault(field string, raw *int, def int) (int, error) {
	if raw == nil {
		return def, nil
	}
	if *raw <= 0 {
		return 0, fmt.Errorf("%s must be > 0 when set", field)
	}
	return *raw, nil
}

func parseInt64WithDefault(field string, raw *int64, def int64) (int64, error) {
	if raw == nil {
		return def, nil
	}
	if *raw <= 0 {
		return 0, fmt.Errorf("%s must be > 0 when set", field)
	}
	return *raw, nil
}

func minDuration(a, b time.Duration) time.Duration {
	if b < a {
		return b
	}
	return a
}

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/haze518/mcpshield/internal/audit"
	"github.com/haze518/mcpshield/internal/auth"
	"github.com/haze518/mcpshield/internal/gateway"
	"github.com/haze518/mcpshield/internal/observability"
	"github.com/haze518/mcpshield/internal/policy"
	"github.com/haze518/mcpshield/internal/transport"
	"github.com/haze518/mcpshield/internal/upstream"
	"github.com/haze518/mcpshield/pkg/config"
)

const warmupRetryInterval = 5 * time.Second

func main() {
	if err := rootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "mcpshield",
		Short: "MCPShield — MCP protocol gateway",
	}
	root.AddCommand(serveCmd())
	root.AddCommand(validateUpstreamCmd())
	root.AddCommand(validatePolicyCmd())
	root.AddCommand(auditCmd())
	root.AddCommand(replayCmd())
	return root
}

// ---- serve --------------------------------------------------------------

func serveCmd() *cobra.Command {
	var cfgPath string

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the MCP gateway",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runServe(cmd.Context(), cfgPath)
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", "config.yaml", "path to config file")
	return cmd
}

func buildEntries(cfg *config.Config) []upstream.Entry {
	entries := make([]upstream.Entry, 0, len(cfg.Upstreams))
	for _, u := range cfg.Upstreams {
		entries = append(entries, upstream.Entry{
			ID:     u.ID,
			Prefix: u.Prefix,
			Client: transport.NewMCPHTTPClient(u.ID, u.URL, u.Headers),
		})
	}
	return entries
}

// buildAuth constructs the Authenticator from config.
// Type "api_key": requires Keys list; validates Bearer tokens via SHA-256.
// Type "none": allow-all — only permitted when insecureAllowAnonymous is true.
// Empty type: always rejected to prevent accidental fail-open deployments.
func buildAuth(cfg config.AuthConfig, insecureAllowAnonymous bool) (auth.Authenticator, error) {
	switch cfg.Type {
	case "api_key":
		if len(cfg.Keys) == 0 {
			return nil, fmt.Errorf("auth type 'api_key' requires at least one key entry")
		}
		keys := make(map[string]string, len(cfg.Keys))
		for _, k := range cfg.Keys {
			if k.KeyHash == "" {
				return nil, fmt.Errorf("auth key %q: key_hash is required", k.ID)
			}
			if k.ClientID == "" {
				return nil, fmt.Errorf("auth key %q: client_id is required", k.ID)
			}
			keys[k.KeyHash] = k.ClientID
		}
		return auth.NewAPIKeyAuthenticator(keys), nil
	case "none":
		if !insecureAllowAnonymous {
			return nil, fmt.Errorf("auth.type 'none' requires server.insecure_allow_anonymous: true")
		}
		return auth.NewAllowAll(), nil
	default: // includes ""
		return nil, fmt.Errorf("auth.type is required; set to 'api_key' or 'none' (with server.insecure_allow_anonymous: true)")
	}
}

func runServe(ctx context.Context, cfgPath string) error {
	log := observability.NewLogger()

	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// Build authenticator.
	authenticator, err := buildAuth(cfg.Auth, cfg.Server.InsecureAllowAnonymous)
	if err != nil {
		return fmt.Errorf("init auth: %w", err)
	}
	if cfg.Auth.Type == "none" {
		log.Warn("auth type is 'none'; all requests are accepted (demo mode)")
	}

	// Load policy — fail fast if policy_file is set but invalid.
	var policyEngine *policy.YAMLPolicyEngine
	if cfg.PolicyFile != "" {
		compiled, err := policy.LoadFromFile(cfg.PolicyFile)
		if err != nil {
			return fmt.Errorf("load policy: %w", err)
		}
		policyEngine = policy.NewYAMLPolicyEngine(compiled)
		log.Info("policy loaded", slog.String("file", cfg.PolicyFile))
	} else {
		// No policy file → deny-all (fail-closed).
		policyEngine = policy.NewYAMLPolicyEngine(nil)
		log.Warn("no policy_file configured; running in deny-all mode")
	}

	// Build audit logger.
	auditLog, err := audit.NewLogger(cfg.Audit)
	if err != nil {
		return fmt.Errorf("init audit: %w", err)
	}
	defer auditLog.Close()
	if cfg.Audit.Enabled {
		log.Info("audit enabled", slog.String("backend", cfg.Audit.Backend))
	}

	// Bind server lifecycle to OS signals before building the upstream manager
	// so that background refresh goroutines are tied to the signal-derived
	// context and stop cleanly on SIGINT/SIGTERM.
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	entries := buildEntries(cfg)
	mgr := upstream.NewManager(ctx, entries)

	gw := gateway.New(
		authenticator,
		policyEngine,
		mgr,
		auditLog,
	)

	sessionTTL := 30 * time.Minute
	if cfg.Server.SessionTTL != "" {
		ttl, err := time.ParseDuration(cfg.Server.SessionTTL)
		if err != nil {
			return fmt.Errorf("parse server.session_ttl: %w", err)
		}
		sessionTTL = ttl
	}
	sessionMaxEntries := 10_000
	if cfg.Server.SessionMaxEntries != nil {
		sessionMaxEntries = *cfg.Server.SessionMaxEntries
	}
	gw.SetSessionConfig(sessionTTL, sessionMaxEntries)
	retryInterval := warmupRetryInterval
	if cfg.Server.WarmupRetryInterval != "" {
		d, err := time.ParseDuration(cfg.Server.WarmupRetryInterval)
		if err != nil {
			return fmt.Errorf("parse server.warmup_retry_interval: %w", err)
		}
		retryInterval = d
	}
	log.Info("session cache configured",
		slog.Duration("ttl", sessionTTL),
		slog.Int("max_entries", sessionMaxEntries))
	log.Info("HTTP session cache is in-memory; process restart requires clients to re-initialize")

	if cfg.Server.MaxRequestBytes > 0 {
		gw.SetMaxRequestBytes(cfg.Server.MaxRequestBytes)
		log.Info("request body limit", slog.Int64("bytes", cfg.Server.MaxRequestBytes))
	}

	if cfg.Observability.Metrics.Enabled {
		reg := observability.NewRegistry(cfg.Observability.Metrics.IncludeClientID)
		gw.SetMetrics(reg)
		// Wire audit drop/fail counters into Prometheus if the logger supports it.
		if sal, ok := auditLog.(*audit.SQLiteAuditLogger); ok {
			sal.SetMetrics(reg)
		}
		// Wire upstream protocol-error, response-too-large, and refresh-fail counters.
		for _, e := range entries {
			if c, ok := e.Client.(*transport.MCPHTTPClient); ok {
				c.SetMetrics(reg)
			}
		}
		mgr.SetMetrics(reg)
		log.Info("metrics enabled", slog.String("path", "/metrics"))
	}

	srv := transport.NewHTTPServer(cfg.Server.Listen, gw)

	// SIGHUP: hot-reload policy without restart.
	sighupCh := make(chan os.Signal, 1)
	signal.Notify(sighupCh, syscall.SIGHUP)
	go func() {
		for range sighupCh {
			if cfg.PolicyFile == "" {
				log.Warn("SIGHUP received but policy_file is not configured")
				continue
			}
			compiled, err := policy.LoadFromFile(cfg.PolicyFile)
			if err != nil {
				log.Error("policy reload failed; keeping previous policy",
					slog.String("file", cfg.PolicyFile),
					slog.String("err", err.Error()))
				continue
			}
			policyEngine.Swap(compiled)
			log.Info("policy reloaded", slog.String("file", cfg.PolicyFile))
		}
	}()

	errCh := make(chan error, 1)
	go func() {
		log.Info("server starting", slog.String("addr", cfg.Server.Listen))
		if err := srv.ListenAndServe(); err != nil {
			errCh <- err
		}
	}()

	go runWarmupUntilReady(ctx, mgr, retryInterval, log)

	select {
	case <-ctx.Done():
		log.Info("shutting down")
		signal.Stop(sighupCh)
		return srv.Shutdown(context.Background())
	case err := <-errCh:
		return fmt.Errorf("server error: %w", err)
	}
}

func runWarmupUntilReady(ctx context.Context, mgr interface {
	Warmup(context.Context) error
	Ready() bool
}, retryInterval time.Duration, log *slog.Logger) {
	if retryInterval <= 0 {
		retryInterval = warmupRetryInterval
	}
	if log == nil {
		log = slog.Default()
	}
	for {
		if mgr.Ready() {
			return
		}
		if err := mgr.Warmup(ctx); err == nil {
			log.Info("startup warmup completed")
			return
		} else if ctx.Err() == nil {
			log.Warn("startup warmup failed; will retry",
				slog.String("error", err.Error()),
				slog.Duration("retry_in", retryInterval))
		}

		timer := time.NewTimer(retryInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

// ---- validate-upstream --------------------------------------------------

func validateUpstreamCmd() *cobra.Command {
	var cfgPath, upstreamID string

	cmd := &cobra.Command{
		Use:   "validate-upstream",
		Short: "Validate connectivity to an upstream MCP server",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runValidateUpstream(cmd.Context(), cfgPath, upstreamID)
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", "config.yaml", "path to config file")
	cmd.Flags().StringVar(&upstreamID, "upstream", "", "upstream id to validate")
	_ = cmd.MarkFlagRequired("upstream")
	return cmd
}

func runValidateUpstream(ctx context.Context, cfgPath, upstreamID string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	var found *config.UpstreamConfig
	for i := range cfg.Upstreams {
		if cfg.Upstreams[i].ID == upstreamID {
			found = &cfg.Upstreams[i]
			break
		}
	}
	if found == nil {
		return fmt.Errorf("upstream %q not found in config", upstreamID)
	}

	mgr := upstream.NewManager(ctx, []upstream.Entry{
		{
			ID:     found.ID,
			Prefix: found.Prefix,
			Client: transport.NewMCPHTTPClient(found.ID, found.URL, found.Headers),
		},
	})

	if err := mgr.Warmup(ctx); err != nil {
		return fmt.Errorf("warmup failed: %w", err)
	}
	tools, err := mgr.ToolsList(ctx)
	if err != nil {
		return fmt.Errorf("tools/list failed: %w", err)
	}

	fmt.Printf("upstream %q OK: %d tool(s)\n", upstreamID, len(tools))
	return nil
}

// ---- validate-policy ----------------------------------------------------

func validatePolicyCmd() *cobra.Command {
	var policyFile string

	cmd := &cobra.Command{
		Use:   "validate-policy",
		Short: "Validate a policy YAML file",
		RunE: func(_ *cobra.Command, _ []string) error {
			return runValidatePolicy(policyFile)
		},
	}
	cmd.Flags().StringVar(&policyFile, "file", "", "path to policy YAML file")
	_ = cmd.MarkFlagRequired("file")
	return cmd
}

func runValidatePolicy(path string) error {
	if _, err := policy.LoadFromFile(path); err != nil {
		return fmt.Errorf("policy invalid: %w", err)
	}
	fmt.Println("policy OK")
	return nil
}

// ---- audit sub-commands -------------------------------------------------

func auditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Audit log management",
	}
	cmd.AddCommand(auditVerifyCmd())
	cmd.AddCommand(auditExportCmd())
	return cmd
}

func auditVerifyCmd() *cobra.Command {
	var dbPath string
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify audit log hash-chain integrity",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runAuditVerify(cmd.Context(), dbPath)
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "", "path to audit.db")
	_ = cmd.MarkFlagRequired("db")
	return cmd
}

func runAuditVerify(ctx context.Context, dbPath string) error {
	store, err := audit.NewSQLiteStore(config.AuditSQLiteConfig{Path: dbPath})
	if err != nil {
		return fmt.Errorf("open audit db: %w", err)
	}
	defer store.Close()

	if err := audit.VerifyChain(ctx, store); err != nil {
		return fmt.Errorf("chain verification FAILED: %w", err)
	}
	fmt.Println("chain OK")
	return nil
}

func auditExportCmd() *cobra.Command {
	var dbPath, since, format string
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export audit log as JSON Lines",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runAuditExport(cmd.Context(), dbPath, since, format)
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "", "path to audit.db")
	cmd.Flags().StringVar(&since, "since", "", "export events on/after this RFC3339 timestamp (optional)")
	cmd.Flags().StringVar(&format, "format", "jsonl", "output format (jsonl)")
	_ = cmd.MarkFlagRequired("db")
	return cmd
}

func runAuditExport(ctx context.Context, dbPath, since, _ string) error {
	store, err := audit.NewSQLiteStore(config.AuditSQLiteConfig{Path: dbPath})
	if err != nil {
		return fmt.Errorf("open audit db: %w", err)
	}
	defer store.Close()

	var sinceTime time.Time
	if since != "" {
		t, err := time.Parse(time.RFC3339, since)
		if err != nil {
			return fmt.Errorf("invalid --since %q: %w", since, err)
		}
		sinceTime = t
	}

	return audit.ExportJSONL(ctx, store, sinceTime, os.Stdout)
}

// ---- replay -------------------------------------------------------------

func replayCmd() *cobra.Command {
	var dbPath, sessionID, mode, policyFile string
	cmd := &cobra.Command{
		Use:   "replay",
		Short: "Replay recorded session events",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runReplay(cmd.Context(), dbPath, sessionID, mode, policyFile)
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "", "path to audit.db")
	cmd.Flags().StringVar(&sessionID, "session", "", "session ID to replay")
	cmd.Flags().StringVar(&mode, "mode", "read-only", "read-only|policy-check")
	cmd.Flags().StringVar(&policyFile, "policy", "", "policy YAML file (required for policy-check)")
	_ = cmd.MarkFlagRequired("db")
	_ = cmd.MarkFlagRequired("session")
	return cmd
}

func runReplay(ctx context.Context, dbPath, sessionID, mode, policyFile string) error {
	return runReplayTo(ctx, dbPath, sessionID, mode, policyFile, os.Stdout)
}

func runReplayTo(ctx context.Context, dbPath, sessionID, mode, policyFile string, w io.Writer) error {
	store, err := audit.NewSQLiteStore(config.AuditSQLiteConfig{Path: dbPath})
	if err != nil {
		return fmt.Errorf("open audit db: %w", err)
	}
	defer store.Close()

	switch mode {
	case "read-only":
		return audit.ReplayReadOnly(ctx, store, sessionID, w)
	case "policy-check":
		if policyFile == "" {
			return errors.New("--policy is required for policy-check mode")
		}
		compiled, err := policy.LoadFromFile(policyFile)
		if err != nil {
			return fmt.Errorf("load policy: %w", err)
		}
		eng := policy.NewYAMLPolicyEngine(compiled)
		return audit.ReplayPolicyCheck(ctx, store, sessionID, eng, w)
	default:
		return fmt.Errorf("unknown --mode %q (want read-only or policy-check)", mode)
	}
}

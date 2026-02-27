package observability

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Registry wraps the official Prometheus counters for MCPShield.
// It is safe for concurrent use. The public Inc* methods are the only
// call sites — gateway.go and main.go require no changes.
//
// Registry satisfies audit.AuditMetrics via IncAuditDropped and IncAuditWriteFail.
// Registry satisfies transport.UpstreamMetrics via IncUpstreamProtocolError and
// IncUpstreamResponseTooLarge.
// Registry satisfies upstream.ManagerMetrics via IncToolsRefreshFail.
type Registry struct {
	reg                      *prometheus.Registry
	requests                 *prometheus.CounterVec
	rateLimitHits            *prometheus.CounterVec
	policyDenies             *prometheus.CounterVec
	auditDropped             *prometheus.CounterVec
	auditWriteFail           *prometheus.CounterVec
	upstreamProtocolErrors   *prometheus.CounterVec
	upstreamResponseTooLarge *prometheus.CounterVec
	toolsRefreshFail         *prometheus.CounterVec
	includeClientID          bool
}

// NewRegistry creates a metrics registry backed by the official Prometheus
// client. When includeClientID is true, rate-limit-hit metrics include a
// client_id label.
func NewRegistry(includeClientID bool) *Registry {
	reg := prometheus.NewRegistry()

	requests := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "mcpshield_requests_total",
			Help: "Total MCP requests processed.",
		},
		[]string{"method", "tool", "decision"},
	)

	rateLimitLabels := []string{"tool"}
	if includeClientID {
		rateLimitLabels = append(rateLimitLabels, "client_id")
	}
	rateLimitHits := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "mcpshield_rate_limit_hits_total",
			Help: "Total rate limit hits.",
		},
		rateLimitLabels,
	)

	policyDenies := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "mcpshield_policy_denies_total",
			Help: "Total policy deny decisions.",
		},
		[]string{"rule"},
	)

	auditDropped := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "mcpshield_audit_dropped_total",
			Help: "Total audit events dropped (queue full or DB write failure).",
		},
		[]string{"backend"},
	)

	auditWriteFail := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "mcpshield_audit_write_fail_total",
			Help: "Total audit batch write failures (DB errors).",
		},
		[]string{"backend"},
	)

	upstreamProtocolErrors := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "mcpshield_upstream_protocol_errors_total",
			Help: "Total upstream responses failing JSON-RPC 2.0 protocol validation.",
		},
		[]string{"upstream_id"},
	)

	upstreamResponseTooLarge := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "mcpshield_upstream_response_too_large_total",
			Help: "Total upstream responses exceeding the configured size limit.",
		},
		[]string{"upstream_id"},
	)

	toolsRefreshFail := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "mcpshield_tools_refresh_fail_total",
			Help: "Total upstream tools/list cache refresh failures.",
		},
		[]string{"upstream_id"},
	)

	reg.MustRegister(
		requests, rateLimitHits, policyDenies,
		auditDropped, auditWriteFail,
		upstreamProtocolErrors, upstreamResponseTooLarge,
		toolsRefreshFail,
	)

	return &Registry{
		reg:                      reg,
		requests:                 requests,
		rateLimitHits:            rateLimitHits,
		policyDenies:             policyDenies,
		auditDropped:             auditDropped,
		auditWriteFail:           auditWriteFail,
		upstreamProtocolErrors:   upstreamProtocolErrors,
		upstreamResponseTooLarge: upstreamResponseTooLarge,
		toolsRefreshFail:         toolsRefreshFail,
		includeClientID:          includeClientID,
	}
}

// IncRequest increments mcpshield_requests_total{method, tool, decision}.
func (r *Registry) IncRequest(method, tool, decision string) {
	r.requests.WithLabelValues(method, tool, decision).Inc()
}

// IncRateLimitHit increments mcpshield_rate_limit_hits_total{tool[, client_id]}.
func (r *Registry) IncRateLimitHit(tool, clientID string) {
	if r.includeClientID {
		r.rateLimitHits.WithLabelValues(tool, clientID).Inc()
	} else {
		r.rateLimitHits.WithLabelValues(tool).Inc()
	}
}

// IncPolicyDeny increments mcpshield_policy_denies_total{rule}.
func (r *Registry) IncPolicyDeny(rule string) {
	r.policyDenies.WithLabelValues(rule).Inc()
}

// IncAuditDropped increments mcpshield_audit_dropped_total{backend}.
func (r *Registry) IncAuditDropped(backend string) {
	r.auditDropped.WithLabelValues(backend).Inc()
}

// IncAuditWriteFail increments mcpshield_audit_write_fail_total{backend}.
func (r *Registry) IncAuditWriteFail(backend string) {
	r.auditWriteFail.WithLabelValues(backend).Inc()
}

// IncUpstreamProtocolError increments mcpshield_upstream_protocol_errors_total{upstream_id}.
func (r *Registry) IncUpstreamProtocolError(upstreamID string) {
	r.upstreamProtocolErrors.WithLabelValues(upstreamID).Inc()
}

// IncUpstreamResponseTooLarge increments mcpshield_upstream_response_too_large_total{upstream_id}.
func (r *Registry) IncUpstreamResponseTooLarge(upstreamID string) {
	r.upstreamResponseTooLarge.WithLabelValues(upstreamID).Inc()
}

// IncToolsRefreshFail increments mcpshield_tools_refresh_fail_total{upstream_id}.
func (r *Registry) IncToolsRefreshFail(upstreamID string) {
	r.toolsRefreshFail.WithLabelValues(upstreamID).Inc()
}

// Handler returns an http.Handler that serves metrics in Prometheus text format.
func (r *Registry) Handler() http.Handler {
	return promhttp.HandlerFor(r.reg, promhttp.HandlerOpts{})
}

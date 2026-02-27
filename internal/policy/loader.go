package policy

import (
	"bytes"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/haze518/mcpshield/internal/mcp"
)

// ---- raw YAML structs (unexported) --------------------------------------

type policyFile struct {
	Version  string                   `yaml:"version"`
	Defaults defaultsConfig           `yaml:"defaults"`
	Toolsets map[string]toolsetConfig `yaml:"toolsets,omitempty"`
	Rules    []ruleConfig             `yaml:"rules,omitempty"`
}

type defaultsConfig struct {
	Action string `yaml:"action"`
}

type toolsetConfig struct {
	Tools []string `yaml:"tools"`
}

type ruleConfig struct {
	Name      string                  `yaml:"name"`
	Action    string                  `yaml:"action"`
	Tools     []string                `yaml:"tools,omitempty"`
	Toolset   string                  `yaml:"toolset,omitempty"`
	Args      map[string]ArgValidator `yaml:"args,omitempty"`
	Reason    string                  `yaml:"reason,omitempty"`
	RateLimit *rateLimitConfig        `yaml:"rate_limit,omitempty"`
}

type rateLimitConfig struct {
	Max    int    `yaml:"max"`
	Window string `yaml:"window"`
	Per    string `yaml:"per,omitempty"` // "global" (default) | "client"
}

// ---- compiled types (exported where needed) -----------------------------

// CompiledPolicy is the immutable compiled representation of a policy file.
// Created by LoadFromFile or LoadFromBytes; passed to YAMLPolicyEngine.
type CompiledPolicy struct {
	allowedSurface map[string]struct{}
	allowRules     []compiledRule
	denyRules      []compiledRule
}

type compiledRule struct {
	name      string
	tools     map[string]struct{}
	args      map[string]*compiledArgValidator
	reason    string
	rateLimit *compiledRateLimit
}

type compiledRateLimit struct {
	max    int
	window time.Duration
	per    string // "global" | "client"
}

// ---- loaders ------------------------------------------------------------

// LoadFromFile reads and compiles a policy from a YAML file.
func LoadFromFile(path string) (*CompiledPolicy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy file: %w", err)
	}
	return LoadFromBytes(data)
}

// LoadFromBytes compiles a policy from raw YAML bytes with strict field checking.
func LoadFromBytes(data []byte) (*CompiledPolicy, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var pf policyFile
	if err := dec.Decode(&pf); err != nil {
		return nil, fmt.Errorf("decode policy: %w", err)
	}
	return compile(&pf)
}

func compile(pf *policyFile) (*CompiledPolicy, error) {
	if pf.Version != "1" {
		return nil, fmt.Errorf("unsupported policy version %q (want \"1\")", pf.Version)
	}

	toolsets := make(map[string][]string, len(pf.Toolsets))
	for name, ts := range pf.Toolsets {
		toolsets[name] = ts.Tools
	}

	names := make(map[string]struct{}, len(pf.Rules))
	allowedSurface := make(map[string]struct{})
	var allowRules, denyRules []compiledRule

	for i, r := range pf.Rules {
		if r.Name == "" {
			return nil, fmt.Errorf("rule[%d]: name is required", i)
		}
		if r.Action != "allow" && r.Action != "deny" {
			return nil, fmt.Errorf("rule %q: action must be allow or deny", r.Name)
		}
		if len(r.Tools) == 0 && r.Toolset == "" {
			return nil, fmt.Errorf("rule %q: must specify tools or toolset", r.Name)
		}
		if _, dup := names[r.Name]; dup {
			return nil, fmt.Errorf("duplicate rule name %q", r.Name)
		}
		names[r.Name] = struct{}{}

		toolSet := make(map[string]struct{}, len(r.Tools))
		for _, t := range r.Tools {
			toolSet[t] = struct{}{}
		}
		if r.Toolset != "" {
			ts, ok := toolsets[r.Toolset]
			if !ok {
				return nil, fmt.Errorf("rule %q: toolset %q not defined", r.Name, r.Toolset)
			}
			for _, t := range ts {
				toolSet[t] = struct{}{}
			}
		}

		compiledArgs := make(map[string]*compiledArgValidator, len(r.Args))
		for argName, av := range r.Args {
			cv, err := newCompiledArgValidator(av)
			if err != nil {
				return nil, fmt.Errorf("rule %q, arg %q: %w", r.Name, argName, err)
			}
			compiledArgs[argName] = cv
		}

		var crl *compiledRateLimit
		if r.RateLimit != nil {
			if r.Action != "allow" {
				return nil, fmt.Errorf("rule %q: rate_limit is only valid on allow rules", r.Name)
			}
			if r.RateLimit.Max <= 0 {
				return nil, fmt.Errorf("rule %q: rate_limit.max must be > 0", r.Name)
			}
			dur, err := time.ParseDuration(r.RateLimit.Window)
			if err != nil {
				return nil, fmt.Errorf("rule %q: rate_limit.window %q: %w", r.Name, r.RateLimit.Window, err)
			}
			if dur <= 0 {
				return nil, fmt.Errorf("rule %q: rate_limit.window must be positive, got %q", r.Name, r.RateLimit.Window)
			}
			per := r.RateLimit.Per
			if per == "" {
				per = "global"
			}
			if per != "global" && per != "client" {
				return nil, fmt.Errorf("rule %q: rate_limit.per must be 'global' or 'client', got %q", r.Name, per)
			}
			crl = &compiledRateLimit{max: r.RateLimit.Max, window: dur, per: per}
		}

		cr := compiledRule{
			name:      r.Name,
			tools:     toolSet,
			args:      compiledArgs,
			reason:    r.Reason,
			rateLimit: crl,
		}

		switch r.Action {
		case "allow":
			allowRules = append(allowRules, cr)
			for t := range toolSet {
				allowedSurface[t] = struct{}{}
			}
		case "deny":
			denyRules = append(denyRules, cr)
		}
	}

	return &CompiledPolicy{
		allowedSurface: allowedSurface,
		allowRules:     allowRules,
		denyRules:      denyRules,
	}, nil
}

// ---- evaluation ---------------------------------------------------------

// evaluate runs the full policy algorithm against a tools/call request.
// Caller must ensure p is non-nil.
func (p *CompiledPolicy) evaluate(call *mcp.ToolsCallRequest) Decision {
	// 1. Tool must be in the allowed surface.
	if _, ok := p.allowedSurface[call.Name]; !ok {
		return Decision{Action: "deny", Reason: "tool not in allowed surface"}
	}

	// 2. Deny rules act as guardrails.
	for _, rule := range p.denyRules {
		if _, ok := rule.tools[call.Name]; !ok {
			continue
		}
		// Unconditional deny (no args) OR any arg validator fails → deny.
		if len(rule.args) == 0 || anyArgFails(rule.args, call.Arguments) {
			reason := rule.reason
			if reason == "" {
				reason = "denied by rule " + rule.name
			}
			return Decision{Action: "deny", Rule: rule.name, Reason: reason}
		}
	}

	// 3. Allow rule arg validators must all pass.
	for _, rule := range p.allowRules {
		if _, ok := rule.tools[call.Name]; !ok {
			continue
		}
		if len(rule.args) == 0 {
			continue
		}
		if anyArgFails(rule.args, call.Arguments) {
			return Decision{Action: "deny", Rule: rule.name, Reason: "arg validation failed"}
		}
	}

	return Decision{Action: "allow"}
}

// anyArgFails returns true when any arg validator is missing or its constraint fails.
func anyArgFails(validators map[string]*compiledArgValidator, args map[string]any) bool {
	for name, v := range validators {
		val, ok := args[name]
		if !ok {
			return true // missing arg treated as invalid
		}
		if !v.Validate(val) {
			return true
		}
	}
	return false
}

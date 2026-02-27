package policy

import (
	"fmt"
	"regexp"
)

// ArgValidator defines string constraints for a single argument.
// Compiled from YAML; applied to string argument values only.
type ArgValidator struct {
	Match    string   `yaml:"match,omitempty"`
	NotMatch string   `yaml:"not_match,omitempty"`
	OneOf    []string `yaml:"one_of,omitempty"`
	MaxLen   int      `yaml:"max_len,omitempty"`
}

// compiledArgValidator holds a parsed ArgValidator with pre-compiled regexes.
type compiledArgValidator struct {
	raw        ArgValidator
	matchRE    *regexp.Regexp
	notMatchRE *regexp.Regexp
}

func newCompiledArgValidator(av ArgValidator) (*compiledArgValidator, error) {
	c := &compiledArgValidator{raw: av}
	if av.Match != "" {
		re, err := regexp.Compile(av.Match)
		if err != nil {
			return nil, fmt.Errorf("match: %w", err)
		}
		c.matchRE = re
	}
	if av.NotMatch != "" {
		re, err := regexp.Compile(av.NotMatch)
		if err != nil {
			return nil, fmt.Errorf("not_match: %w", err)
		}
		c.notMatchRE = re
	}
	return c, nil
}

// Validate returns true if val satisfies all constraints.
// Non-string values always fail when any constraint is defined.
// A missing argument (nil val) also fails.
func (v *compiledArgValidator) Validate(val any) bool {
	s, ok := val.(string)
	if !ok {
		return false
	}
	if v.matchRE != nil && !v.matchRE.MatchString(s) {
		return false
	}
	if v.notMatchRE != nil && v.notMatchRE.MatchString(s) {
		return false
	}
	if len(v.raw.OneOf) > 0 {
		found := false
		for _, opt := range v.raw.OneOf {
			if s == opt {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if v.raw.MaxLen > 0 && len(s) > v.raw.MaxLen {
		return false
	}
	return true
}

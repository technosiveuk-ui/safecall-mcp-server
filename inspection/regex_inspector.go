package inspection

import (
	"context"
	"fmt"

	"github.com/technosiveuk-ui/safecall-mcp-server/core"
)

// RegexInspector scans field values against a set of compiled regex patterns.
// It recurses into nested maps for deep inspection and attributes every
// finding to the specific field path (e.g. "user.ssn").
type RegexInspector struct {
	patterns []Pattern
}

// NewRegexInspector creates a RegexInspector using the built-in pattern set.
func NewRegexInspector() *RegexInspector {
	return &RegexInspector{patterns: BuiltinPatterns}
}

// NewRegexInspectorWithPatterns creates a RegexInspector with custom patterns.
func NewRegexInspectorWithPatterns(patterns []Pattern) *RegexInspector {
	dst := make([]Pattern, len(patterns))
	copy(dst, patterns)
	return &RegexInspector{patterns: dst}
}

// Inspect examines all fields and returns regex-matched findings.
func (ri *RegexInspector) Inspect(_ context.Context, fields map[string]any) ([]core.Finding, error) {
	return ri.inspectMap(fields, ""), nil
}

func (ri *RegexInspector) inspectMap(fields map[string]any, prefix string) []core.Finding {
	var findings []core.Finding
	for key, val := range fields {
		fieldPath := key
		if prefix != "" {
			fieldPath = prefix + "." + key
		}

		switch v := val.(type) {
		case map[string]any:
			// Recurse into nested maps.
			findings = append(findings, ri.inspectMap(v, fieldPath)...)
		default:
			str := fmt.Sprintf("%v", v)
			for _, p := range ri.patterns {
				if p.Regex.MatchString(str) {
					findings = append(findings, core.NewFinding(fieldPath, p.Category, str))
					break // one finding per field is enough
				}
			}
		}
	}
	return findings
}

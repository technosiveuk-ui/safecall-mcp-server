package inspection

import (
	"context"
	"fmt"
	"strings"

	"github.com/technosiveuk-ui/safecall-mcp-server/core"
)

// sensitiveFieldNames is the default set of field names that are inherently
// suspicious regardless of their value content.
var sensitiveFieldNames = map[string]string{
	"password":     "SECRET/PASSWORD",
	"passwd":       "SECRET/PASSWORD",
	"secret":       "SECRET/GENERIC",
	"api_key":      "SECRET/API_KEY",
	"apikey":       "SECRET/API_KEY",
	"api-key":      "SECRET/API_KEY",
	"token":        "SECRET/TOKEN",
	"access_token": "SECRET/TOKEN",
	"ssn":          "PII/SSN",
	"credit_card":  "PII/CREDIT_CARD",
	"creditcard":   "PII/CREDIT_CARD",
}

// FieldNameInspector triggers findings based solely on field names matching
// known sensitive keywords. Per PRD FR3: a field named "password" must
// trigger a finding even if the value doesn't match a standard regex.
type FieldNameInspector struct {
	keywords map[string]string // lowered field name → category
}

// NewFieldNameInspector creates a FieldNameInspector with the default keyword set.
func NewFieldNameInspector() *FieldNameInspector {
	return &FieldNameInspector{keywords: sensitiveFieldNames}
}

// Inspect scans field names for sensitive keywords.
func (fni *FieldNameInspector) Inspect(_ context.Context, fields map[string]any) ([]core.Finding, error) {
	return fni.inspectMap(fields, ""), nil
}

func (fni *FieldNameInspector) inspectMap(fields map[string]any, prefix string) []core.Finding {
	var findings []core.Finding
	for key, val := range fields {
		fieldPath := key
		if prefix != "" {
			fieldPath = prefix + "." + key
		}

		lowered := strings.ToLower(key)
		if category, ok := fni.keywords[lowered]; ok {
			findings = append(findings, core.NewFinding(fieldPath, category, fmt.Sprintf("%v", val)))
		}

		// Recurse into nested maps.
		if nested, ok := val.(map[string]any); ok {
			findings = append(findings, fni.inspectMap(nested, fieldPath)...)
		}
	}
	return findings
}

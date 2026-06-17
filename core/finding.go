package core

import (
	"crypto/sha256"
	"encoding/hex"
)

// Finding represents a single sensitive-data detection attributed to a
// specific field in the tool-call arguments or response.
type Finding struct {
	// FieldName is the dot-separated path to the field, e.g. "user.ssn".
	FieldName string `json:"field_name"`

	// Category classifies the finding, e.g. "PII/SSN", "SECRET/API_KEY".
	Category string `json:"category"`

	// OriginalValue holds the raw value that triggered the finding. It is kept
	// in memory ONLY for redaction/diagnostics and is NEVER serialized —
	// persisting it would log the very secrets SafeCall is built to protect.
	// Use Fingerprint for audit correlation. The json:"-" tag enforces this at
	// the type level so no Emitter can leak it, regardless of implementation.
	OriginalValue string `json:"-"`

	// Fingerprint is a short, non-reversible digest of OriginalValue
	// (sha256[:8] as hex). It lets operators correlate the same secret across
	// audit events without ever exposing the plaintext.
	Fingerprint string `json:"fingerprint,omitempty"`

	// RedactedValue is the masked replacement applied to the field, e.g.
	// "***REDACTED***".
	RedactedValue string `json:"redacted_value,omitempty"`
}

// RedactedPlaceholder is the standard mask applied to redacted values.
const RedactedPlaceholder = "***REDACTED***"

// NewFinding constructs a Finding from a sensitive detection. It centralizes
// the invariant that the raw value is never exposed via JSON while still
// recording a non-reversible fingerprint for correlation. Always prefer this
// constructor over a struct literal so the no-leak guarantee cannot be bypassed
// by a forgotten field tag.
func NewFinding(fieldName, category, originalValue string) Finding {
	return Finding{
		FieldName:     fieldName,
		Category:      category,
		OriginalValue: originalValue,
		Fingerprint:   fingerprint(originalValue),
		RedactedValue: RedactedPlaceholder,
	}
}

// fingerprint returns a non-reversible, short digest of a secret value for
// audit correlation. It can never be used to recover the original.
func fingerprint(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:8]) // 16 hex chars (64 bits) — ample for log correlation
}

package policy

import (
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/technosiveuk-ui/safecall-mcp-server/core"
	"github.com/technosiveuk-ui/safecall-mcp-server/internal/fileutil"
	"gopkg.in/yaml.v3"
)

// yamlFile is the on-disk structure of policies.yaml.
type yamlFile struct {
	Tools map[string]yamlPolicy `yaml:"tools"`
}

// yamlPolicy is a single tool's policy in the YAML file.
type yamlPolicy struct {
	Action       string   `yaml:"action"`
	RedactFields []string `yaml:"redact_fields,omitempty"`
}

// YamlProvider loads policies from a local YAML file. It validates file
// permissions on Unix (must be 0600) and caches parsed policies in memory.
// It is safe for concurrent use after construction.
type YamlProvider struct {
	mu       sync.RWMutex
	policies map[string]*Policy
}

// NewYamlProvider reads and parses the policy file at the given path.
// It returns a PolicyLoadError if the file is missing, has wrong permissions,
// or contains invalid YAML.
func NewYamlProvider(path string) (*YamlProvider, error) {
	// NFR5: enforce file permissions before reading.
	if err := fileutil.CheckFilePermissions(path); err != nil {
		return nil, &core.PolicyLoadError{Path: path, Err: err}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, &core.PolicyLoadError{Path: path, Err: err}
	}

	var file yamlFile
	if err := yaml.Unmarshal(data, &file); err != nil {
		return nil, &core.PolicyLoadError{
			Path: path,
			Err:  fmt.Errorf("invalid YAML: %w", err),
		}
	}

	policies := make(map[string]*Policy, len(file.Tools))
	for name, yp := range file.Tools {
		policies[name] = &Policy{
			Action:       core.ParseAction(yp.Action),
			RedactFields: yp.RedactFields,
		}
	}

	return &YamlProvider{policies: policies}, nil
}

// PolicyFor returns the policy for the named tool, or nil if no policy exists.
func (yp *YamlProvider) PolicyFor(_ context.Context, toolName string) (*Policy, error) {
	yp.mu.RLock()
	defer yp.mu.RUnlock()
	p, ok := yp.policies[toolName]
	if !ok {
		return nil, nil
	}
	return p, nil
}

// StaticProvider is an in-memory provider built from a map. Useful for
// testing and programmatic configuration.
type StaticProvider struct {
	policies map[string]*Policy
}

// NewStaticProvider creates a provider from a pre-built policy map.
func NewStaticProvider(policies map[string]*Policy) *StaticProvider {
	return &StaticProvider{policies: policies}
}

// PolicyFor returns the policy for the named tool.
func (sp *StaticProvider) PolicyFor(_ context.Context, toolName string) (*Policy, error) {
	p, ok := sp.policies[toolName]
	if !ok {
		return nil, nil
	}
	return p, nil
}

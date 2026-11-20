// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"go.yaml.in/yaml/v3"
)

// Load reads, strictly decodes and validates the config at path.
// Warnings are non-fatal findings (e.g. secret scanning disabled).
func Load(path string) (*Config, []string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, MaxConfigBytes+1))
	if err != nil {
		return nil, nil, err
	}
	if len(data) > MaxConfigBytes {
		return nil, nil, fmt.Errorf("%s: larger than %d bytes", path, MaxConfigBytes)
	}
	return Parse(data)
}

// Parse strictly decodes and validates a config document.
func Parse(data []byte) (*Config, []string, error) {
	cfg, err := decode(data)
	if err != nil {
		return nil, nil, err
	}
	warnings, err := cfg.Validate()
	if err != nil {
		return nil, warnings, err
	}
	return cfg, warnings, nil
}

func decode(data []byte) (*Config, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("config is empty")
		}
		return nil, fmt.Errorf("decode: %w", err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("decode: config must contain exactly one YAML document")
	}
	return &cfg, nil
}

// UnmarshalYAML accepts "name" or {name: ..., as: ...}. Node.Decode does not
// inherit KnownFields, so mapping keys are checked by hand.
func (r *RefSpec) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.ScalarNode:
		if n.Tag != "!!str" {
			return fmt.Errorf("line %d: branch must be a string, got %s", n.Line, n.Tag)
		}
		r.Name = n.Value
		return nil
	case yaml.MappingNode:
		seen := map[string]bool{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			if seen[k.Value] {
				return fmt.Errorf("line %d: duplicate key %q in branch spec", k.Line, k.Value)
			}
			seen[k.Value] = true
			if v.Kind != yaml.ScalarNode || v.Tag != "!!str" {
				return fmt.Errorf("line %d: branch %q must be a string", v.Line, k.Value)
			}
			switch k.Value {
			case "name":
				r.Name = v.Value
			case "as":
				r.As = v.Value
			default:
				return fmt.Errorf("line %d: field %s not found in branch spec (allowed: name, as)", k.Line, k.Value)
			}
		}
		return nil
	default:
		return fmt.Errorf("line %d: branch must be a name or {name, as} mapping", n.Line)
	}
}

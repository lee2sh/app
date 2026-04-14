// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package appconfig

import (
	"fmt"
	"os"
	"strings"

	"sigs.k8s.io/yaml"
)

// Config is the top-level YAML configuration for multi-org GitHub App routing.
type Config struct {
	Orgs []OrgConfig `json:"orgs"`
}

// OrgConfig binds a GitHub organization to one or more GitHub Apps.
type OrgConfig struct {
	Name string      `json:"name"`
	Apps []AppConfig `json:"apps"`
}

// AppConfig describes a single GitHub App and its credential source.
// Exactly one of KMSKey, PrivateKeyFile, or PrivateKey must be set.
type AppConfig struct {
	AppID          int64  `json:"app_id"`
	KMSKey         string `json:"kms_key,omitempty"`
	PrivateKeyFile string `json:"private_key_file,omitempty"`
	PrivateKey     string `json:"private_key,omitempty"`
}

// Load reads a YAML config file from path, expands environment variables
// in the content (so that ${VAR} references are resolved), and returns
// the parsed Config.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	// Expand ${VAR} references so that private_key can be injected from env.
	expanded := os.ExpandEnv(string(data))

	var cfg Config
	if err := yaml.UnmarshalStrict([]byte(expanded), &cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}
	return &cfg, nil
}

// Validate checks the config for structural errors:
//   - at least one org
//   - no duplicate org names (case-insensitive)
//   - no duplicate app IDs (globally)
//   - at least one app per org
//   - exactly one credential source per app
//
// Org names are normalized to lowercase since GitHub organization names
// are case-insensitive.
func (c *Config) Validate() error {
	if len(c.Orgs) == 0 {
		return fmt.Errorf("config must have at least one org")
	}

	orgNames := make(map[string]bool)
	appIDs := make(map[int64]bool)

	for i := range c.Orgs {
		c.Orgs[i].Name = strings.ToLower(c.Orgs[i].Name)
		org := c.Orgs[i]
		if org.Name == "" {
			return fmt.Errorf("org name must not be empty")
		}
		if orgNames[org.Name] {
			return fmt.Errorf("duplicate org name: %q", org.Name)
		}
		orgNames[org.Name] = true

		if len(org.Apps) == 0 {
			return fmt.Errorf("org %q must have at least one app", org.Name)
		}

		for _, app := range org.Apps {
			if app.AppID == 0 {
				return fmt.Errorf("org %q: app_id must not be zero", org.Name)
			}
			if appIDs[app.AppID] {
				return fmt.Errorf("duplicate app_id: %d", app.AppID)
			}
			appIDs[app.AppID] = true

			sources := 0
			if app.KMSKey != "" {
				sources++
			}
			if app.PrivateKeyFile != "" {
				sources++
			}
			if app.PrivateKey != "" {
				sources++
			}
			if sources != 1 {
				return fmt.Errorf("org %q, app %d: exactly one of kms_key, private_key_file, or private_key must be set", org.Name, app.AppID)
			}
		}
	}

	return nil
}

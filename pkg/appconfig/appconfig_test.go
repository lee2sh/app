// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package appconfig

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(`
orgs:
  - name: my-org
    apps:
      - app_id: 111
        kms_key: projects/p/locations/global/keyRings/kr/cryptoKeys/k/cryptoKeyVersions/1
      - app_id: 222
        kms_key: projects/p/locations/global/keyRings/kr/cryptoKeys/k/cryptoKeyVersions/2
  - name: other-org
    apps:
      - app_id: 333
        private_key_file: /etc/secrets/key.pem
`), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	if len(cfg.Orgs) != 2 {
		t.Fatalf("expected 2 orgs, got %d", len(cfg.Orgs))
	}
	if cfg.Orgs[0].Name != "my-org" {
		t.Errorf("expected org name my-org, got %q", cfg.Orgs[0].Name)
	}
	if len(cfg.Orgs[0].Apps) != 2 {
		t.Errorf("expected 2 apps for my-org, got %d", len(cfg.Orgs[0].Apps))
	}
	if cfg.Orgs[0].Apps[0].AppID != 111 {
		t.Errorf("expected app_id 111, got %d", cfg.Orgs[0].Apps[0].AppID)
	}
	if cfg.Orgs[1].Apps[0].PrivateKeyFile != "/etc/secrets/key.pem" {
		t.Errorf("expected private_key_file, got %q", cfg.Orgs[1].Apps[0].PrivateKeyFile)
	}
}

func TestLoadExpandsEnvVars(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(`
orgs:
  - name: env-org
    apps:
      - app_id: 999
        private_key: "${TEST_INJECTED_PEM}"
`), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("TEST_INJECTED_PEM", "test-pem-value-12345")

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	if cfg.Orgs[0].Apps[0].PrivateKey != "test-pem-value-12345" {
		t.Errorf("env var not expanded: %q", cfg.Orgs[0].Apps[0].PrivateKey)
	}
}

func TestLoadFileNotFound(t *testing.T) {
	_, err := Load("/nonexistent/config.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadInvalidYAML(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(cfgPath, []byte(`{not valid yaml: [`), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Load(cfgPath)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestLoadStrictRejectsUnknownFields(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "strict.yaml")
	if err := os.WriteFile(cfgPath, []byte(`
orgs:
  - name: my-org
    apps:
      - app_id: 111
        kms_key: key
        unknown_field: oops
`), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Load(cfgPath)
	if err == nil {
		t.Fatal("expected error for unknown field")
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name:    "empty orgs",
			cfg:     Config{},
			wantErr: true,
		},
		{
			name: "empty org name",
			cfg: Config{Orgs: []OrgConfig{
				{Name: "", Apps: []AppConfig{{AppID: 1, KMSKey: "k"}}},
			}},
			wantErr: true,
		},
		{
			name: "duplicate org names",
			cfg: Config{Orgs: []OrgConfig{
				{Name: "org", Apps: []AppConfig{{AppID: 1, KMSKey: "k"}}},
				{Name: "org", Apps: []AppConfig{{AppID: 2, KMSKey: "k"}}},
			}},
			wantErr: true,
		},
		{
			name: "no apps in org",
			cfg: Config{Orgs: []OrgConfig{
				{Name: "org", Apps: nil},
			}},
			wantErr: true,
		},
		{
			name: "zero app_id",
			cfg: Config{Orgs: []OrgConfig{
				{Name: "org", Apps: []AppConfig{{AppID: 0, KMSKey: "k"}}},
			}},
			wantErr: true,
		},
		{
			name: "duplicate app_id across orgs",
			cfg: Config{Orgs: []OrgConfig{
				{Name: "org1", Apps: []AppConfig{{AppID: 1, KMSKey: "k1"}}},
				{Name: "org2", Apps: []AppConfig{{AppID: 1, KMSKey: "k2"}}},
			}},
			wantErr: true,
		},
		{
			name: "no credential source",
			cfg: Config{Orgs: []OrgConfig{
				{Name: "org", Apps: []AppConfig{{AppID: 1}}},
			}},
			wantErr: true,
		},
		{
			name: "multiple credential sources",
			cfg: Config{Orgs: []OrgConfig{
				{Name: "org", Apps: []AppConfig{{AppID: 1, KMSKey: "k", PrivateKey: "pk"}}},
			}},
			wantErr: true,
		},
		{
			name: "valid single org kms",
			cfg: Config{Orgs: []OrgConfig{
				{Name: "org", Apps: []AppConfig{{AppID: 1, KMSKey: "k"}}},
			}},
			wantErr: false,
		},
		{
			name: "valid multi org mixed credentials",
			cfg: Config{Orgs: []OrgConfig{
				{Name: "org1", Apps: []AppConfig{
					{AppID: 1, KMSKey: "k"},
					{AppID: 2, KMSKey: "k2"},
				}},
				{Name: "org2", Apps: []AppConfig{
					{AppID: 3, PrivateKeyFile: "/path"},
				}},
				{Name: "org3", Apps: []AppConfig{
					{AppID: 4, PrivateKey: "pem"},
				}},
			}},
			wantErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if (err != nil) != tc.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

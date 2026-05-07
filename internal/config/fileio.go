package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// applyConfigPerms enforces 0600 on the config file and 0700 on its parent
// directory. It only chmods when current perms differ from the target, so
// repeat calls on already-tight perms are no-ops and safe on directories
// the process doesn't own (e.g. /tmp).
//
// Strictness is the caller's choice. SaveFileConfig bubbles errors because
// it just wrote secrets and a dir we can't tighten is a real problem. The
// load path swallows the return: chmod can fail on read-only FS, foreign-
// owned files, or filesystems that don't honor unix perms, none of which
// should block reading config.
func applyConfigPerms(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	if fi, err := os.Stat(path); err == nil && fi.Mode().Perm() != 0600 {
		if err := os.Chmod(path, 0600); err != nil {
			return fmt.Errorf("failed to set config file permissions: %w", err)
		}
	}
	dir := filepath.Dir(path)
	if fi, err := os.Stat(dir); err == nil && fi.Mode().Perm() != 0700 {
		if err := os.Chmod(dir, 0700); err != nil {
			return fmt.Errorf("failed to set config directory permissions: %w", err)
		}
	}
	return nil
}

// LoadFileConfig loads a FileConfig from the default or specified path.
// Returns the config and the path it was loaded from.
func LoadFileConfig() (*FileConfig, string, error) {
	configPath := envOr("PINCHTAB_CONFIG", filepath.Join(userConfigDir(), "config.json"))

	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			// No file on disk — the effective config is the defaults. Returning
			// a populated DefaultFileConfig() (rather than a zero FileConfig{})
			// means callers that subsequently SaveFileConfig don't write a
			// half-empty file with all-zero security/instance fields, which
			// previously caused IDPI and other defaults to be silently disabled
			// on first-run auto-config. ConfigVersion is reset so NeedsWizard()
			// still treats this as a first-install state.
			defaults := DefaultFileConfig()
			defaults.ConfigVersion = ""
			return &defaults, configPath, nil
		}
		return nil, configPath, fmt.Errorf("failed to read config file: %w", err)
	}

	_ = applyConfigPerms(configPath)

	if isLegacyConfig(data) {
		fc, err := loadLegacyFileConfig(data)
		return fc, configPath, err
	}

	defaults := DefaultFileConfig()
	defaults.ConfigVersion = ""
	fc := &defaults
	if err := json.Unmarshal(data, fc); err != nil {
		return nil, configPath, fmt.Errorf("failed to parse config: %w", err)
	}
	NormalizeFileConfigAliasesFromJSON(fc, data)

	return fc, configPath, nil
}

// SaveFileConfig saves a FileConfig to the specified path.
func SaveFileConfig(fc *FileConfig, path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	data, err := json.MarshalIndent(fc, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize config: %w", err)
	}
	data = append(data, '\n')

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return applyConfigPerms(path)
}

func loadLegacyFileConfig(data []byte) (*FileConfig, error) {
	var lc legacyFileConfig
	if err := json.Unmarshal(data, &lc); err != nil {
		return nil, fmt.Errorf("failed to parse legacy config: %w", err)
	}

	defaults := DefaultFileConfig()
	fc := &defaults
	legacy := convertLegacyConfig(&lc)
	if legacy.Server.Port != "" {
		fc.Server.Port = legacy.Server.Port
	}
	if legacy.Server.Token != "" {
		fc.Server.Token = legacy.Server.Token
	}
	if legacy.Server.StateDir != "" {
		fc.Server.StateDir = legacy.Server.StateDir
	}
	if legacy.InstanceDefaults.Mode != "" {
		fc.InstanceDefaults.Mode = legacy.InstanceDefaults.Mode
	}
	if legacy.InstanceDefaults.NoRestore != nil {
		fc.InstanceDefaults.NoRestore = legacy.InstanceDefaults.NoRestore
	}
	if legacy.InstanceDefaults.MaxTabs != nil {
		fc.InstanceDefaults.MaxTabs = legacy.InstanceDefaults.MaxTabs
	}
	if legacy.Profiles.BaseDir != "" {
		fc.Profiles.BaseDir = legacy.Profiles.BaseDir
	}
	if legacy.Profiles.DefaultProfile != "" {
		fc.Profiles.DefaultProfile = legacy.Profiles.DefaultProfile
	}
	if legacy.Security.AllowEvaluate != nil {
		fc.Security.AllowEvaluate = legacy.Security.AllowEvaluate
	}
	if legacy.Security.AllowMacro != nil {
		fc.Security.AllowMacro = legacy.Security.AllowMacro
	}
	if legacy.Security.AllowScreencast != nil {
		fc.Security.AllowScreencast = legacy.Security.AllowScreencast
	}
	if legacy.Security.AllowDownload != nil {
		fc.Security.AllowDownload = legacy.Security.AllowDownload
	}
	if legacy.Security.AllowUpload != nil {
		fc.Security.AllowUpload = legacy.Security.AllowUpload
	}
	if legacy.Timeouts.ActionSec != 0 {
		fc.Timeouts.ActionSec = legacy.Timeouts.ActionSec
	}
	if legacy.Timeouts.NavigateSec != 0 {
		fc.Timeouts.NavigateSec = legacy.Timeouts.NavigateSec
	}
	if legacy.MultiInstance.InstancePortStart != nil {
		fc.MultiInstance.InstancePortStart = legacy.MultiInstance.InstancePortStart
	}
	if legacy.MultiInstance.InstancePortEnd != nil {
		fc.MultiInstance.InstancePortEnd = legacy.MultiInstance.InstancePortEnd
	}

	return fc, nil
}

func NormalizeFileConfigAliasesFromJSON(fc *FileConfig, data []byte) {
	if fc == nil {
		return
	}

	type rawIDPI struct {
		AllowedDomains *[]string `json:"allowedDomains"`
	}
	type rawSecurity struct {
		AllowedDomains *[]string `json:"allowedDomains"`
		IDPI           *rawIDPI  `json:"idpi"`
	}
	type rawConfig struct {
		Security *rawSecurity `json:"security"`
	}

	var raw rawConfig
	if err := json.Unmarshal(data, &raw); err != nil || raw.Security == nil {
		return
	}

	switch {
	case raw.Security.AllowedDomains != nil:
		fc.Security.AllowedDomains = append([]string(nil), (*raw.Security.AllowedDomains)...)
	case raw.Security.IDPI != nil && raw.Security.IDPI.AllowedDomains != nil:
		fc.Security.AllowedDomains = append([]string(nil), (*raw.Security.IDPI.AllowedDomains)...)
	}
}

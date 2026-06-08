package providerhooks

import (
	"sync"

	"github.com/pinchtab/pinchtab/internal/bridge"
	"github.com/pinchtab/pinchtab/internal/config"
)

// Hooks lets browser providers expose optional bridge decoration and
// lifecycle cleanup behavior without leaking concrete implementations into
// generic server/orchestrator code.
type Hooks struct {
	DecorateBridge func(bridge.BridgeAPI, *config.RuntimeConfig) bridge.BridgeAPI
	CleanupProfile func(string)
	Shutdown       func()
}

var (
	mu       sync.RWMutex
	registry = map[string]Hooks{}
)

// Register stores provider-specific hooks under a normalized browser ID.
func Register(browserID string, hooks Hooks) {
	mu.Lock()
	defer mu.Unlock()
	registry[browserID] = hooks
}

// DecorateBridge applies the provider's bridge decorator when one exists.
func DecorateBridge(browserID string, api bridge.BridgeAPI, cfg *config.RuntimeConfig) bridge.BridgeAPI {
	mu.RLock()
	hooks, ok := registry[browserID]
	mu.RUnlock()
	if !ok || hooks.DecorateBridge == nil {
		return api
	}
	return hooks.DecorateBridge(api, cfg)
}

// CleanupProfile runs provider-specific orphan cleanup for a profile path.
func CleanupProfile(browserID, profileDir string) {
	mu.RLock()
	hooks, ok := registry[browserID]
	mu.RUnlock()
	if !ok || hooks.CleanupProfile == nil {
		return
	}
	hooks.CleanupProfile(profileDir)
}

// Shutdown runs provider-specific process cleanup during server shutdown.
func Shutdown(browserID string) {
	mu.RLock()
	hooks, ok := registry[browserID]
	mu.RUnlock()
	if !ok || hooks.Shutdown == nil {
		return
	}
	hooks.Shutdown()
}

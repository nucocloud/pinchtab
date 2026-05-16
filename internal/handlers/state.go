package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	"github.com/pinchtab/pinchtab/internal/httpx"
	"github.com/pinchtab/pinchtab/internal/state"
)

type tabLoadState struct {
	ReadyState           string `json:"readyState,omitempty"`
	NavigationInProgress bool   `json:"navigationInProgress"`
	NetworkIdle          *bool  `json:"networkIdle,omitempty"`
	State                string `json:"state"`
}

type tabStateResponse struct {
	TabID         string       `json:"tabId"`
	URL           string       `json:"url,omitempty"`
	Title         string       `json:"title,omitempty"`
	DialogPresent bool         `json:"dialogPresent"`
	Dialog        interface{}  `json:"dialog,omitempty"`
	Load          tabLoadState `json:"load"`
	Actionability string       `json:"actionability"`
}

func (h *Handlers) stateExportEnabled() bool {
	return h != nil && h.Config != nil && h.Config.AllowStateExport
}

// HandleStateList lists all saved state files.
func (h *Handlers) HandleStateList(w http.ResponseWriter, r *http.Request) {
	entries, err := state.List(h.Config.StateDir)
	if err != nil {
		httpx.Error(w, 500, fmt.Errorf("list states: %w", err))
		return
	}
	httpx.JSON(w, 200, map[string]any{
		"states": entries,
		"count":  len(entries),
	})
}

// HandleStateShow returns the full contents of a saved state file.
func (h *Handlers) HandleStateShow(w http.ResponseWriter, r *http.Request) {
	if !h.stateExportEnabled() {
		httpx.ErrorCode(w, 403, "state_export_disabled", httpx.DisabledEndpointMessage("stateExport", "security.allowStateExport"), false, map[string]any{
			"setting": "security.allowStateExport",
		})
		return
	}

	name := r.URL.Query().Get("name")
	if name == "" {
		httpx.Error(w, 400, fmt.Errorf("name query parameter is required"))
		return
	}

	encryptionKey := os.Getenv("PINCHTAB_STATE_KEY")
	path := state.ResolvePath(h.Config.StateDir, name)
	sf, err := state.Load(path, encryptionKey)
	if err != nil {
		httpx.Error(w, 500, fmt.Errorf("load state: %w", err))
		return
	}
	httpx.JSON(w, 200, sf)
}

type stateSaveRequest struct {
	Name     string                 `json:"name"`
	Encrypt  bool                   `json:"encrypt"`
	TabID    string                 `json:"tabId"`
	Metadata map[string]interface{} `json:"metadata"`
}

// HandleStateSave captures the current browser state and writes it to disk.
func (h *Handlers) HandleStateSave(w http.ResponseWriter, r *http.Request) {
	if !h.stateExportEnabled() {
		httpx.ErrorCode(w, 403, "state_export_disabled", httpx.DisabledEndpointMessage("stateExport", "security.allowStateExport"), false, map[string]any{
			"setting": "security.allowStateExport",
		})
		return
	}

	var req stateSaveRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodySize)).Decode(&req); err != nil {
		httpx.Error(w, 400, fmt.Errorf("decode: %w", err))
		return
	}

	encryptionKey := ""
	if req.Encrypt {
		encryptionKey = os.Getenv("PINCHTAB_STATE_KEY")
		if err := state.ValidateEncryptionKey(encryptionKey); err != nil {
			httpx.Error(w, 400, fmt.Errorf("encryption key required: set PINCHTAB_STATE_KEY environment variable"))
			return
		}
	}

	ctx, resolvedTabID, err := h.tabContext(r, req.TabID)
	if err != nil {
		WriteTabContextError(w, err, 404)
		return
	}
	if _, ok := h.enforceCurrentTabDomainPolicy(w, r, ctx, resolvedTabID); !ok {
		return
	}

	tCtx, tCancel := context.WithTimeout(ctx, 30*time.Second)
	defer tCancel()

	var cookies []*network.Cookie
	if err := chromedp.Run(tCtx, chromedp.ActionFunc(func(ctx context.Context) error {
		var err error
		cookies, err = network.GetCookies().Do(ctx)
		return err
	})); err != nil {
		httpx.Error(w, 500, fmt.Errorf("get cookies: %w", err))
		return
	}

	storageScript := `
		(function() {
			try {
				var localEntries = {};
				for (var i = 0; i < localStorage.length; i++) {
					var k = localStorage.key(i);
					localEntries[k] = localStorage.getItem(k);
				}
				var sessionEntries = {};
				for (var i = 0; i < sessionStorage.length; i++) {
					var k = sessionStorage.key(i);
					sessionEntries[k] = sessionStorage.getItem(k);
				}
				return JSON.stringify({
					local: localEntries,
					session: sessionEntries,
					url: window.location.href,
					origin: window.location.origin,
					userAgent: navigator.userAgent
				});
			} catch(e) {
				return JSON.stringify({
					error: e.message,
					local: {},
					session: {},
					url: window.location.href,
					origin: window.location.origin,
					userAgent: navigator.userAgent
				});
			}
		})()
	`

	var storageJSON string
	if err := chromedp.Run(tCtx, chromedp.Evaluate(storageScript, &storageJSON)); err != nil {
		httpx.Error(w, 500, fmt.Errorf("evaluate storage: %w", err))
		return
	}

	var storageResult struct {
		Local     map[string]string `json:"local"`
		Session   map[string]string `json:"session"`
		URL       string            `json:"url"`
		Origin    string            `json:"origin"`
		UserAgent string            `json:"userAgent"`
		Error     string            `json:"error"`
	}
	if err := json.Unmarshal([]byte(storageJSON), &storageResult); err != nil {
		httpx.Error(w, 500, fmt.Errorf("parse storage result: %w", err))
		return
	}

	stateCookies := make([]state.Cookie, len(cookies))
	for i, c := range cookies {
		stateCookies[i] = state.Cookie{
			Name:     c.Name,
			Value:    c.Value,
			Domain:   c.Domain,
			Path:     c.Path,
			Secure:   c.Secure,
			HTTPOnly: c.HTTPOnly,
			SameSite: c.SameSite.String(),
			Expires:  c.Expires,
		}
	}
	if storageResult.Local == nil {
		storageResult.Local = map[string]string{}
	}
	if storageResult.Session == nil {
		storageResult.Session = map[string]string{}
	}

	origins := []string{}
	if storageResult.Origin != "" {
		origins = append(origins, storageResult.Origin)
	}

	metadata := map[string]interface{}{
		"url":       storageResult.URL,
		"origin":    storageResult.Origin,
		"userAgent": storageResult.UserAgent,
	}
	for k, v := range req.Metadata {
		metadata[k] = v
	}

	sf := &state.StateFile{
		Name:    req.Name,
		SavedAt: time.Now(),
		Origins: origins,
		Cookies: stateCookies,
		Storage: map[string]state.OriginStorage{
			storageResult.Origin: {
				Local:   storageResult.Local,
				Session: storageResult.Session,
			},
		},
		Metadata: metadata,
	}

	path, err := state.Save(h.Config.StateDir, sf, encryptionKey)
	if err != nil {
		httpx.Error(w, 500, fmt.Errorf("save state: %w", err))
		return
	}

	slog.Info("state saved",
		"name", sf.Name,
		"path", path,
		"cookies", len(stateCookies),
		"origin", storageResult.Origin,
		"encrypted", req.Encrypt,
		"tabId", resolvedTabID,
		"remoteAddr", r.RemoteAddr,
	)

	httpx.JSON(w, 200, map[string]any{
		"name":      sf.Name,
		"path":      path,
		"cookies":   len(stateCookies),
		"origins":   origins,
		"encrypted": req.Encrypt,
	})
}

// HandleStateLoad reads a state file and restores cookies and storage.
func (h *Handlers) HandleStateLoad(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name  string `json:"name"`
		TabID string `json:"tabId"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodySize)).Decode(&req); err != nil {
		httpx.Error(w, 400, fmt.Errorf("decode: %w", err))
		return
	}
	if req.Name == "" {
		httpx.Error(w, 400, fmt.Errorf("name is required"))
		return
	}

	encryptionKey := os.Getenv("PINCHTAB_STATE_KEY")
	path := state.ResolvePath(h.Config.StateDir, req.Name)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		matches, matchErr := state.FindByPrefix(h.Config.StateDir, req.Name)
		if matchErr == nil && len(matches) > 0 {
			path = state.ResolvePath(h.Config.StateDir, matches[0].Name)
		}
	}
	sf, err := state.Load(path, encryptionKey)
	if err != nil {
		sf, err = state.Load(path, "")
		if err != nil {
			httpx.Error(w, 500, fmt.Errorf("load state: %w", err))
			return
		}
	}

	ctx, resolvedTabID, err := h.tabContext(r, req.TabID)
	if err != nil {
		WriteTabContextError(w, err, 404)
		return
	}
	if _, ok := h.enforceCurrentTabDomainPolicy(w, r, ctx, resolvedTabID); !ok {
		return
	}

	tCtx, tCancel := context.WithTimeout(ctx, 30*time.Second)
	defer tCancel()

	cookiesRestored := 0
	if len(sf.Cookies) > 0 {
		if err := chromedp.Run(tCtx, chromedp.ActionFunc(func(ctx context.Context) error {
			for _, c := range sf.Cookies {
				params := network.SetCookie(c.Name, c.Value).
					WithDomain(c.Domain).
					WithPath(c.Path).
					WithSecure(c.Secure).
					WithHTTPOnly(c.HTTPOnly)

				if c.SameSite != "" {
					var sameSite network.CookieSameSite
					switch c.SameSite {
					case "Strict":
						sameSite = network.CookieSameSiteStrict
					case "Lax":
						sameSite = network.CookieSameSiteLax
					case "None":
						sameSite = network.CookieSameSiteNone
					}
					if sameSite != "" {
						params = params.WithSameSite(sameSite)
					}
				}

				if err := chromedp.Run(tCtx, params); err == nil {
					cookiesRestored++
				}
			}
			return nil
		})); err != nil {
			httpx.Error(w, 500, fmt.Errorf("restore cookies: %w", err))
			return
		}
	}

	storageRestored := 0
	for _, originStorage := range sf.Storage {
		for k, v := range originStorage.Local {
			keyJSON, _ := json.Marshal(k)
			valueJSON, _ := json.Marshal(v)
			script := fmt.Sprintf(`localStorage.setItem(%s, %s)`, string(keyJSON), string(valueJSON))
			if err := chromedp.Run(tCtx, chromedp.Evaluate(script, nil)); err == nil {
				storageRestored++
			}
		}
		for k, v := range originStorage.Session {
			keyJSON, _ := json.Marshal(k)
			valueJSON, _ := json.Marshal(v)
			script := fmt.Sprintf(`sessionStorage.setItem(%s, %s)`, string(keyJSON), string(valueJSON))
			if err := chromedp.Run(tCtx, chromedp.Evaluate(script, nil)); err == nil {
				storageRestored++
			}
		}
	}

	slog.Info("state loaded",
		"name", req.Name,
		"path", path,
		"cookiesRestored", cookiesRestored,
		"storageItemsRestored", storageRestored,
		"tabId", resolvedTabID,
		"remoteAddr", r.RemoteAddr,
	)

	httpx.JSON(w, 200, map[string]any{
		"name":                 req.Name,
		"cookiesRestored":      cookiesRestored,
		"storageItemsRestored": storageRestored,
		"origins":              sf.Origins,
	})
}

// HandleStateDelete removes a saved state file.
func (h *Handlers) HandleStateDelete(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		httpx.Error(w, 400, fmt.Errorf("name query parameter is required"))
		return
	}
	if err := state.Delete(h.Config.StateDir, name); err != nil {
		httpx.Error(w, 500, fmt.Errorf("delete state: %w", err))
		return
	}
	slog.Info("state deleted", "name", name, "remoteAddr", r.RemoteAddr)
	httpx.JSON(w, 200, map[string]any{"deleted": name})
}

// HandleStateClean removes state files older than a given duration.
func (h *Handlers) HandleStateClean(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OlderThanHours int `json:"olderThanHours"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodySize)).Decode(&req); err != nil {
		httpx.Error(w, 400, fmt.Errorf("decode: %w", err))
		return
	}
	if req.OlderThanHours <= 0 {
		req.OlderThanHours = 24
	}
	duration := time.Duration(req.OlderThanHours) * time.Hour
	removed, err := state.Clean(h.Config.StateDir, duration)
	if err != nil {
		httpx.Error(w, 500, fmt.Errorf("clean states: %w", err))
		return
	}
	slog.Info("state clean", "olderThanHours", req.OlderThanHours, "removed", removed, "remoteAddr", r.RemoteAddr)
	httpx.JSON(w, 200, map[string]any{
		"removed":        removed,
		"olderThanHours": req.OlderThanHours,
		"sessionsDir":    filepath.Base(state.SessionsDir(h.Config.StateDir)),
	})
}

// HandleTabState returns lightweight tab/page state signals for agent workflows.
func (h *Handlers) HandleTabState(w http.ResponseWriter, r *http.Request) {
	if h.Bridge == nil {
		httpx.ErrorCode(w, http.StatusServiceUnavailable, "bridge_unavailable", "browser bridge unavailable", false, nil)
		return
	}

	tabID := r.PathValue("id")
	if tabID == "" {
		tabID = r.PathValue("tabId")
	}
	if tabID == "" {
		httpx.ErrorCode(w, http.StatusBadRequest, "missing_tab_id", "missing tab id", false, nil)
		return
	}

	_, resolvedTabID, err := h.Bridge.TabContext(tabID)
	if err != nil {
		WriteTabContextError(w, err, http.StatusNotFound)
		return
	}

	resp := tabStateResponse{
		TabID:         resolvedTabID,
		DialogPresent: false,
		Load:          tabLoadState{State: "unknown"},
		Actionability: "ready",
	}

	if targets, err := h.Bridge.ListTargets(); err == nil {
		for _, t := range targets {
			if string(t.TargetID) == resolvedTabID {
				resp.URL = t.URL
				resp.Title = t.Title
				break
			}
		}
	}

	if dm := h.Bridge.GetDialogManager(); dm != nil {
		if dialog := dm.GetPending(resolvedTabID); dialog != nil {
			resp.Dialog = dialog
			resp.DialogPresent = true
			resp.Actionability = "blocked"
		}
	}

	if bridgeWithState, ok := h.Bridge.(interface {
		GetDocumentReadyState(string) (string, error)
		IsNetworkIdle(string) (bool, bool)
	}); ok {
		if readyState, err := bridgeWithState.GetDocumentReadyState(resolvedTabID); err == nil {
			resp.Load.ReadyState = readyState
			switch readyState {
			case "loading":
				resp.Load.State = "loading"
				resp.Load.NavigationInProgress = true
				if resp.Actionability == "ready" {
					resp.Actionability = "caution"
				}
			case "interactive":
				resp.Load.State = "interactive"
				if resp.Actionability == "ready" {
					resp.Actionability = "caution"
				}
			case "complete":
				resp.Load.State = "complete"
			}
		}
		if idle, ok := bridgeWithState.IsNetworkIdle(resolvedTabID); ok {
			resp.Load.NetworkIdle = &idle
			if !idle && resp.Load.State == "complete" {
				resp.Load.State = "busy"
				if resp.Actionability == "ready" {
					resp.Actionability = "caution"
				}
			}
		}
	}

	httpx.JSON(w, http.StatusOK, resp)
}

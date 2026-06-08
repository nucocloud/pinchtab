package handlers

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/pinchtab/pinchtab/internal/bridge"
	"github.com/pinchtab/pinchtab/internal/httpx"
)

// HandleScreenshot captures a screenshot of the current tab.
//
// @Endpoint GET /screenshot
func (h *Handlers) HandleScreenshot(w http.ResponseWriter, r *http.Request) {
	if err := h.ensureBrowser(h.Config); err != nil {
		if h.writeBridgeUnavailable(w, err) {
			return
		}
		httpx.Error(w, 500, fmt.Errorf("browser initialization: %w", err))
		return
	}

	tabID := r.URL.Query().Get("tabId")
	output := r.URL.Query().Get("output")
	selector := r.URL.Query().Get("selector")
	reqNoAnim := r.URL.Query().Get("noAnimations") == "true"
	annotate := r.URL.Query().Get("annotate") == "true" || r.URL.Query().Get("annotate") == "1"
	// beyondViewport captures the full scrollable document. selector wins
	// silently when both are set — selector already clips to an element, and
	// stacking a doc-sized clip on top would be meaningless.
	beyondViewport := r.URL.Query().Get("beyondViewport") == "true" || r.URL.Query().Get("beyondViewport") == "1"
	if selector != "" {
		beyondViewport = false
	}

	ctx, resolvedTabID, err := h.tabContext(r, tabID)
	if err != nil {
		WriteTabContextError(w, err, 404)
		return
	}
	if _, ok := h.enforceCurrentTabDomainPolicy(w, r, ctx, resolvedTabID); !ok {
		return
	}

	tCtx, tCancel := context.WithTimeout(ctx, h.Config.ActionTimeout)
	defer tCancel()
	go httpx.CancelOnClientDone(r.Context(), tCancel)

	if reqNoAnim && !h.Config.NoAnimations {
		if err := bridge.DisableAnimationsOnce(tCtx); err != nil {
			httpx.Error(w, 500, fmt.Errorf("disable animations: %w", err))
			return
		}
	}

	if annotate {
		quality := 80
		if q := r.URL.Query().Get("quality"); q != "" {
			if qn, err := strconv.Atoi(q); err == nil {
				quality = qn
			}
		}
		fmtStr := "jpeg"
		if r.URL.Query().Get("format") == "png" {
			fmtStr = "png"
		}
		img, items, outFormat, err := h.captureAnnotatedScreenshot(tCtx, resolvedTabID, selector, fmtStr, quality, beyondViewport)
		if err != nil {
			httpx.Error(w, 500, fmt.Errorf("annotate: %w", err))
			return
		}
		contentType := "image/jpeg"
		if outFormat == "png" {
			contentType = "image/png"
		}
		if r.URL.Query().Get("raw") == "true" {
			w.Header().Set("Content-Type", contentType)
			if _, err := w.Write(img); err != nil {
				slog.Error("annotated screenshot write", "err", err)
			}
			return
		}
		httpx.JSON(w, 200, map[string]any{
			"format":      outFormat,
			"base64":      base64.StdEncoding.EncodeToString(img),
			"annotations": items,
		})
		return
	}

	var clip *bridge.ScreenshotClip
	if selector != "" {
		nodeID, err := h.resolveSelectorNodeID(tCtx, resolvedTabID, selector)
		if err != nil {
			httpx.Error(w, 400, frameScopedSelectorError("selector", err))
			return
		}
		clip, err = bridge.ScreenshotClipForNode(tCtx, nodeID)
		if err != nil {
			httpx.Error(w, 500, fmt.Errorf("selector screenshot: %w", err))
			return
		}
	}
	// beyondViewport (when no selector clip) is handled inside
	// bridge.CaptureScreenshot via opts.BeyondViewport below.

	quality := 80
	if q := r.URL.Query().Get("quality"); q != "" {
		if qn, err := strconv.Atoi(q); err == nil {
			quality = qn
		}
	}

	format := "jpeg"
	contentType := "image/jpeg"
	ext := ".jpg"

	if r.URL.Query().Get("format") == "png" {
		format = "png"
		contentType = "image/png"
		ext = ".png"
	}

	scale := 1.0
	if s := r.URL.Query().Get("scale"); s != "" {
		if sf, err := strconv.ParseFloat(s, 64); err == nil {
			scale = bridge.ClampScale(sf)
		}
	}
	cdpFormat := bridge.ScreenshotFormatJpeg
	if format == "png" {
		cdpFormat = bridge.ScreenshotFormatPng
	}
	// Route through the shared bridge.CaptureScreenshot engine: it carries the
	// scale/beyondViewport clip synthesis and the provider-runtime fixes
	// (BringToFront + WithFromSurface(false)) so capture works on chrome and
	// cloak alike; tCtx already targets the active provider's CDP session.
	buf, err := bridge.CaptureScreenshot(tCtx, bridge.ScreenshotOpts{
		Format:         cdpFormat,
		Quality:        quality,
		Clip:           clip,
		BeyondViewport: beyondViewport,
		Scale:          scale,
	})
	if err != nil {
		httpx.Error(w, 500, fmt.Errorf("screenshot: %w", err))
		return
	}

	if output == "file" {
		screenshotDir := filepath.Join(h.Config.StateDir, "screenshots")
		if err := os.MkdirAll(screenshotDir, 0750); err != nil {
			httpx.Error(w, 500, fmt.Errorf("create screenshot dir: %w", err))
			return
		}

		timestamp := time.Now().Format("20060102-150405")
		filename := fmt.Sprintf("screenshot-%s%s", timestamp, ext)
		filePath := filepath.Join(screenshotDir, filename)

		if err := os.WriteFile(filePath, buf, 0600); err != nil {
			httpx.Error(w, 500, fmt.Errorf("write screenshot: %w", err))
			return
		}

		httpx.JSON(w, 200, map[string]any{
			"path":      filePath,
			"size":      len(buf),
			"format":    format,
			"timestamp": timestamp,
		})
		return
	}

	if r.URL.Query().Get("raw") == "true" {
		w.Header().Set("Content-Type", contentType)
		if _, err := w.Write(buf); err != nil {
			slog.Error("screenshot write", "err", err)
		}
		return
	}

	httpx.JSON(w, 200, map[string]any{
		"format": format,
		"base64": base64.StdEncoding.EncodeToString(buf),
	})
}

// HandleTabScreenshot returns screenshot bytes for a tab identified by path ID.
//
// @Endpoint GET /tabs/{id}/screenshot
func (h *Handlers) HandleTabScreenshot(w http.ResponseWriter, r *http.Request) {
	tabID := r.PathValue("id")
	if tabID == "" {
		httpx.Error(w, 400, fmt.Errorf("tab id required"))
		return
	}

	q := r.URL.Query()
	q.Set("tabId", tabID)

	req := r.Clone(r.Context())
	u := *r.URL
	u.RawQuery = q.Encode()
	req.URL = &u

	h.HandleScreenshot(w, req)
}

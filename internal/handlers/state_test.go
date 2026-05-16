package handlers

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/pinchtab/pinchtab/internal/config"
)

func TestHandleTabState(t *testing.T) {
	h := New(&mockBridge{}, &config.RuntimeConfig{}, nil, nil, nil)
	tabID := "tab1"
	req := httptest.NewRequest("GET", "/tabs/"+tabID+"/state", nil)
	req.SetPathValue("tabId", tabID)
	w := httptest.NewRecorder()

	h.HandleTabState(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["tabId"] != tabID {
		t.Fatalf("expected tabId %s, got %v", tabID, got["tabId"])
	}
	if got["dialogPresent"] != false {
		t.Fatalf("expected dialogPresent=false, got %v", got["dialogPresent"])
	}
}

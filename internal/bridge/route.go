package bridge

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"strings"
	"sync"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	"github.com/pinchtab/pinchtab/internal/security"
)

// RouteAction names how an intercepted request should be handled.
type RouteAction string

const (
	RouteActionContinue RouteAction = "continue"
	RouteActionAbort    RouteAction = "abort"
	RouteActionFulfill  RouteAction = "fulfill"
)

// allowedFulfillContentTypes is the explicit safe-list of MIME types that may
// be used as the Content-Type of a fulfilled (mocked) response.
//
// Inclusion criterion: browsers do not execute scripts in this MIME. That is
// the security property fulfill needs — the response body runs in the
// response origin's security context, so anything the browser would parse
// and execute (HTML, JS, XHTML, SVG with embedded <script>, XSLT) becomes a
// scripted-injection vector in that origin.
//
// Implicitly denied (the absences are intentional, not an oversight):
//   - text/html, application/xhtml+xml — render and run scripts.
//   - text/javascript, application/javascript, application/x-javascript,
//     text/ecmascript, application/ecmascript — script files.
//   - image/svg+xml — SVG can carry inline <script>.
//   - text/xsl, application/xslt+xml — transform XML into HTML+JS at parse
//     time (note: application/xml itself is allowed because it does not
//     trigger XSLT processing on its own).
//   - application/x-shockwave-flash, application/x-msdownload — historic
//     auto-execute risk.
//
// Expanding this list is a deliberate security decision; do it with review,
// not as a casual addition.
var allowedFulfillContentTypes = map[string]struct{}{
	"application/json":         {},
	"application/xml":          {},
	"application/pdf":          {},
	"application/octet-stream": {},
	"text/plain":               {},
	"text/csv":                 {},
	"text/xml":                 {},
	"image/png":                {},
	"image/jpeg":               {},
	"image/gif":                {},
	"image/webp":               {},
	"video/mp4":                {},
	"video/webm":               {},
	"audio/mpeg":               {},
	"audio/ogg":                {},
	"audio/wav":                {},
}

// validResourceTypes is the CDP Network.ResourceType enum lowercased. Match
// is case-insensitive (see ruleMatches), so callers can pass "Script", "xhr",
// etc., but the rule must name a known category.
var validResourceTypes = map[string]struct{}{
	"document":           {},
	"stylesheet":         {},
	"image":              {},
	"media":              {},
	"font":               {},
	"script":             {},
	"texttrack":          {},
	"xhr":                {},
	"fetch":              {},
	"prefetch":           {},
	"eventsource":        {},
	"websocket":          {},
	"manifest":           {},
	"signedexchange":     {},
	"ping":               {},
	"cspviolationreport": {},
	"preflight":          {},
	"other":              {},
}

// IsFulfillContentTypeAllowed reports whether ct is on the safe-list and free
// of header-injection control bytes. Empty ct returns true — AddRule defaults
// it to application/json before storing.
func IsFulfillContentTypeAllowed(ct string) bool {
	if ct == "" {
		return true
	}
	if containsHeaderControlChar(ct) {
		return false
	}
	base := strings.TrimSpace(strings.ToLower(strings.SplitN(ct, ";", 2)[0]))
	_, ok := allowedFulfillContentTypes[base]
	return ok
}

// IsResourceTypeValid reports whether rt names a known CDP resource category.
// Empty rt is valid (means "no resource-type filter").
func IsResourceTypeValid(rt string) bool {
	if rt == "" {
		return true
	}
	_, ok := validResourceTypes[strings.ToLower(rt)]
	return ok
}

// normalizeHTTPMethod returns the upper-case form of m (trimmed) when it is a
// recognised HTTP method, and ok=false otherwise. Only methods the browser
// actually emits are accepted; custom verbs would never match a browser
// request anyway, so there's no point letting them through.
func normalizeHTTPMethod(m string) (string, bool) {
	upper := strings.ToUpper(strings.TrimSpace(m))
	switch upper {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "CONNECT", "TRACE":
		return upper, true
	}
	return "", false
}

// containsHeaderControlChar reports whether s contains any byte that would
// allow header injection if the string were spliced into an HTTP header value
// (CR, LF, NUL).
func containsHeaderControlChar(s string) bool {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\r', '\n', 0:
			return true
		}
	}
	return false
}

// RouteRule describes a single interception rule for a tab.
//
// Pattern matching semantics (deliberately asymmetric, mirrors the user-facing
// CLI ergonomics):
//
//   - No wildcards in Pattern → SUBSTRING match against the request URL.
//     "tracker.io" matches "https://tracker.io/x" and "https://x?ref=tracker.io".
//
//   - Pattern contains '*' or '?' → ANCHORED full-URL glob match.
//     "*.png" compiles to "^.*\.png$" and matches URLs ending in .png.
//     "*api*" matches any URL containing "api". To get substring-style
//     matching with a wildcard, wrap the pattern in '*'s on both sides.
//
// The asymmetry is intentional: bare strings are the common
// "block-this-domain" case where substring is what users mean; wildcards are
// the structural case (extension, host shape) where anchored full-URL is
// what they mean. ResourceType, when set, narrows matches to a specific CDP
// resource category (e.g. "script", "xhr", "image").
type RouteRule struct {
	Pattern      string      `json:"pattern"`
	Action       RouteAction `json:"action"`
	Body         string      `json:"body,omitempty"`
	ContentType  string      `json:"contentType,omitempty"`
	Status       int         `json:"status,omitempty"`
	ResourceType string      `json:"resourceType,omitempty"`

	// Method, when non-empty, narrows matches to the given HTTP method
	// (case-insensitive). Empty Method matches any method, with one exception:
	// fulfill rules skip OPTIONS preflights by default — fulfilling preflights
	// can break or bypass CORS, so the operator must explicitly set
	// Method="OPTIONS" to opt in.
	Method string `json:"method,omitempty"`

	// compiled is the precompiled regex for wildcard patterns. It is nil for
	// substring patterns (Pattern has no '*' or '?'). Set once at AddRule time
	// and read-only thereafter so the listener doesn't recompile per event.
	// Unexported so encoding/json skips it on the way out of /network/route.
	compiled *regexp.Regexp
}

// RouteManager tracks active per-tab interception rules. It enables CDP fetch
// interception lazily when the first rule is added and disables it when the
// last rule is removed.
type RouteManager struct {
	mu               sync.Mutex
	perTab           map[string]*tabRouteState
	allowedDomainsFn func() []string // nil ⇒ no allowlist enforcement

	// Fetch-domain coordination with proxy auth (see Bridge.tabSetup): while
	// rules own a tab's Fetch domain, the proxy-auth listener's blanket
	// ContinueRequest is suppressed and the route enable must keep
	// handleAuthRequests so challenges stay answerable.
	proxyAuthActive    func() bool                // nil ⇒ no proxy auth configured
	setPauseSuppressed func(tabID string, v bool) // nil ⇒ no coordination
}

// tabRouteState holds per-tab interception state. listenCtx, when non-nil, is
// derived from the tab's chromedp context and gates the listener; cancelling
// listenCancel stops dispatch (chromedp skips listeners with a done context)
// and is called when the last rule is removed or the tab closes.
type tabRouteState struct {
	rules        []RouteRule
	listenCtx    context.Context
	listenCancel context.CancelFunc
	fetchEnabled bool
}

// NewRouteManager constructs a RouteManager. allowedDomainsFn, when non-nil, is
// called at fulfill-time to decide whether the matched URL host is allowed to
// receive a fabricated response body (security.allowedDomains boundary).
// Pass nil to disable that check.
func NewRouteManager(allowedDomainsFn func() []string) *RouteManager {
	return &RouteManager{perTab: make(map[string]*tabRouteState), allowedDomainsFn: allowedDomainsFn}
}

// SetFetchAuthCoordination wires the proxy-auth coordination callbacks: the
// gate reporting whether proxy credentials are configured, and the per-tab
// pause-suppression setter on the owning Bridge.
func (rm *RouteManager) SetFetchAuthCoordination(proxyAuthActive func() bool, setPauseSuppressed func(tabID string, v bool)) {
	if rm == nil {
		return
	}
	rm.proxyAuthActive = proxyAuthActive
	rm.setPauseSuppressed = setPauseSuppressed
}

func (rm *RouteManager) proxyAuthOn() bool {
	return rm.proxyAuthActive != nil && rm.proxyAuthActive()
}

func (rm *RouteManager) suppressPause(tabID string, v bool) {
	if rm.setPauseSuppressed != nil {
		rm.setPauseSuppressed(tabID, v)
	}
}

// MaxFulfillBodyBytes caps the size of a fulfill rule's response body. The
// HTTP handler enforces this for early 400s; AddRule re-checks so non-HTTP
// callers (direct bridge users, future ipc) also benefit.
const MaxFulfillBodyBytes = 1 << 20 // 1 MiB

// MaxRulesPerTab caps how many interception rules a single tab may carry.
// Without a cap an attacker (or runaway agent) could install thousands of
// rules to consume memory and slow every paused request through a long
// per-event match loop. The number is generous for legitimate use — typical
// fixtures have a few rules — and conservative against abuse.
const MaxRulesPerTab = 100

// ErrTooManyRules is returned by AddRule when a tab already holds
// MaxRulesPerTab rules and the incoming rule is not a same-pattern replace.
var ErrTooManyRules = errors.New("too many interception rules on this tab")

// forbiddenFulfillSchemes lists URL schemes where fulfill must always be
// rejected regardless of the host allowlist. data:/javascript: are inline
// pseudo-URLs that don't traverse the network so a fulfill is meaningless;
// file:/blob:/ftp: bypass the web origin model in surprising ways; chrome:
// and chrome-extension: are privileged browser origins where forging a
// response is dangerous; about: should never be intercepted at all (about:
// blank in particular is special-cased earlier in the stack).
var forbiddenFulfillSchemes = map[string]struct{}{
	"javascript":       {},
	"data":             {},
	"file":             {},
	"blob":             {},
	"ftp":              {},
	"chrome":           {},
	"chrome-extension": {},
	"about":            {},
}

// ErrTabNotRouted is returned by Remove when the tab has no rule state
// registered with the manager — distinct from "tab found, pattern matched
// nothing" which returns (0, nil). Callers can map this to a 404 to
// differentiate from a benign no-op removal.
var ErrTabNotRouted = errors.New("tab has no interception rules registered")

// AddRule installs (or replaces, by Pattern) a rule for the given tab.
func (rm *RouteManager) AddRule(ctx context.Context, tabID string, rule RouteRule) error {
	if rm == nil {
		return fmt.Errorf("route manager not initialized")
	}
	if rule.Pattern == "" {
		return fmt.Errorf("pattern required")
	}
	if rule.Action == "" {
		rule.Action = RouteActionContinue
	}
	switch rule.Action {
	case RouteActionContinue, RouteActionAbort, RouteActionFulfill:
	default:
		return fmt.Errorf("invalid action %q", rule.Action)
	}
	if !IsResourceTypeValid(rule.ResourceType) {
		return fmt.Errorf("invalid resourceType %q", rule.ResourceType)
	}
	if rule.Method != "" {
		normalized, ok := normalizeHTTPMethod(rule.Method)
		if !ok {
			return fmt.Errorf("invalid method %q", rule.Method)
		}
		rule.Method = normalized
	}
	// Body cap, status range, and content-type validation apply regardless of
	// Action so non-HTTP callers (MCP, future ipc) can't smuggle malformed
	// values past the bridge by setting Action=abort/continue. Defaults
	// (Status=200, ContentType=application/json) are still applied only when
	// the rule actually uses them (fulfill).
	if len(rule.Body) > MaxFulfillBodyBytes {
		return fmt.Errorf("body exceeds %d bytes (cap)", MaxFulfillBodyBytes)
	}
	if rule.Status != 0 && (rule.Status < 100 || rule.Status > 599) {
		return fmt.Errorf("status %d out of HTTP range (100-599)", rule.Status)
	}
	if rule.ContentType != "" && !IsFulfillContentTypeAllowed(rule.ContentType) {
		return fmt.Errorf("contentType %q is not on the fulfill safe-list (or contains control chars)", rule.ContentType)
	}
	if rule.Action == RouteActionFulfill {
		if rule.Status == 0 {
			rule.Status = 200
		}
		if rule.ContentType == "" {
			rule.ContentType = "application/json"
		}
	}

	compiled, err := compileRulePattern(rule.Pattern)
	if err != nil {
		return fmt.Errorf("invalid pattern %q: %w", rule.Pattern, err)
	}
	rule.compiled = compiled

	rm.mu.Lock()
	state := rm.perTab[tabID]
	isNewState := state == nil
	if state == nil {
		state = &tabRouteState{}
		rm.perTab[tabID] = state
	}

	// Snapshot for rollback on fetch.Enable failure.
	priorRules := append([]RouteRule(nil), state.rules...)
	priorListenCtx := state.listenCtx
	priorListenCancel := state.listenCancel
	priorFetchEnabled := state.fetchEnabled

	replaced := false
	for i, r := range state.rules {
		if r.Pattern == rule.Pattern {
			state.rules[i] = rule
			replaced = true
			break
		}
	}
	if !replaced {
		if len(state.rules) >= MaxRulesPerTab {
			if isNewState {
				delete(rm.perTab, tabID)
			}
			rm.mu.Unlock()
			return fmt.Errorf("%w: cap is %d", ErrTooManyRules, MaxRulesPerTab)
		}
		state.rules = append(state.rules, rule)
	}

	needRegister := state.listenCancel == nil
	needEnable := !state.fetchEnabled
	if needRegister {
		state.listenCtx, state.listenCancel = context.WithCancel(ctx)
	}
	listenCtx := state.listenCtx
	rm.mu.Unlock()

	if needRegister {
		rm.registerListener(listenCtx, tabID)
	}
	if needEnable {
		// Suppress the proxy-auth listener's blanket continue BEFORE rules
		// take over dispatch, and keep handleAuthRequests on so proxy
		// challenges stay answerable while routes own the Fetch domain.
		rm.suppressPause(tabID, true)
		handleAuth := rm.proxyAuthOn()
		if err := chromedp.Run(ctx, chromedp.ActionFunc(func(c context.Context) error {
			return fetch.Enable().
				WithPatterns([]*fetch.RequestPattern{{URLPattern: "*"}}).
				WithHandleAuthRequests(handleAuth).
				Do(c)
		})); err != nil {
			rm.suppressPause(tabID, false)
			rm.rollbackAddRule(tabID, isNewState, needRegister, priorRules, priorListenCtx, priorListenCancel, priorFetchEnabled)
			return fmt.Errorf("fetch.enable: %w", err)
		}
		rm.mu.Lock()
		if s := rm.perTab[tabID]; s != nil {
			s.fetchEnabled = true
		}
		rm.mu.Unlock()
	}
	return nil
}

// rollbackAddRule restores the per-tab state captured before a failed AddRule.
// If we registered a fresh listener for this call, its context is cancelled so
// the no-op listener handle is released.
func (rm *RouteManager) rollbackAddRule(tabID string, isNewState, registeredListener bool, priorRules []RouteRule, priorListenCtx context.Context, priorListenCancel context.CancelFunc, priorFetchEnabled bool) {
	rm.mu.Lock()
	s := rm.perTab[tabID]
	if s == nil {
		rm.mu.Unlock()
		return
	}
	var newCancel context.CancelFunc
	if registeredListener {
		newCancel = s.listenCancel
		s.listenCtx = priorListenCtx
		s.listenCancel = priorListenCancel
	}
	s.rules = priorRules
	s.fetchEnabled = priorFetchEnabled
	if isNewState && len(s.rules) == 0 {
		delete(rm.perTab, tabID)
	}
	rm.mu.Unlock()

	if newCancel != nil {
		newCancel()
	}
}

// Remove deletes rules matching pattern. Empty pattern removes all rules for
// the tab. Returns the number of rules removed. When the last rule is removed,
// the listener context is cancelled and CDP fetch interception is disabled.
func (rm *RouteManager) Remove(ctx context.Context, tabID string, pattern string) (int, error) {
	if rm == nil {
		return 0, fmt.Errorf("route manager not initialized")
	}

	rm.mu.Lock()
	state := rm.perTab[tabID]
	if state == nil {
		rm.mu.Unlock()
		// Tab has no rule state at all — distinct from "rules exist but the
		// pattern matched nothing." The handler maps ErrTabNotRouted to 404.
		return 0, ErrTabNotRouted
	}

	removed := 0
	if pattern == "" {
		removed = len(state.rules)
		state.rules = nil
	} else {
		kept := state.rules[:0]
		for _, r := range state.rules {
			if r.Pattern == pattern {
				removed++
				continue
			}
			kept = append(kept, r)
		}
		state.rules = kept
	}

	teardown := len(state.rules) == 0
	wasEnabled := state.fetchEnabled
	cancel := state.listenCancel
	if teardown {
		state.fetchEnabled = false
		state.listenCancel = nil
		state.listenCtx = nil
		delete(rm.perTab, tabID)
	}
	rm.mu.Unlock()

	if teardown {
		if wasEnabled {
			if rm.proxyAuthOn() {
				// Hand the Fetch domain back to proxy auth instead of
				// disabling it (which would kill auth handling too).
				// Unsuppress first so no paused request goes unanswered.
				rm.suppressPause(tabID, false)
				if err := chromedp.Run(ctx, chromedp.ActionFunc(func(c context.Context) error {
					return fetch.Enable().WithHandleAuthRequests(true).Do(c)
				})); err != nil {
					slog.Debug("fetch re-enable for proxy auth failed during route teardown", "tabId", tabID, "err", err)
				}
			} else {
				if err := chromedp.Run(ctx, chromedp.ActionFunc(func(c context.Context) error {
					return fetch.Disable().Do(c)
				})); err != nil {
					slog.Debug("fetch.disable failed during route teardown", "tabId", tabID, "err", err)
				}
				rm.suppressPause(tabID, false)
			}
		} else {
			rm.suppressPause(tabID, false)
		}
		if cancel != nil {
			cancel()
		}
	}
	return removed, nil
}

// RemoveTab drops all rule state for a tab without issuing CDP calls. It is
// the cleanup hook fired by TabManager when a tab closes (manual close,
// eviction, auto-close, or Chrome reporting the target gone). When the tab's
// chromedp context is already canceled, fetch.Disable would fail anyway —
// canceling the listener context is the only meaningful step. Without this
// hook, perTab[tabID] and its cancel func would leak; if Chrome ever reused
// the target id, a stale entry would be found.
func (rm *RouteManager) RemoveTab(tabID string) {
	if rm == nil || tabID == "" {
		return
	}
	rm.mu.Lock()
	state := rm.perTab[tabID]
	if state == nil {
		rm.mu.Unlock()
		return
	}
	cancel := state.listenCancel
	delete(rm.perTab, tabID)
	rm.mu.Unlock()
	// Hand pause dispatch back even though the Bridge drops the whole flag in
	// its own onTabRemoved hook right after — RemoveTab must stay correct on
	// its own, not by courtesy of the caller's cleanup ordering.
	rm.suppressPause(tabID, false)
	if cancel != nil {
		cancel()
	}
}

// List returns the current rules for a tab.
func (rm *RouteManager) List(tabID string) []RouteRule {
	if rm == nil {
		return nil
	}
	rm.mu.Lock()
	defer rm.mu.Unlock()
	state := rm.perTab[tabID]
	if state == nil {
		return nil
	}
	out := make([]RouteRule, len(state.rules))
	copy(out, state.rules)
	return out
}

func (rm *RouteManager) registerListener(listenCtx context.Context, tabID string) {
	// Verify the context is target-bound. chromedp.ListenTarget on a
	// browser-level context (Target == nil) would broadcast to every tab —
	// we explicitly require the per-tab target so dispatch is session-scoped.
	if c := chromedp.FromContext(listenCtx); c == nil || c.Target == nil {
		slog.Warn("route listener not registered: chromedp context has no target", "tabId", tabID)
		return
	}
	chromedp.ListenTarget(listenCtx, func(ev interface{}) {
		if listenCtx.Err() != nil {
			return
		}
		e, ok := ev.(*fetch.EventRequestPaused)
		if !ok {
			return
		}
		eventResourceType := strings.ToLower(string(e.ResourceType))
		eventMethod := strings.ToUpper(strings.TrimSpace(e.Request.Method))
		rule, matched, hasRules := rm.match(tabID, e.Request.URL, eventResourceType, eventMethod)
		// Teardown in progress: rules drained but fetch.Disable not yet
		// landed. Skip dispatch — fetch.Disable will release pending requests.
		if !hasRules {
			return
		}
		go rm.dispatch(listenCtx, tabID, e, rule, matched)
	})
}

// dispatch issues the CDP response for a paused request. Errors are logged at
// Debug level — fetch operations frequently fail benignly when a tab navigates
// while a request is paused, and elevating those to Warn would be noisy.
func (rm *RouteManager) dispatch(listenCtx context.Context, tabID string, e *fetch.EventRequestPaused, rule RouteRule, matched bool) {
	if listenCtx.Err() != nil {
		return
	}
	executor := cdp.WithExecutor(listenCtx, chromedp.FromContext(listenCtx).Target)

	if !matched || rule.Action == RouteActionContinue {
		if err := fetch.ContinueRequest(e.RequestID).Do(executor); err != nil {
			slog.Debug("fetch.continueRequest failed", "tabId", tabID, "url", e.Request.URL, "err", err)
		}
		return
	}

	switch rule.Action {
	case RouteActionAbort:
		if err := fetch.FailRequest(e.RequestID, network.ErrorReasonBlockedByClient).Do(executor); err != nil {
			slog.Debug("fetch.failRequest failed", "tabId", tabID, "url", e.Request.URL, "err", err)
		}
	case RouteActionFulfill:
		if !rm.fulfillForgeryPermittedFor(e.Request.URL) {
			slog.Warn("route fulfill blocked: response forgery not permitted (allowlisted host or forbidden scheme)",
				"tabId", tabID,
				"url", e.Request.URL,
				"pattern", rule.Pattern,
			)
			if err := fetch.ContinueRequest(e.RequestID).Do(executor); err != nil {
				slog.Debug("fetch.continueRequest (fulfill fallthrough) failed", "tabId", tabID, "url", e.Request.URL, "err", err)
			}
			return
		}
		headers := []*fetch.HeaderEntry{{Name: "Content-Type", Value: rule.ContentType}}
		if err := fetch.FulfillRequest(e.RequestID, int64(rule.Status)).
			WithResponseHeaders(headers).
			WithBody(base64.StdEncoding.EncodeToString([]byte(rule.Body))).
			Do(executor); err != nil {
			slog.Debug("fetch.fulfillRequest failed", "tabId", tabID, "url", e.Request.URL, "err", err)
		}
	default:
		if err := fetch.ContinueRequest(e.RequestID).Do(executor); err != nil {
			slog.Debug("fetch.continueRequest (default) failed", "tabId", tabID, "url", e.Request.URL, "err", err)
		}
	}
}

// match looks for the first rule matching url + resourceType + method. The
// third return value (hasRules) is true iff the tab has any rules at all —
// callers use it to skip dispatch entirely during teardown windows.
//
// Method semantics:
//
//   - Rule.Method != ""   → strict method match (case-insensitive).
//   - Rule.Method == "" + non-OPTIONS event → match any method.
//   - Rule.Method == "" + OPTIONS event + Action == fulfill → SKIP. CORS
//     preflights deserve explicit opt-in: a fulfill that catches the
//     preflight without ACAO/ACAM/ACAH headers breaks the real request, and
//     a fulfill that fakes those headers bypasses CORS for the real call.
//     Operators who genuinely want to mock OPTIONS set Method:"OPTIONS".
//   - Rule.Method == "" + OPTIONS event + Action != fulfill → match.
//     Aborting/passing-through preflights is benign.
func (rm *RouteManager) match(tabID, url, resourceType, method string) (rule RouteRule, matched bool, hasRules bool) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	state := rm.perTab[tabID]
	if state == nil || len(state.rules) == 0 {
		return RouteRule{}, false, false
	}
	const optionsMethod = "OPTIONS"
	for _, r := range state.rules {
		if r.ResourceType != "" && !strings.EqualFold(r.ResourceType, resourceType) {
			continue
		}
		if r.Method != "" {
			if !strings.EqualFold(r.Method, method) {
				continue
			}
		} else if r.Action == RouteActionFulfill && method == optionsMethod {
			continue
		}
		if ruleMatchesURL(r, url) {
			return r, true, true
		}
	}
	return RouteRule{}, false, true
}

// fulfillForgeryPermittedFor reports whether forging a response (action
// fulfill) is permitted for rawURL. The name is deliberate: this is a
// permission check on RESPONSE FORGERY, not a generic "is this URL allowed"
// query, and it inverts the host-allowlist on purpose.
//
// Policy:
//
//  1. Special-scheme URLs (data:, javascript:, file:, blob:, ftp:, chrome:,
//     chrome-extension:, about:) are ALWAYS denied — fulfilling those either
//     makes no sense or escapes the web origin model in surprising ways.
//  2. With no allowlist configured (nil accessor or empty list) the policy
//     is inactive and forgery is permitted on all normal-scheme URLs.
//  3. Otherwise: forgery is BLOCKED on hosts listed in security.allowedDomains
//     and PERMITTED on all other hosts. Rationale: allowedDomains marks the
//     sensitive surfaces the operator has authorized the agent to interact
//     with (banking, email, internal SaaS) — exactly the origins where
//     injecting attacker-controlled responses is most damaging, because the
//     body executes in that origin's security context with access to its
//     cookies, localStorage, and DOM. Unlisted hosts are the typical mocking
//     targets (third-party APIs, CDNs, analytics endpoints) where response
//     forgery is a normal test/dev tool.
//
// Yes, this is intentionally the opposite of "is the host allowlisted." If
// you find yourself reading `!security.HostAllowed(...)` and reaching for the
// `!`, that is the policy.
func (rm *RouteManager) fulfillForgeryPermittedFor(rawURL string) bool {
	if isForbiddenFulfillScheme(rawURL) {
		return false
	}
	if rm.allowedDomainsFn == nil {
		return true
	}
	allow := rm.allowedDomainsFn()
	if len(allow) == 0 {
		return true
	}
	return !security.HostAllowed(rawURL, allow)
}

// isForbiddenFulfillScheme reports whether rawURL uses a scheme where
// fulfill must always be rejected (see forbiddenFulfillSchemes for the set
// and rationale). Unparseable URLs are treated as forbidden.
func isForbiddenFulfillScheme(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return true
	}
	scheme := strings.ToLower(strings.TrimSpace(parsed.Scheme))
	if scheme == "" {
		return false
	}
	_, forbidden := forbiddenFulfillSchemes[scheme]
	return forbidden
}

// ruleMatchesURL reports whether r matches url, using the precompiled regex
// when present (wildcard patterns) and a substring check otherwise. AddRule
// always populates r.compiled for wildcard patterns; the on-the-fly fallback
// here keeps the function correct when state is populated by other paths
// (e.g. unit tests) and is never hit in production.
func ruleMatchesURL(r RouteRule, url string) bool {
	if r.Pattern == "" {
		return false
	}
	if r.compiled != nil {
		return r.compiled.MatchString(url)
	}
	if strings.ContainsAny(r.Pattern, "*?") {
		return globMatch(r.Pattern, url)
	}
	return strings.Contains(url, r.Pattern)
}

// compileRulePattern returns the precompiled regex for wildcard patterns or
// nil for substring patterns. Errors only when a wildcard pattern fails to
// compile (escaped char issues).
func compileRulePattern(pattern string) (*regexp.Regexp, error) {
	if pattern == "" || !strings.ContainsAny(pattern, "*?") {
		return nil, nil
	}
	return globToRegex(pattern)
}

// globMatch is a convenience used by tests; production code uses
// ruleMatchesURL with the precompiled regex stored on the rule.
func globMatch(pattern, url string) bool {
	if pattern == "" {
		return false
	}
	if !strings.ContainsAny(pattern, "*?") {
		return strings.Contains(url, pattern)
	}
	re, err := globToRegex(pattern)
	if err != nil {
		return false
	}
	return re.MatchString(url)
}

func globToRegex(pattern string) (*regexp.Regexp, error) {
	var sb strings.Builder
	sb.WriteString("^")
	for _, r := range pattern {
		switch r {
		case '*':
			sb.WriteString(".*")
		case '?':
			sb.WriteString(".")
		case '.', '+', '(', ')', '[', ']', '{', '}', '|', '^', '$', '\\':
			sb.WriteRune('\\')
			sb.WriteRune(r)
		default:
			sb.WriteRune(r)
		}
	}
	sb.WriteString("$")
	return regexp.Compile(sb.String())
}

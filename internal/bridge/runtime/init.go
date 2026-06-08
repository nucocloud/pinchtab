package runtime

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"os"
	"os/exec"
	goruntime "runtime"
	"strings"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/pinchtab/pinchtab/internal/browsers"
	_ "github.com/pinchtab/pinchtab/internal/browsers/builtin"
	"github.com/pinchtab/pinchtab/internal/browsers/runtimekit"
	"github.com/pinchtab/pinchtab/internal/config"
	"github.com/pinchtab/pinchtab/internal/config/geo"
	"github.com/pinchtab/pinchtab/internal/stealth"
)

var (
	runtimeGOOS              = goruntime.GOOS
	osGeteuid                = os.Geteuid
	containerMarkerPath      = "/.dockerenv"
	geoProviderForConfigFunc = geoProviderForConfig
)

const launchGeoLookupTimeout = 3 * time.Second

type launchGeoAlignment struct {
	info  geo.Info
	flags []string
	env   []string
}

type Hooks struct {
	SetHumanRandSeed        func(int64)
	IsProfileLockError      func(string) bool
	ClearStaleProfileLocks  func(profileDir, errMsg string) (bool, error)
	ConfigureBrowserProcess func(*exec.Cmd)
	// QuarantineCorruptedProfile moves profileDir aside and recreates an
	// empty dir at the same path. Used to recover from silent CDP attach
	// failures (observed with CloakBrowser when the profile dir holds
	// state it cannot ingest). Returns the quarantine path on success.
	QuarantineCorruptedProfile func(profileDir string) (string, error)
}

// InitBrowser initializes a browser for a Bridge instance.
//
// When cfg.CDPAttachURL is set, this skips launching a browser process and
// connects to the externally-managed browser at that browser-level CDP
// WebSocket URL. The returned cancel funcs only release the chromedp
// allocator + browser context; the external browser process is left alive.
func InitBrowser(cfg *config.RuntimeConfig, bundle *stealth.Bundle, hooks Hooks) (context.Context, context.CancelFunc, context.Context, context.CancelFunc, stealth.LaunchMode, error) {
	if cfg != nil && strings.TrimSpace(cfg.CDPAttachURL) != "" {
		return initBrowserFromExistingCDP(cfg, bundle)
	}

	targetBinary := runtimekit.FindBrowserBinary(config.NormalizeBrowser(cfg.DefaultBrowser))
	if strings.TrimSpace(cfg.BrowserBinary) != "" {
		targetBinary = strings.TrimSpace(cfg.BrowserBinary)
	}
	slog.Info("starting browser initialization", "headless", cfg.Headless, "profile", cfg.ProfileDir, "binary", targetBinary)
	browserID := config.NormalizeBrowser(cfg.DefaultBrowser)
	if b, ok := browsers.Get(browserID); ok {
		tcfg := browsers.TargetConfig{
			Provider: browserID,
			Binary:   targetBinary,
		}
		if err := b.ValidateTarget(tcfg); err != nil {
			return nil, nil, nil, nil, stealth.LaunchModeUninitialized, missingBrowserBinaryError(cfg)
		}
	}

	bundle = ensureStealthBundle(cfg, bundle)
	geoAlignment, err := resolveLaunchGeoAlignment(context.Background(), cfg)
	if err != nil {
		return nil, nil, nil, nil, stealth.LaunchModeUninitialized, fmt.Errorf("failed to resolve proxy geo alignment: %w", err)
	}
	allocCtx, allocCancel, opts, debugPort, err := setupAllocator(cfg, bundle, hooks, geoAlignment)
	if err != nil {
		return nil, nil, nil, nil, stealth.LaunchModeUninitialized, err
	}
	browserCtx, browserCancel, launchMode, err := startBrowser(allocCtx, cfg, bundle, opts, debugPort, hooks, geoAlignment)
	if err != nil {
		allocCancel()
		slog.Error("browser initialization failed", "headless", cfg.Headless, "error", err.Error())
		return nil, nil, nil, nil, stealth.LaunchModeUninitialized, fmt.Errorf("failed to start browser: %w", err)
	}

	if proxyAuthEnabled(cfg.Proxy) {
		if err := enableProxyAuth(browserCtx, cfg.Proxy); err != nil {
			browserCancel()
			allocCancel()
			return nil, nil, nil, nil, stealth.LaunchModeUninitialized, fmt.Errorf("failed to enable proxy auth: %w", err)
		}
	}

	slog.Info("browser initialized successfully", "headless", cfg.Headless, "profile", cfg.ProfileDir)
	return allocCtx, allocCancel, browserCtx, browserCancel, launchMode, nil
}

// initBrowserFromExistingCDP attaches the bridge to a browser that is already
// running outside pinchtab (e.g. the user's everyday browser launched with
// --remote-debugging-port=NNNN). No process is spawned and no profile lock
// is taken. The allocator is a chromedp remote allocator; the returned
// cancel funcs release only the chromedp side, never the external browser.
func initBrowserFromExistingCDP(cfg *config.RuntimeConfig, bundle *stealth.Bundle) (context.Context, context.CancelFunc, context.Context, context.CancelFunc, stealth.LaunchMode, error) {
	browserID, _ := config.ParseBrowser(cfg.DefaultBrowser, cfg.BrowsersAvailable)
	if browserID == "" {
		browserID = config.NormalizeBrowser(cfg.DefaultBrowser)
	}
	if b, ok := browsers.Get(browserID); ok && !b.SupportsRemoteCDP() {
		return nil, nil, nil, nil, stealth.LaunchModeUninitialized,
			fmt.Errorf("provider %q does not support remote CDP attach", browserID)
	}

	wsURL := strings.TrimSpace(cfg.CDPAttachURL)
	slog.Info("attaching to existing browser via CDP", "cdpUrl", wsURL)

	remoteAllocCtx, remoteAllocCancel := chromedp.NewRemoteAllocator(context.Background(), wsURL)
	browserCtx, browserCancel := chromedp.NewContext(remoteAllocCtx)

	// Touch the browser so we fail fast if the CDP URL is unreachable. We
	// intentionally do NOT inject the stealth/UA script here — the user's
	// browser is theirs, and rewriting its launch contract would be both
	// surprising and likely break extensions, profile features, and
	// already-open tabs.
	if err := chromedp.Run(browserCtx, chromedp.ActionFunc(func(ctx context.Context) error {
		return nil
	})); err != nil {
		browserCancel()
		remoteAllocCancel()
		return nil, nil, nil, nil, stealth.LaunchModeUninitialized, fmt.Errorf("failed to attach to CDP at %s: %w", wsURL, err)
	}

	slog.Info("attached to existing browser via CDP", "cdpUrl", wsURL)
	return remoteAllocCtx, remoteAllocCancel, browserCtx, browserCancel, stealth.LaunchModeAttached, nil
}

// FindBrowserBinary exposes the launch-time browser discovery used by runtime
// initialization so diagnostics can report against the same search path.
func FindBrowserBinary() string {
	return runtimekit.FindBrowserBinary("chrome")
}

type providerLaunchPlan struct {
	browser browsers.Browser
	args    []string
	env     []string
	binary  string
}

func providerLaunchConfig(cfg *config.RuntimeConfig, binary string, debugPort int) browsers.LaunchConfig {
	return runtimekit.LaunchConfigFromRuntime(cfg, binary, debugPort, launchNeedsNoSandbox())
}

func resolveProviderLaunchPlan(cfg *config.RuntimeConfig, launchCfg browsers.LaunchConfig) (providerLaunchPlan, error) {
	plan, err := runtimekit.ResolveProviderLaunchPlan(cfg, launchCfg)
	if err != nil {
		return providerLaunchPlan{}, fmt.Errorf("%s launch args: %w", config.NormalizeBrowser(cfg.DefaultBrowser), err)
	}
	return providerLaunchPlan{
		browser: plan.Browser,
		args:    plan.Args,
		env:     plan.Env,
		binary:  plan.Binary,
	}, nil
}

func appendExecAllocatorFlag(opts []chromedp.ExecAllocatorOption, flag string) []chromedp.ExecAllocatorOption {
	name := strings.TrimPrefix(flag, "--")
	if parts := strings.SplitN(name, "=", 2); len(parts) == 2 {
		return append(opts, chromedp.Flag(parts[0], parts[1]))
	}
	return append(opts, chromedp.Flag(name, true))
}

func ensureStealthBundle(cfg *config.RuntimeConfig, bundle *stealth.Bundle) *stealth.Bundle {
	if bundle != nil {
		return bundle
	}
	return stealth.NewBundle(cfg, cryptoRandSeed())
}

func appendExecAllocatorFlags(opts []chromedp.ExecAllocatorOption, flags []string) []chromedp.ExecAllocatorOption {
	for _, flag := range flags {
		opts = appendExecAllocatorFlag(opts, flag)
	}
	return opts
}

func setupAllocator(cfg *config.RuntimeConfig, bundle *stealth.Bundle, hooks Hooks, geoAlignment launchGeoAlignment) (context.Context, context.CancelFunc, []chromedp.ExecAllocatorOption, int, error) {
	opts := []chromedp.ExecAllocatorOption{
		chromedp.NoFirstRun,
		chromedp.NoDefaultBrowserCheck,
	}
	debugPort := 0
	if cfg.BrowserDebugPort > 0 {
		debugPort = cfg.BrowserDebugPort
	} else if port, err := findFreePort(cfg.InstancePortStart, cfg.InstancePortEnd); err == nil {
		debugPort = port
	}
	binary := strings.TrimSpace(cfg.BrowserBinary)
	if binary == "" {
		binary = runtimekit.FindBrowserBinary(config.NormalizeBrowser(cfg.DefaultBrowser))
	}
	plan, err := resolveProviderLaunchPlan(cfg, runtimekit.LaunchConfigFromRuntime(cfg, binary, debugPort, launchNeedsNoSandbox()))
	if err != nil {
		return nil, nil, nil, 0, err
	}
	opts = appendExecAllocatorFlags(opts, plan.args)
	opts = appendExecAllocatorFlags(opts, bundle.Launch.Args)
	opts = appendExecAllocatorFlags(opts, config.BrowserProxyFlags(cfg.Proxy))
	opts = appendExecAllocatorFlags(opts, geoAlignment.flags)

	if plan.binary != "" {
		opts = append(opts, chromedp.ExecPath(plan.binary))
	}

	if cfg.Headless {
		opts = append(opts, chromedp.Flag("headless", "new"))
		opts = append(opts, chromedp.Flag("hide-scrollbars", true))
		opts = append(opts, chromedp.Flag("mute-audio", true))
		opts = append(opts, chromedp.Flag("disable-vulkan", true))
		// Use swiftshader (software GPU) for compositing under --headless=new.
		// We deliberately do NOT pass --disable-gpu here: in new-headless
		// mode Page.captureScreenshot routes through the compositor, which
		// needs a GPU backend — disabling the GPU process leaves the
		// compositor with no backend and screenshot calls hang past the
		// action timeout.
		opts = append(opts, chromedp.Flag("use-angle", "swiftshader"))
		// Chromium 121+ requires this opt-in to actually load the
		// swiftshader backend; without it, --use-angle=swiftshader is
		// silently ignored and the compositor has no backend, which
		// manifests as Page.captureScreenshot/printToPDF hanging.
		opts = append(opts, chromedp.Flag("enable-unsafe-swiftshader", true))
		// --in-process-gpu used to be enabled here as a perf optimization
		// (saves one OS process and ~50-150MB per instance). Chrome stable
		// patch updates have repeatedly regressed it for the headless=new
		// + swiftshader combo: a GPU code crash takes the browser with it
		// ~500ms after init, surfacing as `context canceled` on the first
		// CreateTab. We now leave it off by default. Users who know their
		// Chrome build is healthy and want the memory savings can opt in
		// via `browser.extraFlags = "--in-process-gpu"`. DisableInProcessGPU
		// is still honored as a kill switch by the crash-recovery path.
	} else {
		opts = append(opts, chromedp.Flag("headless", false))
	}

	if validPaths := existingExtensionPaths(cfg.ExtensionPaths); len(validPaths) > 0 {
		joined := strings.Join(validPaths, ",")
		opts = append(opts, chromedp.Flag("disable-extensions", false))
		opts = append(opts, chromedp.Flag("load-extension", joined))
		opts = append(opts, chromedp.Flag("disable-extensions-except", joined))
		slog.Info("loading extensions", "paths", joined)
	} else {
		opts = append(opts, chromedp.Flag("disable-extensions", true))
	}

	if cfg.ProfileDir != "" {
		opts = append(opts, chromedp.UserDataDir(cfg.ProfileDir))
	}

	w, h := randomWindowSize()
	opts = append(opts, chromedp.WindowSize(w, h))

	if cfg.Timezone != "" {
		opts = append(opts, chromedp.Flag("tz", cfg.Timezone))
	}

	extraFlags := config.AllowedBrowserExtraFlags(cfg.BrowserExtraFlags)
	if cfg.DisableInProcessGPU {
		// Kill switch from the crash-recovery path: strip a user-supplied
		// --in-process-gpu so a crash loop can't repeat after retry.
		extraFlags = stripInProcessGPUFlag(extraFlags)
	}
	opts = appendExecAllocatorFlags(opts, extraFlags)
	for _, flag := range appendBrowserCompatibilityFlags(nil) {
		opts = appendExecAllocatorFlag(opts, flag)
	}

	opts = append(opts, chromedp.CombinedOutput(newPrefixedLogWriter(os.Stdout, "browser")))
	opts = append(opts, chromedp.ModifyCmdFunc(func(cmd *exec.Cmd) {
		if len(plan.env) > 0 || len(geoAlignment.env) > 0 {
			if cmd.Env == nil {
				cmd.Env = os.Environ()
			}
			if len(plan.env) > 0 {
				cmd.Env = mergeGeoEnv(cmd.Env, plan.env)
			}
			cmd.Env = mergeGeoEnv(cmd.Env, geoAlignment.env)
		}
		if hooks.ConfigureBrowserProcess != nil {
			hooks.ConfigureBrowserProcess(cmd)
		}
	}))

	ctx, cancel := context.WithCancel(context.Background())
	return ctx, cancel, opts, debugPort, nil
}

func browserLaunchArgs(headless bool) []string {
	return runtimekit.BaseFlagArgs("chrome", headless)
}

func BaseBrowserFlagArgs() []string {
	return browserLaunchArgs(false)
}

func appendBrowserCompatibilityFlags(args []string) []string {
	if launchNeedsNoSandbox() {
		return append(args, "--no-sandbox")
	}
	return args
}

func launchNeedsNoSandbox() bool {
	_, err := os.Stat(containerMarkerPath)
	return runtimekit.ChromeNeedsNoSandbox(runtimeGOOS, osGeteuid(), err == nil)
}

func BuildBrowserArgs(cfg *config.RuntimeConfig, port int) []string {
	geoAlignment, err := resolveLaunchGeoAlignment(context.Background(), cfg)
	if err != nil {
		args, _, buildErr := buildBrowserArgsWithBundle(cfg, nil, port, launchGeoAlignment{})
		if buildErr != nil {
			return nil
		}
		return args
	}
	args, _, err := buildBrowserArgsWithBundle(cfg, nil, port, geoAlignment)
	if err != nil {
		return nil
	}
	return args
}

func existingExtensionPaths(paths []string) []string {
	if len(paths) == 0 {
		return nil
	}
	validPaths := make([]string, 0, len(paths))
	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			validPaths = append(validPaths, path)
		}
	}
	return validPaths
}

func buildBrowserArgsWithBundle(cfg *config.RuntimeConfig, bundle *stealth.Bundle, port int, geoAlignment launchGeoAlignment) ([]string, []string, error) {
	bundle = ensureStealthBundle(cfg, bundle)
	binary := strings.TrimSpace(cfg.BrowserBinary)
	if binary == "" {
		binary = runtimekit.FindBrowserBinary(config.NormalizeBrowser(cfg.DefaultBrowser))
	}
	plan, err := resolveProviderLaunchPlan(cfg, runtimekit.LaunchConfigFromRuntime(cfg, binary, port, launchNeedsNoSandbox()))
	if err != nil {
		return nil, nil, err
	}
	args := append([]string(nil), plan.args...)

	args = append(args, bundle.Launch.Args...)
	args = append(args, config.BrowserProxyFlags(cfg.Proxy)...)
	args = append(args, geoAlignment.flags...)

	env := append([]string(nil), plan.env...)
	return args, env, nil
}

func CloakBrowserFlagArgs(cfg *config.RuntimeConfig) []string {
	return runtimekit.CloakBrowserFlagArgs(cfg)
}

func applyStartupStealth(ctx context.Context, cfg *config.RuntimeConfig, bundle *stealth.Bundle, script string) error {
	if !config.PinchTabStealthDefaultsDisabled(cfg) {
		ua := ""
		if bundle != nil {
			ua = bundle.LaunchUserAgent()
		}
		if err := stealth.ApplyTargetEmulation(ctx, cfg, ua); err != nil {
			return err
		}
	}
	if strings.TrimSpace(script) == "" {
		return nil
	}
	return injectedScript(ctx, script)
}

func stripInProcessGPUFlag(flags []string) []string {
	out := flags[:0]
	for _, f := range flags {
		name := strings.SplitN(f, "=", 2)[0]
		if strings.EqualFold(name, "--in-process-gpu") {
			continue
		}
		out = append(out, f)
	}
	return out
}

func missingBrowserBinaryError(cfg *config.RuntimeConfig) error {
	browserID := config.NormalizeBrowser(cfg.DefaultBrowser)
	if b, ok := browsers.Get(browserID); ok {
		name := b.DisplayName()
		return fmt.Errorf("%s binary not found: set browser.binary to the %s binary path", strings.ToLower(name), name)
	}
	return fmt.Errorf("browser binary not found: set browser.binary in config")
}

func injectedScript(ctx context.Context, script string) error {
	return chromedp.FromContext(ctx).Target.Execute(ctx,
		"Page.addScriptToEvaluateOnNewDocument",
		map[string]interface{}{
			"source": script,
		}, nil)
}

func randomWindowSize() (int, int) {
	sizes := [][2]int{
		{1920, 1080}, {1366, 768}, {1536, 864}, {1440, 900},
		{1280, 720}, {1600, 900}, {2560, 1440}, {1280, 800},
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(sizes))))
	idx := 0
	if err == nil {
		idx = int(n.Int64())
	}
	s := sizes[idx]
	return s[0], s[1]
}

type prefixedLogWriter struct {
	dst    io.Writer
	prefix string
	buf    []byte
}

func newPrefixedLogWriter(dst io.Writer, prefix string) *prefixedLogWriter {
	return &prefixedLogWriter{dst: dst, prefix: prefix, buf: make([]byte, 0, 1024)}
}

func (w *prefixedLogWriter) Write(p []byte) (int, error) {
	w.buf = append(w.buf, p...)
	for {
		idx := bytes.IndexByte(w.buf, '\n')
		if idx < 0 {
			break
		}
		line := w.buf[:idx]
		w.buf = w.buf[idx+1:]
		if len(line) > 0 {
			if _, err := fmt.Fprintf(w.dst, "%s: %s\n", w.prefix, string(line)); err != nil {
				return 0, err
			}
		}
	}
	return len(p), nil
}

func geoProviderForConfig(cfg *config.RuntimeConfig) geo.Provider {
	if cfg == nil || cfg.Proxy.Geo == nil || cfg.Proxy.Geo.IsZero() {
		return geo.Noop{}
	}
	return geo.Static{Info: cfg.Proxy.GeoInfo()}
}

func resolveLaunchGeoAlignment(parent context.Context, cfg *config.RuntimeConfig) (launchGeoAlignment, error) {
	if cfg == nil || cfg.Proxy.IsZero() || cfg.Proxy.Geo == nil || cfg.Proxy.Geo.IsZero() {
		return launchGeoAlignment{}, nil
	}
	if !config.CloakBrowserActive(cfg) {
		return launchGeoAlignment{}, nil
	}
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, launchGeoLookupTimeout)
	defer cancel()

	info, err := geoProviderForConfigFunc(cfg).Lookup(ctx, "")
	if err != nil {
		return launchGeoAlignment{}, err
	}
	flags, env := applyGeoAlignment(cfg.DefaultBrowser, info, cfg.Cloak)
	return launchGeoAlignment{
		info:  info,
		flags: flags,
		env:   env,
	}, nil
}

// mergeGeoEnv overlays additions over base by key; base is not mutated.
func mergeGeoEnv(base, additions []string) []string {
	if len(additions) == 0 {
		return base
	}
	out := make([]string, 0, len(base)+len(additions))
	overrideKeys := make(map[string]struct{}, len(additions))
	for _, kv := range additions {
		if eq := strings.IndexByte(kv, '='); eq > 0 {
			overrideKeys[kv[:eq]] = struct{}{}
		}
	}
	for _, kv := range base {
		eq := strings.IndexByte(kv, '=')
		if eq > 0 {
			if _, replace := overrideKeys[kv[:eq]]; replace {
				continue
			}
		}
		out = append(out, kv)
	}
	out = append(out, additions...)
	return out
}

func cryptoRandSeed() int64 {
	n, err := rand.Int(rand.Reader, big.NewInt(1000000000))
	if err != nil {
		return 42
	}
	return n.Int64()
}

// defaultBrowserToLaunchMode maps the DefaultBrowser identifier to the appropriate
// LaunchMode. ghost-chrome uses LaunchModeAuto; everything else (chrome, cloak, ...)
// uses LaunchModeChrome.
func defaultBrowserToLaunchMode(defaultBrowser string) browsers.LaunchMode {
	if config.NormalizeBrowser(defaultBrowser) == config.BrowserGhostChrome {
		return browsers.LaunchModeAuto
	}
	return browsers.LaunchModeChrome
}

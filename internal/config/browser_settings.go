package config

import "strings"

// BrowserBinary returns the serialized browser binary override.
func (fc *FileConfig) BrowserBinary() string {
	if fc == nil {
		return ""
	}
	return strings.TrimSpace(fc.Browser.BrowserBinary)
}

// BrowserDebugPort returns the serialized remote-debugging port override.
func (fc *FileConfig) BrowserDebugPort() int {
	if fc == nil || fc.Browser.BrowserDebugPort == nil {
		return 0
	}
	return *fc.Browser.BrowserDebugPort
}

// SetBrowserDebugPort stores the serialized remote-debugging port override.
func (fc *FileConfig) SetBrowserDebugPort(port int) {
	if fc == nil {
		return
	}
	if port <= 0 {
		fc.Browser.BrowserDebugPort = nil
		return
	}
	fc.Browser.BrowserDebugPort = intPtrIfPositive(port)
}

// BrowserExtraFlags returns the serialized browser extra-flags string.
func (fc *FileConfig) BrowserExtraFlags() string {
	if fc == nil {
		return ""
	}
	return fc.Browser.BrowserExtraFlags
}

// BrowserVersion returns the serialized browser version override.
func (fc *FileConfig) BrowserVersion() string {
	if fc == nil {
		return ""
	}
	return fc.Browser.BrowserVersion
}

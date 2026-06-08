//go:build windows

package bridge

import "os/exec"

// configureBrowserProcess is a no-op on Windows.
func configureBrowserProcess(_ *exec.Cmd) {}

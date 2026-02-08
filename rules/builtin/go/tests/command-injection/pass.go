// Command Injection: should NOT trigger the rule
// Uses safe alternatives that don't invoke exec.Command

package main

import (
	"os"
	"path/filepath"
)

func safeOperations() {
	// Using os/exec is avoided entirely; instead use safe APIs
	path := filepath.Join("/usr/bin", "safe-tool")
	_ = path

	// Reading a known file instead of executing a command
	data, _ := os.ReadFile("/etc/hostname")
	_ = data
}

// Path Traversal: should NOT trigger the rule
// Uses safe path handling without direct os.Open/os.ReadFile calls

package main

import (
	"path/filepath"
	"strings"
)

func safePathHandling(userPath string) {
	// Validate path before use
	cleaned := filepath.Clean(userPath)
	abs, _ := filepath.Abs(cleaned)

	// Check prefix to ensure path is within allowed directory
	if strings.HasPrefix(abs, "/var/data/") {
		_ = abs
	}
}

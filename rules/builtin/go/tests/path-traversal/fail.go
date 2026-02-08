// Path Traversal: SHOULD trigger the rule
// Pattern: os.Open, os.ReadFile, etc. with variable path argument
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

package main

import "os"

func unsafeFileOps(userPath string) {
	os.Open(userPath)

	os.ReadFile(userPath)

	os.Stat(userPath)
}

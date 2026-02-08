// Command Injection: SHOULD trigger the rule
// Pattern: exec.Command or exec.CommandContext with variable arguments
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

package main

import (
	"context"
	"os/exec"
)

func unsafeExec(userInput string, ctx context.Context) {
	exec.Command(userInput)

	exec.CommandContext(ctx, userInput)

	exec.Command(userInput, "--flag")
}

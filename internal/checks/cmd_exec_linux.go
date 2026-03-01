//go:build linux

package checks

import (
	"bytes"
	"os/exec"
	"time"

	"host-config-review-scanner/internal/parser"
)

// CmdExecChecker runs CMD_EXEC type checks (Linux).
type CmdExecChecker struct{}

func (c *CmdExecChecker) Execute(item parser.CustomItem) Result {
	if item.Cmd == "" {
		return Result{Status: StatusError, Output: "no cmd specified"}
	}

	// Run in bash with a timeout
	ctx_cmd := exec.Command("/bin/bash", "-c", item.Cmd)
	var stdout, stderr bytes.Buffer
	ctx_cmd.Stdout = &stdout
	ctx_cmd.Stderr = &stderr

	// Use a channel-based timeout
	done := make(chan error, 1)
	go func() {
		done <- ctx_cmd.Run()
	}()

	select {
	case err := <-done:
		output := stdout.String()
		if err != nil {
			// Some scripts exit with non-zero but still produce valid output
			if output == "" {
				output = stderr.String()
			}
		}
		if matchesExpect(output, item.Expect) {
			return Result{Status: StatusPass, Output: output}
		}
		return Result{Status: StatusFail, Output: output}
	case <-time.After(120 * time.Second):
		if ctx_cmd.Process != nil {
			ctx_cmd.Process.Kill()
		}
		return Result{Status: StatusError, Output: "command timed out after 120s"}
	}
}

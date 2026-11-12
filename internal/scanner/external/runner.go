package external

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
)

// RunResult holds the result of running an external tool
type RunResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// toolEnv holds environment overrides applied to every run of a scanner
// binary, including its version probe.
var toolEnv = map[string][]string{
	// Semgrep checks for a newer release on every invocation. That costs a
	// network round trip per scan and prints "A new version of Semgrep is
	// available", which ended up in the manifest where the version belongs.
	// This is Semgrep's documented switch for the check.
	"semgrep": {"SEMGREP_ENABLE_VERSION_CHECK=0"},
}

// toolCommand prepares a scanner process. Tools without overrides inherit the
// environment unchanged; for the others the override is appended, and os/exec
// keeps the last value of a duplicated key, so it wins over an inherited one.
func toolCommand(ctx context.Context, name string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, name, args...)
	if extra := toolEnv[filepath.Base(name)]; len(extra) > 0 {
		cmd.Env = append(os.Environ(), extra...)
	}
	return cmd
}

// RunTool runs an external CLI tool and returns its output.
// Does not panic on non-zero exit codes — just returns it in ExitCode.
func RunTool(ctx context.Context, name string, args ...string) (RunResult, error) {
	cmd := toolCommand(ctx, name, args...)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	// CommandContext reports a killed process as *exec.ExitError. Treating that
	// like an ordinary scanner exit code would turn a timeout/cancellation into
	// a successful zero-finding scan and violate the full-audit fail-closed
	// contract. Preserve the captured output for diagnostics and propagate the
	// context error so the orchestrator records timed_out/failed explicitly.
	if ctxErr := ctx.Err(); ctxErr != nil {
		return RunResult{
			Stdout:   outBuf.String(),
			Stderr:   errBuf.String(),
			ExitCode: -1,
		}, ctxErr
	}
	exitCode := 0
	if exitErr, ok := err.(*exec.ExitError); ok {
		exitCode = exitErr.ExitCode()
		_ = err // non-zero exit code is not an error, the tool works that way
	} else if err != nil {
		return RunResult{}, err
	}
	return RunResult{
		Stdout:   outBuf.String(),
		Stderr:   errBuf.String(),
		ExitCode: exitCode,
	}, nil
}

// IsInstalled checks whether a tool is available in PATH
func IsInstalled(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

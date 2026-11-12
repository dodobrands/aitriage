package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"time"

	rt "github.com/dodobrands/aitriage/internal/runtime"
)

var containerSequence uint64

// dockerExecutable is indirect so process-lifecycle tests can use a controlled
// child process on every OS without installing Docker.
var dockerExecutable = rt.DockerExecutable

func managedContainerName(kind string) string {
	return fmt.Sprintf("aitriage-%s-%d-%d", kind, os.Getpid(), atomic.AddUint64(&containerSequence, 1))
}

func ensureReportsDir(hostRoot string) (string, error) {
	reports := filepath.Join(hostRoot, "aitriage-reports")
	if err := os.MkdirAll(reports, 0o700); err != nil {
		return "", fmt.Errorf("cannot create reports directory: %w", err)
	}
	if err := os.Chmod(reports, 0o700); err != nil {
		return "", fmt.Errorf("cannot secure reports directory: %w", err)
	}
	return reports, nil
}

// runManagedContainer owns the complete foreground lifecycle. SIGINT/SIGTERM
// stop the exact AITriage container, wait for cleanup, and preserve ordinary
// child exit errors. This prevents orphaned Web, MCP, and agent containers.
func runManagedContainer(parent context.Context, args []string, name string) error {
	ctx, stopSignals := signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	docker := dockerExecutable()
	cmd := exec.Command(docker, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if name != "" {
			_ = exec.CommandContext(cleanupCtx, docker, "stop", "--time", "10", name).Run()
		}
		// The container was stopped on purpose, so the docker client's exit
		// status after the signal says nothing about the audit; it is only
		// reaped here so no process is left behind.
		select {
		case waitErr := <-done:
			_ = waitErr
		case <-cleanupCtx.Done():
			if name != "" {
				_ = exec.Command(docker, "rm", "-f", name).Run()
			}
			_ = cmd.Process.Kill()
			waitErr := <-done
			_ = waitErr
		}
		if parent.Err() != nil {
			return parent.Err()
		}
		return nil
	}
}

// requireContainerRuntime is the common fail-closed launch gate for MCP, Web
// and CLI audits. A command never falls back to a partial native run when the
// verified image is missing or unhealthy.
func requireContainerRuntime(ctx context.Context) error {
	report := rt.Status(ctx, rt.NewDocker(), Version)
	if report.OK {
		return nil
	}
	if report.Err == nil {
		return fmt.Errorf("AITriage full scanner runtime is not ready; run `aitriage setup --full`")
	}
	message := report.Err.Message
	if report.Err.ActionURL != "" {
		message += "\n" + report.Err.ActionURL
	}
	retry := report.Err.RetryCommand
	if retry == "" {
		retry = "aitriage setup --full"
	}
	return fmt.Errorf("%s\nNext: %s", message, retry)
}

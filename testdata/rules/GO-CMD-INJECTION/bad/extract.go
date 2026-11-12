package tools

import (
	"context"
	"fmt"
	"os/exec"
)

func Extract(ctx context.Context, path string) error {
	script := fmt.Sprintf("tar -xf %s -C /tmp/out", path)
	// ruleid: GO-CMD-INJECTION
	return exec.CommandContext(ctx, "/bin/bash", "-c", script).Run()
}

package main

import (
	"context"
	"fmt"
	"path/filepath"

	mcpserver "github.com/dodobrands/aitriage/internal/agent/mcp"
	rt "github.com/dodobrands/aitriage/internal/runtime"
	"github.com/spf13/cobra"
)

var (
	serveTransport string
	servePort      int
	serveProfile   string
	serveScanRoot  string
	serveRuntime   string
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start AITriage as an MCP server",
	Long: `Expose AITriage security tools via Model Context Protocol for Claude Code, Cursor, etc.

Profiles:
  full       All tools, including the mutating securecoder_ignore. No path
             confinement unless --scan-root is set. (default)
  safe  Safe-by-default mode for safe-profile installs: only read-only scan/analysis
             tools; securecoder_ignore is not exposed. Requires --scan-root and
             confines every path (including symlinks) to that directory.`,
	RunE: runServe,
}

func init() {
	rootCmd.AddCommand(serveCmd)
	serveCmd.Flags().StringVar(&serveTransport, "transport", "stdio", "Transport type: stdio or sse")
	serveCmd.Flags().IntVar(&servePort, "port", 8080, "Port for SSE transport")
	serveCmd.Flags().StringVar(&serveProfile, "profile", "full", "Tool profile: full or safe")
	serveCmd.Flags().StringVar(&serveScanRoot, "scan-root", "", "Confine all path arguments to this directory (required for safe profile)")
	serveCmd.Flags().StringVar(&serveRuntime, "runtime", "native", "Where to run: native (in-process) or container (verified Docker image with the full scanner bundle)")
}

func runServe(cmd *cobra.Command, args []string) error {
	profile, err := mcpserver.ParseProfile(serveProfile)
	if err != nil {
		return err
	}
	if profile == mcpserver.ProfileSafe && serveScanRoot == "" {
		return fmt.Errorf("the safe profile requires --scan-root to confine scans to the project directory")
	}

	// Container runtime: re-launch the MCP server inside the verified image so
	// the full scanner bundle is guaranteed. stdio is passed straight through to
	// the host agent; no TTY is allocated.
	if serveRuntime == "container" {
		return serveInContainer(cmd.Context(), profile)
	}

	srv, err := mcpserver.NewServerWithConfig(Version, mcpserver.Config{
		Profile:  profile,
		ScanRoot: serveScanRoot,
	})
	if err != nil {
		return err
	}
	return srv.Run(cmd.Context(), serveTransport, servePort)
}

// containerServeArgs builds the `docker run` argv that launches the MCP server
// inside the container. The repository root mounts read-only at /workspace, the
// reports directory read-write, and the inner server runs natively (the scanner
// bundle is present in the image) confined to /workspace.
func containerServeArgs(image, hostRoot, profile, cache, name string) []string {
	reports := filepath.Join(hostRoot, "aitriage-reports")
	return rt.DockerRunArgs(rt.RunSpec{
		Image:       image,
		Name:        name,
		User:        rt.HostUser(),
		HostRoot:    hostRoot,
		ReportsDir:  reports,
		CacheDir:    cache,
		Interactive: true,
		TTY:         false,
		EnvSet: []string{
			"AITRIAGE_RUNTIME=container",
			"AITRIAGE_CACHE_DIR=/workspace/aitriage-reports/cache",
			// The baseline and dismissal tools write here, because the
			// project itself is read-only.
			"AITRIAGE_REPORTS_DIR=/workspace/aitriage-reports",
		},
		Argv: []string{"serve", "--runtime", "native", "--profile", profile, "--scan-root", "/workspace"},
	})
}

func serveInContainer(ctx context.Context, profile mcpserver.Profile) error {
	if err := requireContainerRuntime(ctx); err != nil {
		return err
	}
	hostRoot, err := resolveProjectRoot([]string{serveScanRoot})
	if err != nil {
		return err
	}
	if _, err := ensureReportsDir(hostRoot); err != nil {
		return err
	}
	cache, err := rt.EnsureScannerCacheDir()
	if err != nil {
		return err
	}
	name := managedContainerName("mcp")
	args := containerServeArgs(rt.ResolveImage(Version), hostRoot, string(profile), cache, name)
	return runManagedContainer(ctx, args, name)
}

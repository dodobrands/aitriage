package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	rt "github.com/dodobrands/aitriage/internal/runtime"
	"github.com/dodobrands/aitriage/internal/server"
	"github.com/spf13/cobra"
)

var (
	webPort       int
	webHostPrefix string
	webRuntime    string
	webProject    string
)

var webCmd = &cobra.Command{
	Use:   "web",
	Short: "Start AITriage Web UI (browser-based security dashboard)",
	Long: `Start the local AITriage browser dashboard for one project.

By default AITriage launches the verified scanner container, mounts the selected
project read-only, publishes Web only on localhost, and writes all state under
<project>/aitriage-reports/. Run "aitriage setup --full" once before starting.

Native mode is intended only for AITriage development.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Container runtime: launch the verified image (full scanner bundle) with
		// the Web port published and the project mounted. The in-process server
		// logic below is unchanged and used for native/dev.
		if webRuntime == "container" {
			return webInContainer(cmd.Context())
		}

		addr := webListenAddress(webPort, os.Getenv("AITRIAGE_RUNTIME"))
		fmt.Printf("\n  AITriage Web UI\n")
		fmt.Printf("  ──────────────────────────────────────\n")
		fmt.Printf("  Open → http://localhost:%d\n", webPort)
		if webHostPrefix != "" {
			fmt.Printf("  Host prefix: %s (scanning host paths transparently)\n", webHostPrefix)
		}
		fmt.Printf("  ──────────────────────────────────────\n\n")

		// Removed auto-open browser to prevent opening :8080 during frontend dev on :5174

		prefix := webHostPrefix
		if prefix == "" {
			prefix = os.Getenv("HOST_PREFIX")
		}

		dbPath := os.Getenv("DB_PATH")
		if dbPath == "" {
			projectRoot, err := resolveProjectRoot([]string{webProject})
			if err != nil {
				return err
			}
			reports, err := ensureReportsDir(projectRoot)
			if err != nil {
				return err
			}
			if err := os.Setenv("AITRIAGE_REPORTS_DIR", reports); err != nil {
				return fmt.Errorf("configure reports directory: %w", err)
			}
			dbDir := filepath.Join(reports, "web")
			if err := os.MkdirAll(dbDir, 0o700); err != nil {
				return fmt.Errorf("failed to create config dir: %w", err)
			}
			dbPath = filepath.Join(dbDir, "aitriage.db")
		} else {
			dbDir := filepath.Dir(dbPath)
			if err := os.MkdirAll(dbDir, 0o700); err != nil {
				return fmt.Errorf("failed to create config dir: %w", err)
			}
		}
		if err := os.Chmod(filepath.Dir(dbPath), 0o700); err != nil {
			return fmt.Errorf("failed to secure config dir: %w", err)
		}

		db, err := server.InitDB(dbPath)
		if err != nil {
			return fmt.Errorf("failed to init db: %w", err)
		}
		defer func() { _ = db.Close() }()

		srv := server.NewServer(prefix, db)
		return srv.Listen(addr)
	},
}

// The container's port is published on loopback by the managed launcher. Native
// mode has no enforced auth and must never publish the dashboard to the LAN.
func webListenAddress(port int, runtime string) string {
	if runtime == "container" {
		return fmt.Sprintf("0.0.0.0:%d", port)
	}
	return fmt.Sprintf("127.0.0.1:%d", port)
}

func init() {
	webCmd.Flags().IntVar(&webPort, "port", 8080, "Port to listen on")
	webCmd.Flags().StringVar(&webHostPrefix, "host-prefix", "", "Prefix added to scan paths (empty = paths used as-is)")
	webCmd.Flags().StringVar(&webRuntime, "runtime", "container", "Where to run: container (default, verified scanner bundle) or native (development only)")
	webCmd.Flags().StringVar(&webProject, "project", ".", "Project root to mount when --runtime container")
	rootCmd.AddCommand(webCmd)
}

// webContainerArgs builds the `docker run` argv for the container Web UI: the
// project root mounts read-only at /workspace, reports read-write, and the Web
// port is published. Reused by the test to lock the launch contract.
func webContainerArgs(image, hostRoot, cache string, port int) []string {
	reports := filepath.Join(hostRoot, "aitriage-reports")
	spec := rt.RunSpec{
		Image:       image,
		User:        rt.HostUser(),
		Name:        fmt.Sprintf("aitriage-web-%d", port),
		HostRoot:    hostRoot,
		ReportsDir:  reports,
		Interactive: false,
		TTY:         false,
		CacheDir:    cache,
		Ports:       []string{fmt.Sprintf("127.0.0.1:%d:8080", port)},
		EnvPassed:   agentEnvAllowlist,
		EnvSet: []string{
			"AITRIAGE_RUNTIME=container",
			"AITRIAGE_CACHE_DIR=/workspace/aitriage-reports/cache",
			"AITRIAGE_REPORTS_DIR=/workspace/aitriage-reports",
			"DB_PATH=/workspace/aitriage-reports/web/aitriage.db",
		},
		Argv: []string{"web", "--runtime", "native", "--port", "8080", "--host-prefix", "/workspace"},
	}
	return rt.DockerRunArgs(spec)
}

func webInContainer(ctx context.Context) error {
	if err := requireContainerRuntime(ctx); err != nil {
		return err
	}
	hostRoot, err := resolveProjectRoot([]string{webProject})
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
	fmt.Printf("\n  AITriage Web UI (container)\n")
	fmt.Printf("  ──────────────────────────────────────\n")
	fmt.Printf("  Open → http://localhost:%d\n", webPort)
	fmt.Printf("  Project: %s (mounted read-only at /workspace)\n", hostRoot)
	fmt.Printf("  Stop: press Ctrl-C\n")
	fmt.Printf("  ──────────────────────────────────────\n\n")

	args := webContainerArgs(rt.ResolveImage(Version), hostRoot, cache, webPort)
	return runManagedContainer(ctx, args, fmt.Sprintf("aitriage-web-%d", webPort))
}

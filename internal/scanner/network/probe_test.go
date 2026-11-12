package network

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestProbeHost(t *testing.T) {
	// Start a local TCP server to test port probing
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start local TCP server: %v", err)
	}
	defer func() { _ = listener.Close() }()

	// Get the port it was assigned
	addr := listener.Addr().String()
	parts := strings.Split(addr, ":")
	portStr := parts[len(parts)-1]

	// Create a goroutine to accept connection so it doesn't block indefinitely
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	// We can't guarantee `ProbeHost` will scan our random port if we just do fullScan=false,
	// because `ProbeHost` scans a specific set of common ports or full 65535 ports.
	// We should test `probePort` directly, or patch commonPorts for testing.
	// Since `probePort` is unexported, we can call it.

	var p int
	_, _ = fmt.Sscanf(portStr, "%d", &p)

	finding := probePort("127.0.0.1", p, "TestService", 1*time.Second)
	if finding == nil {
		t.Fatalf("Expected probePort to find the open port %d, got nil", p)
		return
	}

	if finding.Port != p {
		t.Errorf("Expected finding port %d, got %d", p, finding.Port)
	}
	if finding.Target != "127.0.0.1" {
		t.Errorf("Expected target 127.0.0.1, got %s", finding.Target)
	}
}

// stubLookup replaces DNS resolution for the duration of a test.
func stubLookup(t *testing.T, fn func(string) ([]string, error)) {
	t.Helper()
	original := lookupHost
	lookupHost = fn
	t.Cleanup(func() { lookupHost = original })
}

func unresolvable(host string) ([]string, error) {
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

// A name that does not resolve was not probed. On CI every Compose service
// name fails to resolve, and each one used to become a MEDIUM "port-53"
// finding that went through AI triage.
func TestProbeHostDoesNotReportUnresolvableHost(t *testing.T) {
	stubLookup(t, unresolvable)

	if findings := ProbeHost("db", false); len(findings) != 0 {
		t.Fatalf("unresolvable host produced findings: %+v", findings)
	}
}

func TestProbeDockerCompose(t *testing.T) {
	stubLookup(t, unresolvable)

	// A real listener stands in for a published Compose port.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = listener.Close() }()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	port := listener.Addr().(*net.TCPAddr).Port

	tempDir := t.TempDir()
	composeContent := fmt.Sprintf("services:\n  db:\n    image: postgres\n  web:\n    image: nginx\n    ports:\n      - \"%d:80\"\n", port)
	if err := os.WriteFile(filepath.Join(tempDir, "docker-compose.yml"), []byte(composeContent), 0644); err != nil {
		t.Fatalf("Failed to write docker-compose.yml: %v", err)
	}

	findings := ProbeDockerCompose(tempDir, false)

	foundPublished := false
	for _, f := range findings {
		if f.Service == "DNS" || strings.Contains(f.Message, "resolve") {
			t.Errorf("unresolvable service name reported as a finding: %+v", f)
		}
		if f.Target == "127.0.0.1" && f.Port == port {
			foundPublished = true
		}
	}
	if !foundPublished {
		t.Errorf("published port %d was not reported: %+v", port, findings)
	}
}

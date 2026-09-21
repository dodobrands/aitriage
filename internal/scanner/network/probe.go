package network

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

type NetworkFinding struct {
	Target   string `json:"target"`
	Port     int    `json:"port"`
	Service  string `json:"service"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

// Map of common ports and their typical services
var commonPorts = map[int]string{
	21:    "FTP",
	22:    "SSH",
	23:    "Telnet",
	25:    "SMTP",
	80:    "HTTP",
	443:   "HTTPS",
	3306:  "MySQL",
	5432:  "PostgreSQL",
	27017: "MongoDB",
	6379:  "Redis",
	11211: "Memcached",
	9200:  "Elasticsearch",
	8080:  "HTTP (alt)",
	8443:  "HTTPS (alt)",
	5000:  "Flask/Django/ASP.NET",
	3000:  "Node/React",
	4000:  "Dev server",
	9090:  "Prometheus",
	9091:  "Pushgateway",
	2181:  "Zookeeper",
	9092:  "Kafka",
	5672:  "RabbitMQ",
	15672: "RabbitMQ UI",
	4200:  "Angular Dev",
	8888:  "Jupyter",
	50070: "Hadoop NameNode",
}

// highRiskPorts are databases and services that should never be internet-exposed
var highRiskPorts = map[int]bool{
	3306: true, 5432: true, 27017: true, 6379: true,
	11211: true, 9200: true, 2181: true, 9092: true,
	50070: true, 22: true, 3389: true,
}

// criticalPorts are plaintext / legacy protocols
var criticalPorts = map[int]bool{
	21: true, 23: true, 25: true,
}

// TargetDiscovery searches for potential network targets in the project.
func FindTargets(projectPath string) []string {
	targets := make(map[string]bool)
	targets["127.0.0.1"] = true // Always scan localhost

	// Scan for common infra patterns in yaml, env, and config files
	extensions := map[string]bool{
		".yaml": true, ".yml": true, ".env": true, ".conf": true, ".json": true, ".go": true,
	}

	_ = filepath.WalkDir(projectPath, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			if d != nil && d.IsDir() && (d.Name() == ".git" || d.Name() == "node_modules") {
				return filepath.SkipDir
			}
			return nil
		}
		if extensions[filepath.Ext(path)] {
			content, err := os.ReadFile(path)
			if err == nil {
				// Search for IPs and localhost variants

				lines := strings.Split(string(content), "\n")
				for _, line := range lines {
					if strings.Contains(line, "127.0.0.1") {
						targets["127.0.0.1"] = true
					}
					// Very rough extraction for demo purposes
					if strings.Contains(line, "http") || strings.Contains(line, "host") || strings.Contains(line, "addr") {
						// Look for anything that looks like a hostname in quotes or after =
						parts := strings.FieldsFunc(line, func(r rune) bool {
							return r == '"' || r == '\'' || r == '=' || r == ':' || r == '/' || r == ' '
						})
						for _, p := range parts {
							p = strings.TrimSpace(p)
							if len(p) > 2 && (strings.Contains(p, ".") || p == "localhost" || p == "db") {
								// Basic validation: must not be a file path or a common word
								if !strings.Contains(p, "/") && !strings.HasPrefix(p, "0.") {
									targets[p] = true
								}
							}
						}
					}
				}
			}
		}
		return nil
	})

	var result []string
	for t := range targets {
		// Filter out noisy common words that might be caught
		if t == "localhost" || t == "127.0.0.1" || strings.Contains(t, ".") {
			result = append(result, t)
		}
	}
	sort.Strings(result)
	return result
}

// ProbeHost scans a target host to identify exposed services.
// If fullScan is true, scans all 65535 ports (slower, ~30-60s).
// If fullScan is false, only scans well-known common ports (~0.5s).
func ProbeHost(target string, fullScan bool) []NetworkFinding {
	if target == "" {
		return nil
	}

	// Normalize target
	if target == "localhost" || target == "." {
		target = "127.0.0.1"
	}

	var findings []NetworkFinding
	var mu sync.Mutex

	// DNS resolution for hostnames
	if target != "127.0.0.1" && net.ParseIP(target) == nil {
		ips, err := net.LookupHost(target)
		if err == nil && len(ips) > 0 {
			findings = append(findings, NetworkFinding{
				Target:   target,
				Port:     53,
				Service:  "DNS",
				Severity: "INFO",
				Message:  fmt.Sprintf("Resolved %s → %v", target, ips),
			})
		} else if err != nil {
			findings = append(findings, NetworkFinding{
				Target:   target,
				Port:     53,
				Service:  "DNS",
				Severity: "MEDIUM",
				Message:  fmt.Sprintf("Failed to resolve %s: %v", target, err),
			})
		}
	}

	timeout := 500 * time.Millisecond

	if !fullScan {
		// Fast path: only common ports
		var wg sync.WaitGroup
		for port, service := range commonPorts {
			wg.Add(1)
			go func(p int, srv string) {
				defer wg.Done()
				f := probePort(target, p, srv, timeout)
				if f != nil {
					mu.Lock()
					findings = append(findings, *f)
					mu.Unlock()
				}
			}(port, service)
		}
		wg.Wait()
	} else {
		// Full scan: all 65535 ports with concurrency limit
		timeout = 300 * time.Millisecond
		sem := make(chan struct{}, 512) // max 512 concurrent goroutines
		var wg sync.WaitGroup
		for p := 1; p <= 65535; p++ {
			wg.Add(1)
			sem <- struct{}{}
			go func(port int) {
				defer wg.Done()
				defer func() { <-sem }()
				svc, ok := commonPorts[port]
				if !ok {
					svc = "unknown"
				}
				f := probePort(target, port, svc, timeout)
				if f != nil {
					mu.Lock()
					findings = append(findings, *f)
					mu.Unlock()
				}
			}(p)
		}
		wg.Wait()
	}

	// Sort by port for stable output
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].Port < findings[j].Port
	})

	return findings
}

// probePort attempts a TCP connection to target:port and returns a finding if open.
func probePort(target string, port int, service string, timeout time.Duration) *NetworkFinding {
	address := net.JoinHostPort(target, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return nil
	}
	severity := "INFO"
	if highRiskPorts[port] {
		severity = "HIGH"
	}
	if criticalPorts[port] {
		severity = "CRITICAL"
	}

	banner := ""
	if severity == "HIGH" || severity == "CRITICAL" || port == 5432 || port == 3306 {
		// Basic banner grabbing
		_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		buf := make([]byte, 256)
		n, _ := conn.Read(buf)
		if n > 0 {
			// clean non-printable chars roughly
			var builder strings.Builder
			builder.Grow(n)
			for _, b := range buf[:n] {
				if b >= 32 && b <= 126 {
					builder.WriteByte(b)
				}
			}
			if builder.Len() > 0 {
				banner = fmt.Sprintf(" [Banner: %s]", builder.String())
			}
		}
	}
	if conn != nil {
		_ = conn.Close()
	}

	msg := fmt.Sprintf("Port %d open — service: %s%s", port, service, banner)
	if severity == "HIGH" || severity == "CRITICAL" {
		msg = fmt.Sprintf("EXPOSED: Port %d (%s) is publicly reachable. Apply network ACLs/firewall immediately. Target: %s%s", port, service, target, banner)
	}

	return &NetworkFinding{
		Target:   target,
		Port:     port,
		Service:  service,
		Severity: severity,
		Message:  msg,
	}
}

type dockerCompose struct {
	Services map[string]struct {
		Image string   `yaml:"image"`
		Ports []string `yaml:"ports"`
	} `yaml:"services"`
}

// ProbeDockerCompose searches for docker-compose.yml in the project path and probes extracted services/ports.
func ProbeDockerCompose(projectPath string, fullScan bool) []NetworkFinding {
	if projectPath == "" {
		return nil
	}

	composeFiles := []string{"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}
	var foundPath string
	for _, cf := range composeFiles {
		p := filepath.Join(projectPath, cf)
		if _, err := os.Stat(p); err == nil {
			foundPath = p
			break
		}
	}

	if foundPath == "" {
		return nil
	}

	b, err := os.ReadFile(foundPath)
	if err != nil {
		return nil
	}

	var dc dockerCompose
	if err := yaml.Unmarshal(b, &dc); err != nil {
		return nil
	}

	var findings []NetworkFinding
	var mu sync.Mutex
	var wg sync.WaitGroup

	for serviceName, svc := range dc.Services {
		wg.Add(1)
		go func(name string, ports []string) {
			defer wg.Done()

			// 1. Probe the service name itself (fast path to check if DNS resolves inside a container network)
			hostFindings := ProbeHost(name, false)

			mu.Lock()
			findings = append(findings, hostFindings...)
			mu.Unlock()

			// 2. Probe localhost for mapped ports
			for _, portMapping := range ports {
				// Port mapping can be "8080:80" or "127.0.0.1:8080:80" or "80"
				parts := strings.Split(portMapping, ":")
				hostPortStr := ""
				if len(parts) >= 2 {
					if len(parts) == 2 {
						hostPortStr = parts[0]
					} else {
						hostPortStr = parts[len(parts)-2]
					}
				} else if len(parts) == 1 {
					hostPortStr = parts[0]
				}

				hostPortStr = strings.Split(hostPortStr, "/")[0]
				hostPortStr = strings.TrimSpace(hostPortStr)

				port, err := strconv.Atoi(hostPortStr)
				if err == nil && port > 0 {
					serviceDesc := fmt.Sprintf("Docker Compose mapping for %s", name)
					f := probePort("127.0.0.1", port, serviceDesc, 500*time.Millisecond)
					if f != nil {
						mu.Lock()
						findings = append(findings, *f)
						mu.Unlock()
					}
				}
			}
		}(serviceName, svc.Ports)
	}

	wg.Wait()

	// Deduplicate and sort
	var unique []NetworkFinding
	seen := make(map[string]bool)
	for _, f := range findings {
		key := fmt.Sprintf("%s:%d", f.Target, f.Port)
		if !seen[key] {
			seen[key] = true
			unique = append(unique, f)
		}
	}

	sort.Slice(unique, func(i, j int) bool {
		return unique[i].Port < unique[j].Port
	})

	return unique
}

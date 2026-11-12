package deployaudit

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/dodobrands/aitriage/internal/scanner/external"
	"gopkg.in/yaml.v3"
)

type DeployFinding struct {
	File     string `json:"file"`
	Line     int    `json:"line"`
	Issue    string `json:"issue"`
	Severity string `json:"severity"`
	Evidence string `json:"evidence"`
	Advice   string `json:"advice"`
}

// AuditDeployFiles checks deployment files for security issues.
func AuditDeployFiles(projectPath string) ([]DeployFinding, error) {
	var findings []DeployFinding
	// The same scope decision as every other scanner: .gitignore,
	// .aitriageignore and vendored or generated trees.
	scope := external.NewScopeFilter(projectPath)

	err := filepath.WalkDir(projectPath, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			if d != nil && d.IsDir() && (d.Name() == ".git" || d.Name() == "node_modules" || d.Name() == "vendor") {
				return filepath.SkipDir
			}
			if err == nil && d.IsDir() && !inScope(scope, projectPath, path) {
				return filepath.SkipDir
			}
			return nil
		}
		if !inScope(scope, projectPath, path) {
			return nil
		}

		lowerName := strings.ToLower(d.Name())

		// Dockerfile
		if lowerName == "dockerfile" || strings.HasSuffix(lowerName, ".dockerfile") {
			if f, err := auditDockerfile(path); err == nil {
				findings = append(findings, f...)
			}
		}

		// Compose / Kubernetes / General YAML
		if strings.HasSuffix(lowerName, ".yaml") || strings.HasSuffix(lowerName, ".yml") {
			if lowerName == "docker-compose.yml" || lowerName == "docker-compose.yaml" {
				if f, err := auditCompose(path); err == nil {
					findings = append(findings, f...)
				}
			} else {
				if f, err := auditKubernetes(path); err == nil {
					findings = append(findings, f...)
				}
			}
		}

		// Nginx. A .conf extension says nothing about the program that reads
		// the file (Apache, supervisord, redis and PostgreSQL use it too), so
		// auditNginx decides by content.
		if strings.HasSuffix(lowerName, ".conf") {
			if f, err := auditNginx(path); err == nil {
				findings = append(findings, f...)
			}
		}

		// Makefile
		if lowerName == "makefile" || lowerName == "gnumakefile" {
			if f, err := auditMakefile(path); err == nil {
				findings = append(findings, f...)
			}
		}

		return nil
	})

	if err != nil {
		return findings, fmt.Errorf("failed to walk deploy files: %v", err)
	}

	return findings, nil
}

// inScope applies the project scope filter to a walked path. The filter gets
// the root-relative path: where the checkout itself lives (a parent directory
// called build or dist, as on some CI runners) must not decide what inside it
// is in scope.
func inScope(scope *external.ScopeFilter, root, path string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return true
	}
	return scope.InScope(rel)
}

func auditDockerfile(path string) ([]DeployFinding, error) {
	var findings []DeployFinding
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Check: running as root
		if strings.HasPrefix(line, "USER root") || (strings.HasPrefix(line, "USER") && !strings.Contains(line, "USER ")) {
			findings = append(findings, DeployFinding{
				File: path, Line: lineNum,
				Issue: "dockerfile_root_user", Severity: "HIGH",
				Evidence: line,
				Advice:   "Add USER nonroot or create a dedicated user. Running as root in containers is a security risk.",
			})
		}

		// Check: ADD instead of COPY (ADD can expand URLs)
		if strings.HasPrefix(line, "ADD ") && !strings.Contains(line, ".tar") {
			findings = append(findings, DeployFinding{
				File: path, Line: lineNum,
				Issue: "dockerfile_add_instead_of_copy", Severity: "LOW",
				Evidence: line,
				Advice:   "Prefer COPY over ADD unless you need URL fetching or tar extraction.",
			})
		}

		// Check: hardcoded secrets in ENV
		if strings.HasPrefix(line, "ENV ") && (strings.Contains(line, "PASSWORD") ||
			strings.Contains(line, "SECRET") || strings.Contains(line, "API_KEY")) {
			findings = append(findings, DeployFinding{
				File: path, Line: lineNum,
				Issue: "dockerfile_hardcoded_secret", Severity: "CRITICAL",
				Evidence: fmt.Sprintf("%.50s...", line),
				Advice:   "Never hardcode secrets in Dockerfile ENV. Use --secret or runtime env injection.",
			})
		}
	}
	return findings, nil
}

func walkYamlNode(node *yaml.Node, path string, checkFunc func(*yaml.Node, *yaml.Node)) {
	if node.Kind == yaml.DocumentNode {
		for _, child := range node.Content {
			walkYamlNode(child, path, checkFunc)
		}
		return
	}
	if node.Kind == yaml.MappingNode {
		for i := 0; i < len(node.Content); i += 2 {
			keyNode := node.Content[i]
			valNode := node.Content[i+1]
			checkFunc(keyNode, valNode)
			walkYamlNode(valNode, path, checkFunc)
		}
	}
	if node.Kind == yaml.SequenceNode {
		for _, child := range node.Content {
			walkYamlNode(child, path, checkFunc)
		}
	}
}

func auditCompose(path string) ([]DeployFinding, error) {
	var findings []DeployFinding
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, err // invalid yaml
	}

	walkYamlNode(&root, path, func(key, val *yaml.Node) {
		lowerKey := strings.ToLower(key.Value)

		// Check for hardcoded secrets
		if strings.Contains(lowerKey, "password") || strings.Contains(lowerKey, "secret") {
			if val.Kind == yaml.ScalarNode {
				valStr := val.Value
				if valStr != "" && !strings.Contains(valStr, "${") {
					findings = append(findings, DeployFinding{
						File: path, Line: key.Line,
						Issue: "compose_hardcoded_secret", Severity: "CRITICAL",
						Evidence: fmt.Sprintf("%s: %.20s", key.Value, valStr),
						Advice:   "Use environment variable substitution: ${MY_PASSWORD}",
					})
				}
			}
		}

		// Check for privileged mode
		if lowerKey == "privileged" && val.Kind == yaml.ScalarNode {
			if strings.ToLower(val.Value) == "true" {
				findings = append(findings, DeployFinding{
					File: path, Line: key.Line,
					Issue: "compose_privileged_mode", Severity: "HIGH",
					Evidence: "privileged: true",
					Advice:   "Remove privileged: true. Grant only specific capabilities with cap_add instead.",
				})
			}
		}
	})

	return findings, nil
}

var (
	// nginxMarker matches blocks and directives that only nginx uses. Anchoring
	// at the start of a line keeps comments ("# location of the log") out.
	nginxMarker = regexp.MustCompile(`(?m)^\s*(?:(?:http|server)\s*\{|location\s+\S|upstream\s+\S+\s*\{|server_tokens\s)`)
	// nginxHTTPBlock is the http block that only a main configuration has;
	// conf.d snippets hold server blocks that the main file includes.
	nginxHTTPBlock = regexp.MustCompile(`(?m)^\s*http\s*\{`)
	// apacheMarker matches Apache httpd configuration. Apache directives are
	// case-insensitive, and its ServerTokens has no underscore, unlike nginx's
	// server_tokens.
	apacheMarker = regexp.MustCompile(`(?mi)^\s*(?:<VirtualHost|<Directory|ServerTokens\s)`)
)

// classifyNginx reports whether a *.conf file is nginx configuration and, if
// so, whether it is a main configuration (named nginx.conf or holding the http
// block) rather than a snippet.
func classifyNginx(path, content string) (isNginx, isMain bool) {
	if apacheMarker.MatchString(content) {
		return false, false
	}
	isMain = strings.EqualFold(filepath.Base(path), "nginx.conf") || nginxHTTPBlock.MatchString(content)
	return isMain || nginxMarker.MatchString(content), isMain
}

// auditNginx checks an nginx configuration. Files that are not nginx
// configuration return no findings: every *.conf used to be audited as nginx,
// so an Apache or supervisord config was reported as missing nginx directives.
//
// Directives that are present but wrong (user root, server_tokens on) are
// reported in any nginx file. Directives that are absent are reported only
// for the main configuration: a conf.d snippet is not expected to repeat what
// the http block already sets.
func auditNginx(path string) ([]DeployFinding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	content := string(data)
	isNginx, isMain := classifyNginx(path, content)
	if !isNginx {
		return nil, nil
	}

	var findings []DeployFinding
	scanner := bufio.NewScanner(strings.NewReader(content))
	lineNum := 0
	hasServerTokensOff := false
	hasXFrameOptions := false
	hasCSP := false

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		lower := strings.ToLower(line)

		if strings.HasPrefix(lower, "user root;") || strings.HasPrefix(lower, "user root ") {
			findings = append(findings, DeployFinding{
				File: path, Line: lineNum,
				Issue: "nginx_runs_as_root", Severity: "CRITICAL",
				Evidence: line,
				Advice:   "Nginx configured to run as root. Change user directive to a non-privileged user like 'nginx' or 'www-data'.",
			})
		}
		if strings.Contains(lower, "server_tokens on;") {
			findings = append(findings, DeployFinding{
				File: path, Line: lineNum,
				Issue: "nginx_server_tokens_on", Severity: "LOW",
				Evidence: line,
				Advice:   "server_tokens on exposes Nginx version. Set to off to reduce information disclosure.",
			})
		}
		if strings.Contains(lower, "server_tokens off;") {
			hasServerTokensOff = true
		}
		if strings.Contains(lower, "x-frame-options") {
			hasXFrameOptions = true
		}
		if strings.Contains(lower, "content-security-policy") {
			hasCSP = true
		}
	}

	if !isMain {
		return findings, nil
	}
	if !hasServerTokensOff {
		findings = append(findings, DeployFinding{
			File: path, Line: 1,
			Issue: "nginx_missing_server_tokens_off", Severity: "LOW",
			Evidence: "Whole file",
			Advice:   "Missing 'server_tokens off;' directive. It's recommended to hide Nginx version.",
		})
	}
	if !hasXFrameOptions {
		findings = append(findings, DeployFinding{
			File: path, Line: 1,
			Issue: "nginx_missing_xframe_options", Severity: "MEDIUM",
			Evidence: "Whole file",
			Advice:   "Missing 'add_header X-Frame-Options SAMEORIGIN;'. This leaves the app vulnerable to Clickjacking.",
		})
	}
	if !hasCSP {
		findings = append(findings, DeployFinding{
			File: path, Line: 1,
			Issue: "nginx_missing_csp", Severity: "LOW",
			Evidence: "Whole file",
			Advice:   "Missing Content-Security-Policy header. Consider adding one to prevent XSS.",
		})
	}

	return findings, nil
}

func auditMakefile(path string) ([]DeployFinding, error) {
	var findings []DeployFinding
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		lower := strings.ToLower(line)

		if (strings.Contains(lower, "password") || strings.Contains(lower, "secret") || strings.Contains(lower, "api_key") || strings.Contains(lower, "token")) && strings.Contains(line, "=") && !strings.Contains(line, "$(") && !strings.Contains(line, "${") {
			findings = append(findings, DeployFinding{
				File: path, Line: lineNum,
				Issue: "makefile_hardcoded_secret", Severity: "HIGH",
				Evidence: fmt.Sprintf("%.60s", line),
				Advice:   "Potential hardcoded secret found in Makefile variable assignment. Extract to .env or inject via CI/CD.",
			})
		}
	}
	return findings, nil
}

func auditKubernetes(path string) ([]DeployFinding, error) {
	var findings []DeployFinding
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Kubernetes can have multiple documents in one yaml file
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	var isK8s bool

	for {
		var root yaml.Node
		if err := dec.Decode(&root); err != nil {
			break
		}

		// Fast check if it is k8s by finding apiVersion or kind at root level
		if root.Kind == yaml.DocumentNode && len(root.Content) > 0 {
			mapping := root.Content[0]
			if mapping.Kind == yaml.MappingNode {
				for i := 0; i < len(mapping.Content); i += 2 {
					k := mapping.Content[i].Value
					if k == "apiVersion" || k == "kind" {
						isK8s = true
						break
					}
				}
			}
		}

		if isK8s {
			walkYamlNode(&root, path, func(key, val *yaml.Node) {
				// Check for privileged container
				if key.Value == "privileged" && val.Kind == yaml.ScalarNode {
					if strings.ToLower(val.Value) == "true" {
						findings = append(findings, DeployFinding{
							File: path, Line: key.Line,
							Issue: "k8s_privileged_container", Severity: "CRITICAL",
							Evidence: "privileged: true",
							Advice:   "Container is running in privileged mode. This allows root access to the host node. Use explicit securityContext capabilities instead.",
						})
					}
				}
				// Check for runAsUser: 0
				if key.Value == "runAsUser" && val.Kind == yaml.ScalarNode {
					if val.Value == "0" {
						findings = append(findings, DeployFinding{
							File: path, Line: key.Line,
							Issue: "k8s_run_as_root", Severity: "HIGH",
							Evidence: "runAsUser: 0",
							Advice:   "SecurityContext forces container to run as root. Prefer running as non-root user for defense-in-depth.",
						})
					}
				}
			})
		}
	}

	if !isK8s {
		return nil, nil
	}

	return findings, nil
}

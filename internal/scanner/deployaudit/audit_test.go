package deployaudit

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/dodobrands/aitriage/internal/scanner/external"
)

func TestAuditDockerfile(t *testing.T) {
	content := `
FROM ubuntu:latest
USER root
ADD http://example.com/file /tmp/
ENV PASSWORD=secret123
`
	dir := t.TempDir()
	path := filepath.Join(dir, "Dockerfile")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	findings, err := auditDockerfile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(findings))
	}

	issues := map[string]bool{}
	for _, f := range findings {
		issues[f.Issue] = true
	}

	expected := []string{"dockerfile_root_user", "dockerfile_add_instead_of_copy", "dockerfile_hardcoded_secret"}
	for _, exp := range expected {
		if !issues[exp] {
			t.Errorf("missing expected issue: %s", exp)
		}
	}
}

func TestAuditCompose(t *testing.T) {
	content := `
version: '3'
services:
  web:
    image: nginx
    privileged: true
    environment:
      DATABASE_PASSWORD: supersecret
      SAFE_VAR: ${SAFE_VAR}
`
	dir := t.TempDir()
	path := filepath.Join(dir, "docker-compose.yml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	findings, err := auditCompose(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	issues := map[string]bool{}
	for _, f := range findings {
		issues[f.Issue] = true
	}

	expected := []string{"compose_privileged_mode", "compose_hardcoded_secret"}
	for _, exp := range expected {
		if !issues[exp] {
			t.Errorf("missing expected issue: %s", exp)
		}
	}
}

func TestAuditKubernetes(t *testing.T) {
	content := `
apiVersion: v1
kind: Pod
metadata:
  name: mypod
spec:
  securityContext:
    runAsUser: 0
  containers:
  - name: mycontainer
    image: nginx
    securityContext:
      privileged: true
`
	dir := t.TempDir()
	path := filepath.Join(dir, "deployment.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	findings, err := auditKubernetes(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	issues := map[string]bool{}
	for _, f := range findings {
		issues[f.Issue] = true
	}

	expected := []string{"k8s_run_as_root", "k8s_privileged_container"}
	for _, exp := range expected {
		if !issues[exp] {
			t.Errorf("missing expected issue: %s", exp)
		}
	}
}

func TestAuditNginx(t *testing.T) {
	content := `
user root;
worker_processes auto;
http {
    # does not have tokens off
    # does not have x-frame-opts
    # does not have csp
}
`
	dir := t.TempDir()
	path := filepath.Join(dir, "nginx.conf")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	findings, err := auditNginx(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 4 {
		t.Fatalf("expected 4 findings, got %d", len(findings))
	}

	issues := map[string]bool{}
	for _, f := range findings {
		issues[f.Issue] = true
	}

	expected := []string{
		"nginx_runs_as_root",
		"nginx_missing_server_tokens_off",
		"nginx_missing_xframe_options",
		"nginx_missing_csp",
	}
	for _, exp := range expected {
		if !issues[exp] {
			t.Errorf("missing expected issue: %s", exp)
		}
	}
}

func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func issuesOf(findings []DeployFinding) []string {
	var issues []string
	for _, f := range findings {
		issues = append(issues, filepath.Base(f.File)+":"+f.Issue)
	}
	return issues
}

const apacheConf = `ServerTokens Prod
ServerSignature Off
<VirtualHost *:80>
    ServerName app.example.test
    DocumentRoot /var/www/html
    Header always set X-Frame-Options "SAMEORIGIN"
    <Directory /var/www/html>
        Options -Indexes
    </Directory>
</VirtualHost>
`

const supervisordConf = `[supervisord]
nodaemon=true

[program:app]
command=/usr/local/bin/app --port 8080
autorestart=true
`

// Every *.conf file used to get the nginx checks, so Apache and supervisord
// configs were reported as nginx configs missing server_tokens, CSP and
// X-Frame-Options.
func TestNginxChecksSkipOtherConfFiles(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"docker/apache-hardening.conf": apacheConf,
		"deploy/supervisord.conf":      supervisordConf,
		"deploy/redis.conf":            "bind 127.0.0.1\nport 6379\nappendonly yes\n",
	})

	findings, err := AuditDeployFiles(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("non-nginx .conf files produced findings: %v", issuesOf(findings))
	}
}

func TestNginxMainConfigReportsOnlyWhatIsMissing(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"nginx/nginx.conf": `user nginx;
events {}
http {
    add_header X-Frame-Options SAMEORIGIN;
    add_header Content-Security-Policy "default-src 'self'";
    include /etc/nginx/conf.d/*.conf;
}
`,
	})

	findings, err := AuditDeployFiles(root)
	if err != nil {
		t.Fatal(err)
	}
	if got := issuesOf(findings); len(got) != 1 || got[0] != "nginx.conf:nginx_missing_server_tokens_off" {
		t.Fatalf("findings = %v; want only the missing server_tokens off", got)
	}
}

// A conf.d snippet holds server blocks included into the main config's http
// block; it is not expected to repeat headers set there. Directives it does
// contain are still checked.
func TestNginxSnippetGetsOnlyPresentDirectiveChecks(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"nginx/conf.d/app.conf": `server {
    listen 80;
    server_tokens on;
    location / {
        proxy_pass http://app:8080;
    }
}
`,
		"nginx/conf.d/upstream.conf": "upstream app {\n    server app:8080;\n}\n",
	})

	findings, err := AuditDeployFiles(root)
	if err != nil {
		t.Fatal(err)
	}
	if got := issuesOf(findings); len(got) != 1 || got[0] != "app.conf:nginx_server_tokens_on" {
		t.Fatalf("findings = %v; want only server_tokens on in app.conf", got)
	}
}

func TestNginxDetectionByContent(t *testing.T) {
	cases := []struct {
		name    string
		file    string
		content string
		nginx   bool
		main    bool
	}{
		{"main config by http block", "site.conf", "events {}\nhttp {\n}\n", true, true},
		{"main config by name", "nginx.conf", "worker_processes auto;\n", true, true},
		{"server block", "default.conf", "server {\n    listen 80;\n}\n", true, false},
		{"location block", "locations.conf", "location /api/ {\n    proxy_pass http://api;\n}\n", true, false},
		{"upstream block", "upstreams.conf", "upstream api {\n    server api:8080;\n}\n", true, false},
		{"server_tokens directive", "security.conf", "server_tokens off;\n", true, false},
		{"apache", "httpd.conf", apacheConf, false, false},
		{"apache named nginx.conf", "nginx.conf", "<VirtualHost *:80>\n</VirtualHost>\n", false, false},
		{"supervisord", "supervisord.conf", supervisordConf, false, false},
		{"comment mentioning nginx words", "app.conf", "# location of the log file\nlog=/var/log/app.log\n", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nginx, main := classifyNginx(filepath.Join("conf", tc.file), tc.content)
			if nginx != tc.nginx || main != tc.main {
				t.Errorf("classifyNginx = (nginx %v, main %v); want (%v, %v)", nginx, main, tc.nginx, tc.main)
			}
		})
	}
}

// The deploy audit walked everything except .git, node_modules and vendor,
// so files the project excludes everywhere else were still audited.
func TestAuditDeployFilesHonoursProjectScope(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		".aitriageignore":   "legacy/\n",
		"Dockerfile":        "FROM alpine\nUSER root\n",
		"legacy/Dockerfile": "FROM alpine\nUSER root\n",
		"dist/Dockerfile":   "FROM alpine\nUSER root\n",
	})

	findings, err := AuditDeployFiles(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].File != filepath.Join(root, "Dockerfile") {
		t.Fatalf("findings = %+v; want only the project's own Dockerfile", findings)
	}
}

// auditedFiles returns the root-relative files the deploy audit reported on.
func auditedFiles(t *testing.T, root string) map[string]bool {
	t.Helper()
	findings, err := AuditDeployFiles(root)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]bool{}
	for _, f := range findings {
		rel, err := filepath.Rel(root, f.File)
		if err != nil {
			t.Fatal(err)
		}
		files[filepath.ToSlash(rel)] = true
	}
	return files
}

const rootDockerfile = "FROM alpine:3.19\nUSER root\n"

// The audit asked InScope, which judges a path as a file, about directories.
// A directory a negated pattern re-includes was pruned, so its Dockerfile was
// never audited although every other scanner kept it in scope.
func TestAuditDeployFilesEntersDirectoriesANegationReincludes(t *testing.T) {
	cases := map[string]struct {
		files  map[string]string
		kept   []string
		pruned []string
	}{
		"ignore.paths": {
			files: map[string]string{
				".aitriage.yaml":        "ignore:\n  paths:\n    - \"infra/\"\n    - \"!infra/prod/\"\n",
				"infra/prod/Dockerfile": rootDockerfile,
				"infra/dev/Dockerfile":  rootDockerfile,
				"Dockerfile":            rootDockerfile,
			},
			kept:   []string{"infra/prod/Dockerfile", "Dockerfile"},
			pruned: []string{"infra/dev/Dockerfile"},
		},
		".gitignore": {
			files: map[string]string{
				".gitignore":             "deploy/*\n!deploy/prod/\n",
				"deploy/prod/Dockerfile": rootDockerfile,
				"deploy/dev/Dockerfile":  rootDockerfile,
			},
			kept:   []string{"deploy/prod/Dockerfile"},
			pruned: []string{"deploy/dev/Dockerfile"},
		},
		".aitriageignore": {
			files: map[string]string{
				".aitriageignore":                 "k8s/\n!k8s/base/\n",
				"k8s/base/docker-compose.yml":     "services:\n  web:\n    privileged: true\n",
				"k8s/overlays/docker-compose.yml": "services:\n  web:\n    privileged: true\n",
			},
			kept:   []string{"k8s/base/docker-compose.yml"},
			pruned: []string{"k8s/overlays/docker-compose.yml"},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			writeTree(t, root, tc.files)
			scope := external.NewScopeFilter(root)
			files := auditedFiles(t, root)
			for _, rel := range tc.kept {
				if !scope.InScope(rel) {
					t.Fatalf("the scope filter dropped %s; the case is wrong", rel)
				}
				if !files[rel] {
					t.Errorf("%s is in scope but was not audited (audited: %v)", rel, files)
				}
			}
			for _, rel := range tc.pruned {
				if files[rel] {
					t.Errorf("%s is out of scope but was audited", rel)
				}
			}
		})
	}
}

// A project checked out into a directory called vendor or node_modules was
// skipped whole: the name check also applied to the project directory itself.
func TestAuditDeployFilesAuditsAProjectNamedLikeAVendoredDirectory(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vendor")
	writeTree(t, root, map[string]string{"Dockerfile": rootDockerfile, "vendor/lib/Dockerfile": rootDockerfile})

	files := auditedFiles(t, root)
	if !files["Dockerfile"] || files["vendor/lib/Dockerfile"] {
		t.Errorf("audited %v; want the project's own Dockerfile only", files)
	}
}

func TestAuditMakefile(t *testing.T) {
	content := `
build:
	echo "Building..."
DB_PASSWORD = mysecretpass
SAFE_TOKEN = $(MY_ENV_TOKEN)
`
	dir := t.TempDir()
	path := filepath.Join(dir, "Makefile")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	findings, err := auditMakefile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	if findings[0].Issue != "makefile_hardcoded_secret" {
		t.Errorf("expected makefile_hardcoded_secret, got %s", findings[0].Issue)
	}
}

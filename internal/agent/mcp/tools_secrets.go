package mcp

import (
	"context"
	"fmt"

	"github.com/dodobrands/aitriage/internal/agent/remedy"
	"github.com/dodobrands/aitriage/internal/engine/core"
	"github.com/dodobrands/aitriage/internal/scanner"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type secretsInput struct {
	Path string `json:"path"`
}

type secretsResult struct {
	Found   []core.CheckResult `json:"found"`
	Count   int                `json:"count"`
	Summary string             `json:"summary"`
}

func registerSecretsTool(srv *mcp.Server, guard *PathGuard) {
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "aitriage_secrets",
		Description: "Scan for hardcoded secrets: known credential formats (cloud and vendor API keys, tokens, private keys, credentialed connection strings) and random-looking values assigned to secret-named variables. Returns only secret findings (rule ids SECRET-*).",
	}, func(ctx context.Context, req *mcp.CallToolRequest, input secretsInput) (*mcp.CallToolResult, secretsResult, error) {
		path, err := guard.Resolve(input.Path)
		if err != nil {
			return nil, secretsResult{}, err
		}
		report, err := scanner.Scan(ctx, path, scanner.ScanOptions{})
		if err != nil {
			return nil, secretsResult{}, fmt.Errorf("scan failed: %w", err)
		}
		secrets := secretFindings(report.Results)
		res := secretsResult{
			Found:   secrets,
			Count:   len(secrets),
			Summary: fmt.Sprintf("Found %d potential hardcoded secrets", len(secrets)),
		}
		return nil, res, nil
	})
}

// secretFindings keeps the findings of the hardcoded-secret detector.
func secretFindings(results []core.CheckResult) []core.CheckResult {
	var secrets []core.CheckResult
	for _, r := range results {
		if remedy.IsSecretRule(r.ID) {
			secrets = append(secrets, r)
		}
	}
	return secrets
}

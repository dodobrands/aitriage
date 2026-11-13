package main

import (
	"bufio"
	"context"
	"fmt"
	"os"

	"github.com/dodobrands/aitriage/internal/agent/llm"
	"github.com/dodobrands/aitriage/internal/config"
	"github.com/dodobrands/aitriage/internal/scanner/nfr"
	"github.com/spf13/cobra"
)

var (
	preauditArchitecture string
	preauditProvider     string
	preauditModel        string
	preauditAPIKey       string
	preauditTemperature  llm.TemperatureFlag
)

var preauditCmd = &cobra.Command{
	Use:   "preaudit",
	Short: "Run a Pre-audit NFR check before writing code",
	RunE:  runPreaudit,
}

func init() {
	rootCmd.AddCommand(preauditCmd)
	preauditCmd.Flags().StringVar(&preauditArchitecture, "arch", "", "Describe the architecture you plan to build (e.g. Next.js, Go API, Postgres)")
	preauditCmd.Flags().StringVar(&preauditProvider, "provider", "", "LLM provider: gemini, anthropic, openai, ollama, groq (auto-detected from env)")
	preauditCmd.Flags().StringVar(&preauditModel, "model", "", "LLM model name")
	preauditCmd.Flags().StringVar(&preauditAPIKey, "api-key", "", "LLM API key (or set via env)")
	preauditCmd.Flags().Var(&preauditTemperature, "temperature", llm.TemperatureFlagUsage)
}

func runPreaudit(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Use current dir for config if available
	projectPath := "."
	cfg := config.LoadConfig(projectPath)

	llmCfg := cfg.LLM
	if preauditProvider != "" {
		llmCfg.Provider = preauditProvider
	}
	if preauditModel != "" {
		llmCfg.Model = preauditModel
	}
	if preauditAPIKey != "" {
		llmCfg.APIKey = preauditAPIKey
	}
	llmCfg.Temperature = preauditTemperature.Or(llmCfg.Temperature)

	client, err := llm.NewClient(llm.Config{
		Provider:    llmCfg.Provider,
		Model:       llmCfg.Model,
		APIKey:      llmCfg.APIKey,
		BaseURL:     llmCfg.BaseURL,
		Timeout:     llmCfg.Timeout,
		Temperature: llmCfg.Temperature,
	})
	if err != nil {
		cmd.SilenceUsage = true
		return err
	}

	archDesc := preauditArchitecture
	if archDesc == "" {
		fmt.Println("No architecture description provided via --arch.")
		fmt.Println("Describe your planned architecture (e.g., 'Go API with PostgreSQL and a React frontend'):")
		fmt.Print("> ")
		scanner := bufio.NewScanner(os.Stdin)
		if scanner.Scan() {
			archDesc = scanner.Text()
		}
	}

	fmt.Fprintf(os.Stderr, "\n🔍 AITriage Pre-audit NFR starting...\n")
	fmt.Fprintf(os.Stderr, "📡 Gathering NFR rules...\n")

	rulesText := nfr.GetAllRulesAsText()
	if rulesText == "" {
		rulesText = "No internal rules found. Please provide general security best practices."
	}

	systemPrompt := "You are a senior Application Security Architect. Your job is to conduct a 'Pre-audit' for a new software project based on the user's architectural description."
	userPrompt := fmt.Sprintf(`
The user is planning to build the following architecture:
"""
%s
"""

Here are the standard Non-Functional Requirements (NFR) rules configured in AITriage:
"""
%s
"""

Please provide a detailed Pre-audit Security Checklist. Focus on:
1. Which of the provided NFR rules strictly apply to this architecture.
2. What the developers must implement BEFORE or DURING writing the code (e.g., missing middleware, specific library choices).
3. Any architectural security risks inherent to their proposed stack (e.g., if they mention React, warn about XSS and state management).

Provide actionable, clear, and concise advice in markdown format.
`, archDesc, rulesText)

	fmt.Fprintf(os.Stderr, "🤖 Analyzing architecture via LLM (%s)...\n\n", llmCfg.Provider)

	messages := []llm.Message{
		{Role: "system", Content: systemPrompt},
		{Role: "user", Content: userPrompt},
	}

	analysis, _, err := client.Chat(ctx, messages)
	if err != nil {
		return fmt.Errorf("preaudit analysis failed: %w", err)
	}

	fmt.Println(analysis)
	return nil
}

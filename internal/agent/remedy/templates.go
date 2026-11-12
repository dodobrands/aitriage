package remedy

type FixTemplate struct {
	Prompt     string // %s = file, %d = line
	Example    string
	References []string
}

var defaultTemplate = FixTemplate{
	Prompt:     "Fix the security issue at %s line %d. Review the code and apply appropriate security controls.",
	References: []string{"https://owasp.org/www-project-top-ten/"},
}

var fixTemplates = map[string]FixTemplate{
	"ENTROPY-SECRET": {
		Prompt:     "Open %s line %d. The hardcoded secret must be moved to an environment variable. Replace the literal value with os.Getenv(\"VAR_NAME\") in Go, process.env.VAR_NAME in Node.js, or os.environ.get(\"VAR_NAME\") in Python. Add the variable to .env.example without the value.",
		Example:    "// Before:\nconst apiKey = \"sk-abc123...\"\n\n// After:\nconst apiKey = os.Getenv(\"API_KEY\")\nif apiKey == \"\" {\n    log.Fatal(\"API_KEY env variable is required\")\n}",
		References: []string{"https://12factor.net/config", "https://owasp.org/www-project-top-ten/2021/A02_2021-Cryptographic_Failures"},
	},
	"ENTR-04": {
		Prompt:     "Remove AI assistant chat residue from %s (line %d). Comments like \"As an AI\" or \"I cannot\" should not appear in production code. Clean up all such comments.",
		Example:    "// Remove comments like:\n// 'As an AI language model, I cannot...'\n// 'I apologize, but as an AI...'\n// These are artifacts from AI code generation sessions.",
		References: []string{},
	},
}

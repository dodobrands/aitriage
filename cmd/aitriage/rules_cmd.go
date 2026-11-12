package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/dodobrands/aitriage/internal/models"
	"github.com/dodobrands/aitriage/internal/rules/packs"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// A rule pack is a local directory of rule YAML files. There is no online pack
// registry: the command once listed packs whose download URLs answered 404, so
// `rules list` advertised packs that `rules install` could not download.
// Everything shown here is installed and usable.

var rulesCmd = &cobra.Command{
	Use:   "rules",
	Short: "Manage rule packs — install, list, and remove custom rule sets",
	Long: `Rule pack management for extending AITriage's detection capabilities.

A rule pack is a local directory of rule YAML files (schema: rules/README.md).
Installing copies its rule files to ~/.aitriage/packs/<name>. Scans that run
the engine on this machine (for example "aitriage scan") load installed packs
on top of the built-in ruleset; the container runtime does not.

  aitriage rules list                 → List installed rule packs
  aitriage rules install ./my-rules/  → Install a pack from a local directory
  aitriage rules info my-rules        → Show an installed pack
  aitriage rules remove my-rules      → Remove an installed pack`,
}

var rulesListCmd = &cobra.Command{
	Use:   "list",
	Short: "List installed rule packs",
	Args:  cobra.NoArgs,
	RunE:  runRulesList,
}

var rulesInstallCmd = &cobra.Command{
	Use:   "install <directory>",
	Short: "Install a rule pack from a local directory",
	Args:  cobra.ExactArgs(1),
	RunE:  runRulesInstall,
}

var rulesRemoveCmd = &cobra.Command{
	Use:   "remove <pack-name>",
	Short: "Remove an installed rule pack",
	Args:  cobra.ExactArgs(1),
	RunE:  runRulesRemove,
}

var rulesInfoCmd = &cobra.Command{
	Use:   "info <pack-name>",
	Short: "Show details about an installed rule pack",
	Args:  cobra.ExactArgs(1),
	RunE:  runRulesInfo,
}

func init() {
	rootCmd.AddCommand(rulesCmd)
	rulesCmd.AddCommand(rulesListCmd)
	rulesCmd.AddCommand(rulesInstallCmd)
	rulesCmd.AddCommand(rulesRemoveCmd)
	rulesCmd.AddCommand(rulesInfoCmd)
}

// PackManifest describes an installed rule pack. It is written at install time;
// internal/rules/packs reads the same file for the other surfaces.
type PackManifest struct {
	Name        string   `json:"name" yaml:"name"`
	Version     string   `json:"version" yaml:"version"`
	Description string   `json:"description" yaml:"description"`
	Author      string   `json:"author" yaml:"author"`
	RuleCount   int      `json:"rule_count" yaml:"rule_count"`
	Tags        []string `json:"tags" yaml:"tags"`
	Source      string   `json:"source,omitempty" yaml:"source,omitempty"` // local directory the pack was installed from
}

const (
	rulesCyan   = "\033[38;2;0;245;255m"
	rulesGreen  = "\033[38;2;46;204;113m"
	rulesYellow = "\033[38;2;255;214;0m"
	rulesDim    = "\033[38;2;120;120;140m"
	rulesBold   = "\033[1m"
	rulesReset  = "\033[0m"
)

const rulesInstallHint = "aitriage rules install ./my-rules/"

// countOf renders "1 rule" and "3 rules".
func countOf(n int, noun string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, noun)
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

// silenceRuntimeErrors keeps cobra from printing usage, and the error a second
// time, when a command fails for a reason other than its arguments.
func silenceRuntimeErrors(cmd *cobra.Command) {
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
}

func runRulesList(cmd *cobra.Command, args []string) error {
	out := cmd.ErrOrStderr()
	_, _ = fmt.Fprintf(out, "\n%s%s  ⦿ AITriage Rule Packs%s\n\n", rulesCyan, rulesBold, rulesReset)

	installed := packs.List()
	if len(installed) == 0 {
		_, _ = fmt.Fprintf(out, "  No rule packs installed. Scans use the built-in ruleset only.\n")
	} else {
		_, _ = fmt.Fprintf(out, "%s  Installed:%s\n", rulesBold, rulesReset)
		for _, pack := range installed {
			line := pack.Name
			if pack.Version != "" {
				line += " (" + pack.Version + ")"
			}
			line += " — " + countOf(pack.RuleCount, "rule")
			if pack.Description != "" {
				line += " — " + pack.Description
			}
			_, _ = fmt.Fprintf(out, "  %s✓ %s%s\n", rulesGreen, line, rulesReset)
		}
	}

	_, _ = fmt.Fprintf(out, "\n%s  Install a pack from a local directory: %s%s\n\n", rulesDim, rulesInstallHint, rulesReset)
	return nil
}

func runRulesInstall(cmd *cobra.Command, args []string) error {
	silenceRuntimeErrors(cmd)
	source := args[0]
	out := cmd.ErrOrStderr()

	if info, err := os.Stat(source); err != nil || !info.IsDir() {
		return notAPackDirectory(source)
	}

	_, _ = fmt.Fprintf(out, "\n%s%s  ⦿ Installing rule pack from %s%s\n", rulesCyan, rulesBold, source, rulesReset)
	result, err := installPackFromDir(source, packs.Dir())
	if err != nil {
		return err
	}

	for _, skipped := range result.Skipped {
		_, _ = fmt.Fprintf(out, "%s  ⚠ Skipped %s%s\n", rulesYellow, skipped, rulesReset)
	}
	_, _ = fmt.Fprintf(out, "%s%s  ✅ Installed: %s (%s from %s)%s\n", rulesGreen, rulesBold, result.Name,
		countOf(result.Rules, "rule"), countOf(result.Files, "file"), rulesReset)
	_, _ = fmt.Fprintf(out, "%s  Location: %s%s\n", rulesDim, result.Dir, rulesReset)
	_, _ = fmt.Fprintf(out, "%s  Loaded by scans that run the engine on this machine (for example \"aitriage scan\").%s\n\n", rulesDim, rulesReset)
	return nil
}

// notAPackDirectory explains what install accepts. A name or a URL used to be
// looked up in a registry that served nothing; say so plainly instead.
func notAPackDirectory(arg string) error {
	if strings.Contains(arg, "://") || strings.HasPrefix(arg, "github.com/") {
		return fmt.Errorf("cannot install %q: rule packs are not downloaded. Fetch or clone the pack, then run: aitriage rules install <directory>", arg)
	}
	return fmt.Errorf("%q is not a directory. Rule packs are installed from a local directory of rule YAML files (there is no online pack registry): %s", arg, rulesInstallHint)
}

// packInstall is the outcome of installing one pack.
type packInstall struct {
	Name    string
	Dir     string
	Files   int
	Rules   int
	Skipped []string // "<file>: <reason>"
}

// validPackName rejects names that would address something other than one
// directory directly inside the packs directory. "aitriage rules remove .."
// must not delete ~/.aitriage, let alone the home directory above it.
func validPackName(name string) error {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\`) || filepath.VolumeName(name) != "" {
		return fmt.Errorf("%q is not a rule pack name; see: aitriage rules list", name)
	}
	return nil
}

// installPackFromDir copies every rule file of source into packsDir/<name>,
// named after the source directory, and counts the rules the files define.
// A reinstall replaces the previous copy instead of merging into it, so files
// removed from the source stop being loaded.
func installPackFromDir(source, packsDir string) (packInstall, error) {
	absSource, err := filepath.Abs(source)
	if err != nil {
		return packInstall{}, fmt.Errorf("resolve %s: %w", source, err)
	}
	name := filepath.Base(absSource)
	if validPackName(name) != nil {
		return packInstall{}, fmt.Errorf("cannot name a rule pack after %q; install it from a named directory such as ./my-rules/", absSource)
	}
	absPacks, err := filepath.Abs(packsDir)
	if err != nil {
		return packInstall{}, fmt.Errorf("resolve %s: %w", packsDir, err)
	}
	if err := os.MkdirAll(absPacks, 0o755); err != nil {
		return packInstall{}, fmt.Errorf("create %s: %w", absPacks, err)
	}

	// Stage next to the packs directory, not inside it: the engine loads every
	// YAML file under it, and a half-written pack must never be one of them.
	staging, err := os.MkdirTemp(filepath.Dir(absPacks), ".rules-install-")
	if err != nil {
		return packInstall{}, fmt.Errorf("prepare install: %w", err)
	}
	defer func() { _ = os.RemoveAll(staging) }()
	// A source that contains the packs directory (a home directory, say) must
	// not copy installed packs, or the pack being staged, into the new pack.
	var skipDirs []os.FileInfo
	for _, dir := range []string{absPacks, staging} {
		if info, statErr := os.Stat(dir); statErr == nil {
			skipDirs = append(skipDirs, info)
		}
	}

	result := packInstall{Name: name, Dir: filepath.Join(absPacks, name)}
	walkErr := filepath.WalkDir(absSource, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if info, infoErr := d.Info(); infoErr == nil {
				for _, skip := range skipDirs {
					if os.SameFile(info, skip) {
						return filepath.SkipDir
					}
				}
			}
			return nil
		}
		if !strings.HasSuffix(path, ".yaml") && !strings.HasSuffix(path, ".yml") {
			return nil
		}
		rel, err := filepath.Rel(absSource, path)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			result.Skipped = append(result.Skipped, fmt.Sprintf("%s: %v", rel, err))
			return nil
		}
		var ruleset models.Ruleset
		if err := yaml.Unmarshal(data, &ruleset); err != nil {
			result.Skipped = append(result.Skipped, fmt.Sprintf("%s: not a rule file (%v)", rel, err))
			return nil
		}
		if len(ruleset.Rules) == 0 {
			result.Skipped = append(result.Skipped, fmt.Sprintf("%s: no rules", rel))
			return nil
		}
		dst := filepath.Join(staging, rel)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(dst, data, 0o644); err != nil {
			return err
		}
		result.Files++
		result.Rules += len(ruleset.Rules)
		return nil
	})
	if walkErr != nil {
		return packInstall{}, fmt.Errorf("read %s: %w", absSource, walkErr)
	}
	if result.Rules == 0 {
		return packInstall{}, fmt.Errorf("no rules found in %s: a rule pack needs at least one .yaml file with a top-level \"rules:\" list (see rules/README.md)", absSource)
	}

	manifest, err := json.MarshalIndent(PackManifest{
		Name:      name,
		Version:   "local",
		Source:    absSource,
		RuleCount: result.Rules,
	}, "", "  ")
	if err != nil {
		return packInstall{}, err
	}
	if err := os.WriteFile(filepath.Join(staging, "manifest.json"), manifest, 0o644); err != nil {
		return packInstall{}, fmt.Errorf("write manifest: %w", err)
	}

	if err := os.RemoveAll(result.Dir); err != nil {
		return packInstall{}, fmt.Errorf("replace %s: %w", result.Dir, err)
	}
	if err := os.Rename(staging, result.Dir); err != nil {
		return packInstall{}, fmt.Errorf("install %s: %w", result.Dir, err)
	}
	return result, nil
}

func notInstalled(name string) error {
	return fmt.Errorf("rule pack %q is not installed; see: aitriage rules list", name)
}

func runRulesRemove(cmd *cobra.Command, args []string) error {
	silenceRuntimeErrors(cmd)
	name := args[0]
	if err := validPackName(name); err != nil {
		return err
	}
	// Any directory here is loaded by the engine, with or without a manifest,
	// so any directory can be removed.
	dir := filepath.Join(packs.Dir(), name)
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		return notInstalled(name)
	}
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("failed to remove pack: %w", err)
	}
	_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "✅ Removed rule pack: %s\n", name)
	return nil
}

func runRulesInfo(cmd *cobra.Command, args []string) error {
	silenceRuntimeErrors(cmd)
	name := args[0]
	if err := validPackName(name); err != nil {
		return err
	}
	data, err := os.ReadFile(filepath.Join(packs.Dir(), name, "manifest.json"))
	if errors.Is(err, fs.ErrNotExist) {
		return notInstalled(name)
	}
	if err != nil {
		return err
	}
	var m PackManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return fmt.Errorf("rule pack %q has an unreadable manifest: %w", args[0], err)
	}
	printPackInfo(cmd.ErrOrStderr(), m)
	return nil
}

func printPackInfo(out io.Writer, m PackManifest) {
	_, _ = fmt.Fprintf(out, "\n%s%s  %s%s (%s)\n", rulesCyan, rulesBold, m.Name, rulesReset, m.Version)
	if m.Description != "" {
		_, _ = fmt.Fprintf(out, "%s  %s%s\n", rulesDim, m.Description, rulesReset)
	}
	_, _ = fmt.Fprintf(out, "%s  Rules: %d%s\n", rulesDim, m.RuleCount, rulesReset)
	if m.Author != "" {
		_, _ = fmt.Fprintf(out, "%s  Author: %s%s\n", rulesDim, m.Author, rulesReset)
	}
	if m.Source != "" {
		_, _ = fmt.Fprintf(out, "%s  Source: %s%s\n", rulesDim, m.Source, rulesReset)
	}
	if len(m.Tags) > 0 {
		_, _ = fmt.Fprintf(out, "%s  Tags: %s%s\n", rulesDim, strings.Join(m.Tags, ", "), rulesReset)
	}
	_, _ = fmt.Fprintln(out)
}

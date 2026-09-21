// Package sbom renders a scanned project's dependency graph as a Software Bill
// of Materials. It is shared by the CLI (aitriage sbom) and the Web report
// generator so both emit byte-identical documents from the same scan result.
package sbom

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/dodobrands/aitriage/internal/scanner"
	"github.com/dodobrands/aitriage/internal/scanner/deps"
)

// CycloneDX 1.5 structures
type cycloneDXBOM struct {
	BOMFormat    string                `json:"bomFormat"`
	SpecVersion  string                `json:"specVersion"`
	Version      int                   `json:"version"`
	SerialNumber string                `json:"serialNumber"`
	Metadata     cycloneDXMeta         `json:"metadata"`
	Components   []cycloneDXComponent  `json:"components"`
	Dependencies []cycloneDXDependency `json:"dependencies,omitempty"`
}

type cycloneDXMeta struct {
	Timestamp string          `json:"timestamp"`
	Tools     []cycloneDXTool `json:"tools"`
}

type cycloneDXTool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type cycloneDXComponent struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Purl    string `json:"purl,omitempty"`
	Scope   string `json:"scope,omitempty"`
}

type cycloneDXDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn,omitempty"`
}

// SPDX 2.3 structures
type spdxDocument struct {
	SPDXVersion       string             `json:"spdxVersion"`
	DataLicense       string             `json:"dataLicense"`
	SPDXID            string             `json:"SPDXID"`
	Name              string             `json:"name"`
	DocumentNamespace string             `json:"documentNamespace"`
	CreationInfo      spdxCreationInfo   `json:"creationInfo"`
	Packages          []spdxPackage      `json:"packages"`
	Relationships     []spdxRelationship `json:"relationships,omitempty"`
}

type spdxCreationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

type spdxPackage struct {
	SPDXID           string            `json:"SPDXID"`
	Name             string            `json:"name"`
	VersionInfo      string            `json:"versionInfo"`
	DownloadLocation string            `json:"downloadLocation"`
	ExternalRefs     []spdxExternalRef `json:"externalRefs,omitempty"`
}

type spdxExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

type spdxRelationship struct {
	Element string `json:"spdxElementId"`
	Type    string `json:"relationshipType"`
	Related string `json:"relatedSpdxElement"`
}

// CycloneDX renders the dependency graph as a CycloneDX 1.5 JSON document.
func CycloneDX(report scanner.ScanReport, projectPath string) ([]byte, error) {
	bom := cycloneDXBOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.5",
		Version:      1,
		SerialNumber: fmt.Sprintf("urn:uuid:aitriage-%d", time.Now().UnixNano()),
		Metadata: cycloneDXMeta{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Tools: []cycloneDXTool{{
				Vendor:  "dodobrands",
				Name:    "aitriage",
				Version: "1.0.0",
			}},
		},
	}

	for _, dep := range report.Dependencies {
		comp := cycloneDXComponent{
			Type:    "library",
			Name:    dep.Name,
			Version: dep.Version,
			Purl:    PURL(dep),
		}
		if dep.Type == "dev" {
			comp.Scope = "optional"
		}
		bom.Components = append(bom.Components, comp)
	}

	// Add dependency graph edges
	for parentID, children := range report.DependencyGraph.Edges {
		dep := cycloneDXDependency{
			Ref:       parentID,
			DependsOn: children,
		}
		bom.Dependencies = append(bom.Dependencies, dep)
	}

	return json.MarshalIndent(bom, "", "  ")
}

// SPDX renders the dependency graph as an SPDX 2.3 JSON document.
func SPDX(report scanner.ScanReport, projectPath string) ([]byte, error) {
	doc := spdxDocument{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		SPDXID:            "SPDXRef-DOCUMENT",
		Name:              projectPath,
		DocumentNamespace: fmt.Sprintf("https://aitriage.dev/sbom/%s/%d", projectPath, time.Now().UnixNano()),
		CreationInfo: spdxCreationInfo{
			Created:  time.Now().UTC().Format(time.RFC3339),
			Creators: []string{"Tool: aitriage-1.0.0"},
		},
	}

	for i, dep := range report.Dependencies {
		spdxID := fmt.Sprintf("SPDXRef-Package-%d", i)
		pkg := spdxPackage{
			SPDXID:           spdxID,
			Name:             dep.Name,
			VersionInfo:      dep.Version,
			DownloadLocation: "NOASSERTION",
		}

		purl := PURL(dep)
		if purl != "" {
			pkg.ExternalRefs = []spdxExternalRef{{
				ReferenceCategory: "PACKAGE-MANAGER",
				ReferenceType:     "purl",
				ReferenceLocator:  purl,
			}}
		}

		doc.Packages = append(doc.Packages, pkg)

		// Add relationship
		doc.Relationships = append(doc.Relationships, spdxRelationship{
			Element: "SPDXRef-DOCUMENT",
			Type:    "DESCRIBES",
			Related: spdxID,
		})
	}

	return json.MarshalIndent(doc, "", "  ")
}

// SimpleJSON renders a flat dependency inventory for tooling that wants
// neither CycloneDX nor SPDX.
func SimpleJSON(report scanner.ScanReport) ([]byte, error) {
	type simpleDep struct {
		Name      string `json:"name"`
		Version   string `json:"version"`
		Type      string `json:"type"`
		Ecosystem string `json:"ecosystem"`
		PURL      string `json:"purl,omitempty"`
	}

	var out []simpleDep
	for _, dep := range report.Dependencies {
		out = append(out, simpleDep{
			Name:      dep.Name,
			Version:   dep.Version,
			Type:      dep.Type,
			Ecosystem: dep.Ecosystem,
			PURL:      PURL(dep),
		})
	}

	return json.MarshalIndent(out, "", "  ")
}

// PURL builds a package URL for a dependency, or "" for an ecosystem with no
// canonical purl form.
func PURL(dep deps.Dependency) string {
	switch dep.Ecosystem {
	case "go":
		return fmt.Sprintf("pkg:golang/%s@%s", dep.Name, dep.Version)
	case "npm":
		if strings.HasPrefix(dep.Name, "@") {
			parts := strings.SplitN(dep.Name, "/", 2)
			if len(parts) == 2 {
				return fmt.Sprintf("pkg:npm/%s/%s@%s", parts[0], parts[1], dep.Version)
			}
		}
		return fmt.Sprintf("pkg:npm/%s@%s", dep.Name, dep.Version)
	case "pypi":
		return fmt.Sprintf("pkg:pypi/%s@%s", dep.Name, dep.Version)
	case "rubygems":
		return fmt.Sprintf("pkg:gem/%s@%s", dep.Name, dep.Version)
	case "cargo":
		return fmt.Sprintf("pkg:cargo/%s@%s", dep.Name, dep.Version)
	case "php", "composer":
		// Composer names are already vendor/package, which is the purl shape.
		return fmt.Sprintf("pkg:composer/%s@%s", dep.Name, dep.Version)
	default:
		return ""
	}
}

package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/0xsan7/scram/internal/model"
	"github.com/0xsan7/scram/internal/sbom"
)

// SARIF 2.1.0 output (FR-601), shaped for GitHub code scanning.
//
// Every finding is anchored to the lockfile that pulled the vulnerable
// package in, so clicking a result in the Security tab lands on the
// dependency declaration rather than on a file that merely mentions it.
const (
	sarifVersion = "2.1.0"
	sarifSchema  = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
	// GitHub's taxonomy for supply-chain findings, so the Security tab
	// groups these sensibly.
)

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool        sarifTool         `json:"tool"`
	Invocations []sarifInvocation `json:"invocations,omitempty"`
	Results     []sarifResult     `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name,omitempty"`
	ShortDescription sarifText      `json:"shortDescription"`
	FullDescription  sarifText      `json:"fullDescription,omitempty"`
	HelpURI          string         `json:"helpUri,omitempty"`
	Properties       map[string]any `json:"properties,omitempty"`
	// DefaultConfiguration sets the level a finding shows at before any
	// per-result override.
	DefaultConfiguration sarifRuleConfig `json:"defaultConfiguration"`
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifInvocation struct {
	ExecutionSuccessful        bool                `json:"executionSuccessful"`
	ToolExecutionNotifications []sarifNotification `json:"toolExecutionNotifications,omitempty"`
}

// sarifNotification carries a degradation warning (e.g. an upstream API
// failure) into the SARIF file, so a partial scan is never mistaken for a
// complete one.
type sarifNotification struct {
	Level      string    `json:"level"`
	Message    sarifText `json:"message"`
	Descriptor sarifDesc `json:"descriptor"`
}

type sarifDesc struct {
	ID string `json:"id"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	Properties          map[string]any    `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           *sarifRegion  `json:"region,omitempty"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

func writeSARIF(w io.Writer, scan model.Scan, diff *model.DiffResult) error {
	// New-finding ids, so results can be tagged as introduced-by-this-change.
	newVulns := map[string]bool{}
	if diff != nil {
		for _, id := range diff.Summary.NewVulnIDs {
			newVulns[id] = true
		}
	}

	rules := map[string]sarifRule{}
	var results []sarifResult

	for _, c := range scan.Components {
		for _, v := range c.Vulnerabilities {
			level := sarifLevel(c.Bucket)

			if _, ok := rules[v.ID]; !ok {
				rules[v.ID] = sarifRule{
					ID:               v.ID,
					Name:             sanitizeRuleName(v.ID),
					ShortDescription: sarifText{Text: shortDesc(v)},
					FullDescription:  sarifText{Text: fullDesc(v, c)},
					HelpURI:          v.URL,
					DefaultConfiguration: sarifRuleConfig{
						Level: level,
					},
					Properties: map[string]any{
						"security-severity": securitySeverity(v.CVSSv3),
						"tags":              []string{"security", "dependency", "supply-chain"},
					},
				}
			}

			// Anchor to the manifest that declared the dependency, so the
			// Security tab result is clickable.
			uri := manifestURI(c)
			// A component with no vuln-level CVSS still inherits its
			// component bucket, so the result is not misreported as "note".
			results = append(results, sarifResult{
				RuleID:  v.ID,
				Level:   level,
				Message: sarifText{Text: resultMessage(v, c)},
				Locations: []sarifLocation{{
					PhysicalLocation: sarifPhysical{
						ArtifactLocation: sarifArtifact{URI: uri},
					},
				}},
				PartialFingerprints: map[string]string{
					// Stable across runs so GitHub can track a finding
					// across commits instead of reporting it as new each time.
					"scramComponentPurl/v1": c.Purl,
					"scramVulnId/v1":        v.ID,
				},
				Properties: map[string]any{
					"scram:purl":          c.Purl,
					"scram:ecosystem":     c.Ecosystem,
					"scram:version":       c.Version,
					"scram:cvss":          v.CVSSv3,
					"scram:epss":          v.EPSS,
					"scram:newInThisDiff": newVulns[v.ID],
					"scram:fixedVersion":  v.FixedVersion,
				},
			})
		}
	}

	inv := []sarifInvocation{{ExecutionSuccessful: len(scan.Warnings) == 0}}
	for _, warn := range scan.Warnings {
		inv[0].ToolExecutionNotifications = append(inv[0].ToolExecutionNotifications,
			sarifNotification{
				Level:      "warning",
				Message:    sarifText{Text: warn},
				Descriptor: sarifDesc{ID: "scram.degraded"},
			})
	}
	if len(scan.Warnings) > 0 {
		inv[0].ExecutionSuccessful = false
	}

	log := sarifLog{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           sbom.ToolName,
				Version:        sbom.ToolVersion,
				InformationURI: "https://github.com/0xsan7/scram",
				Rules:          ruleList(rules),
			}},
			Invocations: inv,
			Results:     results,
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

// ruleList flattens the rule map into a stable, sorted slice.
func ruleList(m map[string]sarifRule) []sarifRule {
	ids := make([]string, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]sarifRule, 0, len(ids))
	for _, id := range ids {
		out = append(out, m[id])
	}
	return out
}

// sarifLevel maps a bucket to SARIF's error/warning/note levels.
func sarifLevel(bucket string) string {
	switch bucket {
	case model.BucketCritical, model.BucketHigh:
		return "error"
	case model.BucketMedium:
		return "warning"
	}
	return "note"
}

// securitySeverity is the 0–10 numeric score GitHub expects in rule
// properties. It must be a plain decimal string: GitHub parses it with
// strconv.ParseFloat, and a malformed value makes the Security tab reject the
// whole SARIF upload.
func securitySeverity(cvss float64) string {
	if cvss <= 0 {
		return "0.0"
	}
	if cvss > 10 {
		cvss = 10
	}
	return strconv.FormatFloat(cvss, 'f', 1, 64)
}

// manifestURI maps a component back to the manifest file that declared it,
// so a SARIF result points at a real path in the repo. Falls back to the
// root when the ecosystem has no canonical manifest.
func manifestURI(c model.Component) string {
	switch c.Ecosystem {
	case model.EcoNPM:
		return "package.json"
	case model.EcoPyPI:
		return "requirements.txt"
	case model.EcoGo:
		return "go.mod"
	}
	return "."
}

func shortDesc(v model.Vuln) string {
	if v.Summary != "" {
		return v.Summary
	}
	return v.ID + " affects a scanned dependency"
}

func fullDesc(v model.Vuln, c model.Component) string {
	var b strings.Builder
	b.WriteString(shortDesc(v))
	fmtFprintf(&b, "\n\nPackage: %s (%s)\n", c.Name, c.Version)
	if c.Purl != "" {
		fmtFprintf(&b, "PURL: %s\n", c.Purl)
	}
	if v.CVSSv3 > 0 {
		fmtFprintf(&b, "CVSS v3: %.1f", v.CVSSv3)
		if v.CVSSVector != "" {
			fmtFprintf(&b, " (%s)", v.CVSSVector)
		}
		b.WriteString("\n")
	}
	if v.EPSS > 0 {
		fmtFprintf(&b, "EPSS: %.2f%% probability of exploitation in the next 30 days\n", v.EPSS*100)
	}
	if v.FixedVersion != "" {
		fmtFprintf(&b, "Fixed in: %s\n", v.FixedVersion)
	}
	if v.URL != "" {
		fmtFprintf(&b, "Advisory: %s\n", v.URL)
	}
	if len(v.Aliases) > 0 {
		fmtFprintf(&b, "Aliases: %s\n", strings.Join(v.Aliases, ", "))
	}
	return b.String()
}

func resultMessage(v model.Vuln, c model.Component) string {
	msg := v.ID + " affects " + c.Name + "@" + c.Version
	if v.FixedVersion != "" {
		msg += " (fixed in " + v.FixedVersion + ")"
	}
	return msg
}

// sanitizeRuleName converts an id into a SARIF rule name (which must be a
// valid identifier-ish token).
func sanitizeRuleName(id string) string {
	var b strings.Builder
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

func fmtFprintf(b *strings.Builder, format string, args ...any) {
	// strings.Builder never returns a write error.
	_, _ = fmt.Fprintf(b, format, args...)
}

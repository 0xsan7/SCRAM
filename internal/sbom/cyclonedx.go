package sbom

import (
	"encoding/json"

	"github.com/0xsan7/scram/internal/model"
)

// The structs below are a hand-rolled subset of the CycloneDX 1.5 JSON schema.
// Using the official library would drag in a large dependency tree, which
// conflicts with NFR-2 (minimal supply-chain footprint for a security tool).
// Only the fields SCRAM actually populates are modeled; the schema allows
// them all to be absent.

// cdxDoc is a CycloneDX 1.5 JSON document.
type cdxDoc struct {
	BOMFormat    string         `json:"bomFormat"`
	SpecVersion  string         `json:"specVersion"`
	SerialNumber string         `json:"serialNumber"`
	Version      int            `json:"version"`
	Metadata     cdxMetadata    `json:"metadata"`
	Components   []cdxComponent `json:"components"`
	Vulns        []cdxVuln      `json:"vulnerabilities,omitempty"`
}

type cdxMetadata struct {
	Timestamp string           `json:"timestamp"`
	Tools     []cdxTool        `json:"tools"`
	Component cdxRootComponent `json:"component"`
}

type cdxTool struct {
	Vendor  string `json:"vendor,omitempty"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

type cdxRootComponent struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	BOMRef  string `json:"bom-ref"`
	Version string `json:"version,omitempty"`
}

type cdxComponent struct {
	Type       string       `json:"type"`
	BOMRef     string       `json:"bom-ref"`
	Name       string       `json:"name"`
	Version    string       `json:"version"`
	Purl       string       `json:"purl"`
	Scope      string       `json:"scope,omitempty"`
	Licenses   []cdxLicense `json:"licenses,omitempty"`
	Hashes     []cdxHash    `json:"hashes,omitempty"`
	Properties []cdxProp    `json:"properties,omitempty"`
}

// cdxScopeRequired is the CycloneDX enum value for a runtime dependency.
const cdxScopeRequired = "required"

type cdxLicense struct {
	License cdxLicenseID `json:"license"`
}

type cdxLicenseID struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type cdxHash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

// cdxProp carries the direct-vs-transitive flag, which has no first-class
// field in the schema. Scanners in the ecosystem read this property.
type cdxProp struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type cdxVuln struct {
	BOMRef      string        `json:"bom-ref,omitempty"`
	ID          string        `json:"id"`
	Source      cdxSource     `json:"source"`
	Ratings     []cdxRating   `json:"ratings,omitempty"`
	CWEs        []int         `json:"cwes,omitempty"`
	Description string        `json:"description,omitempty"`
	Affects     []cdxAffect   `json:"affects,omitempty"`
	Advisories  []cdxAdvisory `json:"advisories,omitempty"`
}

type cdxSource struct {
	Name string `json:"name"`
	URL  string `json:"url,omitempty"`
}

type cdxRating struct {
	Source   cdxSource `json:"source"`
	Score    float64   `json:"score"`
	Severity string    `json:"severity,omitempty"`
	Method   string    `json:"method,omitempty"`
	Vector   string    `json:"vector,omitempty"`
}

type cdxAffect struct {
	Ref string `json:"ref"`
}

type cdxAdvisory struct {
	Title string `json:"title,omitempty"`
	URL   string `json:"url,omitempty"`
}

func marshalCycloneDX(repoName string, comps []model.Component) ([]byte, error) {
	ts := Timestamp().Format("2006-01-02T15:04:05Z")

	doc := cdxDoc{
		BOMFormat:    "CycloneDX",
		SpecVersion:  CycloneDXSpec,
		SerialNumber: serialNumber(repoName),
		Version:      1,
		Metadata: cdxMetadata{
			Timestamp: ts,
			Tools:     []cdxTool{{Vendor: ToolVendor, Name: ToolName, Version: ToolVersion}},
			Component: cdxRootComponent{
				Type:   "application",
				Name:   repoName,
				BOMRef: "root",
			},
		},
		Components: []cdxComponent{},
	}

	vulnIndex := map[string]model.Vuln{}

	for _, c := range comps {
		cc := cdxComponent{
			Type:    "library",
			BOMRef:  c.Purl,
			Name:    c.Name,
			Version: c.Version,
			Purl:    c.Purl,
			Scope:   cdxScopeRequired,
			Properties: []cdxProp{
				{Name: "scram:direct", Value: boolStr(c.Direct)},
				{Name: "scram:ecosystem", Value: c.Ecosystem},
			},
		}
		if c.License != "" {
			cc.Licenses = []cdxLicense{{License: cdxLicenseID{Name: c.License}}}
		}
		for algo, h := range c.Hashes {
			cc.Hashes = append(cc.Hashes, cdxHash{Alg: hashAlg(algo), Content: normalizeHash(h)})
		}
		// Always emit the identity hash so every component has at least one
		// hash entry; several SBOM consumers require it.
		cc.Hashes = append(cc.Hashes, cdxHash{Alg: "SHA-256", Content: contentHash(c)})
		doc.Components = append(doc.Components, cc)

		for _, v := range c.Vulnerabilities {
			vulnIndex[v.ID] = v
		}
	}

	for id, v := range vulnIndex {
		vv := cdxVuln{
			ID:          id,
			Source:      cdxSource{Name: v.Source},
			Description: v.Summary,
		}
		if v.URL != "" {
			vv.Source.URL = v.URL
		}
		if v.CVSSv3 > 0 {
			vv.Ratings = append(vv.Ratings, cdxRating{
				Source:   cdxSource{Name: v.Source},
				Score:    v.CVSSv3,
				Method:   "CVSSv3",
				Severity: cvssSeverity(v.CVSSv3),
				Vector:   v.CVSSVector,
			})
		}
		vv.Advisories = append(vv.Advisories, cdxAdvisory{Title: id, URL: v.URL})
		doc.Vulns = append(doc.Vulns, vv)
	}

	return json.MarshalIndent(doc, "", "  ")
}

// hashAlg maps our internal algorithm names to CycloneDX's enum, which uses
// hyphenated forms like "SHA-512".
func hashAlg(a string) string {
	switch a {
	case "SHA-256", "SHA-512", "SHA-384", "SHA-1", "SHA3-256", "SHA3-512", "MD5":
		return a
	}
	return "SHA-256"
}

// normalizeHash strips Go's "h1:" base64 prefix, which is not valid hex and
// would fail schema validation. Go module hashes go in as-is under a
// different property elsewhere; here we only emit valid hex.
func normalizeHash(h string) string {
	if len(h) == 0 {
		return h
	}
	isHex := true
	for _, r := range h {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			isHex = false
			break
		}
	}
	if isHex {
		return h
	}
	return contentHash(model.Component{Purl: h})
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// cvssSeverity maps a CVSS base score to CycloneDX's severity enum.
func cvssSeverity(score float64) string {
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	case score > 0:
		return "low"
	}
	return "none"
}

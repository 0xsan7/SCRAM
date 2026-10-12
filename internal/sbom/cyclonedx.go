package sbom

import (
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"

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

func marshalCycloneDX(repoName string, comps []model.Component, version ...string) ([]byte, error) {
	ts := Timestamp().Format("2006-01-02T15:04:05Z")

	doc := cdxDoc{
		BOMFormat:    "CycloneDX",
		SpecVersion:  CycloneDXSpec,
		SerialNumber: serialNumber(repoName),
		Version:      1,
		Metadata: cdxMetadata{
			Timestamp: ts,
			Tools:     []cdxTool{{Vendor: ToolVendor, Name: ToolName, Version: toolVersion(version)}},
			Component: cdxRootComponent{
				Type:   "application",
				Name:   repoName,
				BOMRef: "root",
			},
		},
		Components: []cdxComponent{},
	}

	vulnIndex := map[string]model.Vuln{}
	affected := map[string]map[string]bool{}

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
		for _, algo := range sortedHashKeys(c.Hashes) {
			h := c.Hashes[algo]
			if alg, digest, ok := packageDigest(algo, h); ok {
				cc.Hashes = append(cc.Hashes, cdxHash{Alg: alg, Content: digest})
			} else {
				cc.Properties = append(cc.Properties, cdxProp{Name: "scram:recorded-hash:" + algo, Value: h})
			}
		}
		cc.Properties = append(cc.Properties, cdxProp{Name: "scram:component-identity-sha256", Value: contentHash(c)})
		doc.Components = append(doc.Components, cc)

		for _, v := range c.Vulnerabilities {
			vulnIndex[v.ID] = v
			if affected[v.ID] == nil {
				affected[v.ID] = map[string]bool{}
			}
			affected[v.ID][c.Purl] = true
		}
	}

	ids := make([]string, 0, len(vulnIndex))
	for id := range vulnIndex {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		v := vulnIndex[id]
		vv := cdxVuln{
			ID:          id,
			Source:      cdxSource{Name: v.Source},
			Description: v.Summary,
		}
		refs := make([]string, 0, len(affected[id]))
		for ref := range affected[id] {
			refs = append(refs, ref)
		}
		sort.Strings(refs)
		for _, ref := range refs {
			vv.Affects = append(vv.Affects, cdxAffect{Ref: ref})
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
	switch strings.ToUpper(a) {
	case "SHA256", "SHA-256":
		return "SHA-256"
	case "SHA512", "SHA-512":
		return "SHA-512"
	case "SHA384", "SHA-384":
		return "SHA-384"
	case "SHA1", "SHA-1":
		return "SHA-1"
	case "SHA3-256", "SHA3-512", "MD5":
		return strings.ToUpper(a)
	}
	return ""
}

// Invalid encodings stay out of content checksum fields. In particular,
// hashing a Go h1 checksum string does not create a package content digest.
func normalizeHash(h string) string {
	if _, err := hex.DecodeString(h); err != nil {
		return ""
	}
	return strings.ToLower(h)
}

func packageDigest(algo, h string) (string, string, bool) {
	alg := hashAlg(algo)
	digest := normalizeHash(h)
	sizes := map[string]int{"SHA-256": 64, "SHA-512": 128, "SHA-384": 96, "SHA-1": 40, "SHA3-256": 64, "SHA3-512": 128, "MD5": 32}
	size, ok := sizes[alg]
	return alg, digest, ok && len(digest) == size
}

func sortedHashKeys(hashes map[string]string) []string {
	keys := make([]string, 0, len(hashes))
	for key := range hashes {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
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

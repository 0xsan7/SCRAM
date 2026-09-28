package sbom

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/0xsan7/scram/internal/model"
)

func fixture() []model.Component {
	return []model.Component{
		{
			Purl: "pkg:npm/lodash@4.17.11", Name: "lodash", Version: "4.17.11",
			Ecosystem: model.EcoNPM, Direct: true, License: "MIT",
			Vulnerabilities: []model.Vuln{
				{ID: "CVE-A", Source: "osv", CVSSv3: 9.1, EPSS: 0.05,
					Summary: "Prototype pollution", URL: "https://osv.dev/vulnerability/CVE-A"},
			},
		},
		{
			Purl: "pkg:npm/@scope/pkg@1.0.0", Name: "@scope/pkg", Version: "1.0.0",
			Ecosystem: model.EcoNPM, Direct: false,
		},
	}
}

func TestCycloneDXStructure(t *testing.T) {
	comps := fixture()
	data, err := marshalCycloneDX("my-app", comps)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	if doc["bomFormat"] != "CycloneDX" {
		t.Errorf("bomFormat: got %v, want CycloneDX", doc["bomFormat"])
	}
	if doc["specVersion"] != "1.5" {
		t.Errorf("specVersion: got %v, want 1.5", doc["specVersion"])
	}
	// serialNumber must be a urn:uuid.
	sn, _ := doc["serialNumber"].(string)
	if len(sn) != len("urn:uuid:")+36 {
		t.Errorf("serialNumber %q is not a urn:uuid", sn)
	}

	meta, _ := doc["metadata"].(map[string]any)
	if meta == nil {
		t.Fatal("metadata missing")
	}
	ts, _ := meta["timestamp"].(string)
	if _, err := time.Parse("2006-01-02T15:04:05Z", ts); err != nil {
		t.Errorf("timestamp %q is not RFC3339: %v", ts, err)
	}

	list, _ := doc["components"].([]any)
	if len(list) != len(comps) {
		t.Fatalf("got %d components, want %d", len(list), len(comps))
	}

	first, _ := list[0].(map[string]any)
	if first["type"] != "library" {
		t.Errorf("component type: got %v, want library", first["type"])
	}
	if first["purl"] != "pkg:npm/lodash@4.17.11" {
		t.Errorf("purl: got %v", first["purl"])
	}
	// Every component must carry at least one hash; some consumers require it.
	hashes, _ := first["hashes"].([]any)
	if len(hashes) == 0 {
		t.Error("component has no hashes")
	}
	// Hash content must be valid hex, or schema validation fails.
	for _, h := range hashes {
		hm, _ := h.(map[string]any)
		content, _ := hm["content"].(string)
		if !isHex(content) {
			t.Errorf("hash content %q is not valid hex", content)
		}
	}
}

// TestCycloneDXHashesAreValidHex is a regression test: Go module hashes
// ("h1:...") are base64, not hex, and emitting them verbatim fails schema
// validation.
func TestCycloneDXHashesAreValidHex(t *testing.T) {
	comps := []model.Component{{
		Purl: "pkg:golang/github.com/x/y@v1.0.0", Name: "github.com/x/y",
		Version: "v1.0.0", Ecosystem: model.EcoGo,
		Hashes: map[string]string{"SHA-256": "h1:abcDEF123+/="},
	}}
	data, err := marshalCycloneDX("app", comps)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Components []struct {
			Hashes []struct {
				Alg     string `json:"alg"`
				Content string `json:"content"`
			} `json:"hashes"`
		} `json:"components"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	for _, h := range doc.Components[0].Hashes {
		if !isHex(h.Content) {
			t.Errorf("hash %q (alg %s) is not valid hex", h.Content, h.Alg)
		}
	}
}

func TestSPDXStructure(t *testing.T) {
	comps := fixture()
	data, err := marshalSPDX("my-app", comps)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	if doc["spdxVersion"] != "SPDX-2.3" {
		t.Errorf("spdxVersion: got %v, want SPDX-2.3", doc["spdxVersion"])
	}
	if doc["SPDXID"] != "SPDXRef-DOCUMENT" {
		t.Errorf("SPDXID: got %v", doc["SPDXID"])
	}
	// SPDX requires a data license.
	if doc["dataLicense"] == "" {
		t.Error("dataLicense is required by the SPDX schema")
	}
	// documentNamespace must be a unique URI.
	if ns, _ := doc["documentNamespace"].(string); ns == "" {
		t.Error("documentNamespace is required")
	}

	pkgs, _ := doc["packages"].([]any)
	if len(pkgs) != len(comps) {
		t.Fatalf("got %d packages, want %d", len(pkgs), len(comps))
	}
	first, _ := pkgs[0].(map[string]any)
	// SPDX forbids downloadLocation of "unknown"; NOASSERTION is the valid
	// "we don't know" value, and SCRAM genuinely doesn't download packages.
	if first["downloadLocation"] != "NOASSERTION" {
		t.Errorf("downloadLocation: got %v, want NOASSERTION", first["downloadLocation"])
	}
	if first["filesAnalyzed"] != false {
		t.Error("filesAnalyzed should be false; SCRAM does not read package contents")
	}
	// SPDXIDs may only contain letters, digits, "." and "-".
	id, _ := first["SPDXID"].(string)
	for _, r := range id {
		ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '.' || r == '-'
		if !ok {
			t.Errorf("SPDXID %q contains an invalid character %q", id, r)
		}
	}
	// Every package needs a purl external ref.
	refs, _ := first["externalRefs"].([]any)
	if len(refs) == 0 {
		t.Error("package has no externalRefs")
	}
}

// TestBothFormatsAgree is the property that keeps the two SBOMs honest: they
// are generated from one component list, so they must never disagree about
// how many components exist.
func TestBothFormatsAgree(t *testing.T) {
	comps := fixture()
	cdx, err := marshalCycloneDX("app", comps)
	if err != nil {
		t.Fatal(err)
	}
	spdx, err := marshalSPDX("app", comps)
	if err != nil {
		t.Fatal(err)
	}
	var a struct {
		Components []any `json:"components"`
	}
	var b struct {
		Packages []any `json:"packages"`
	}
	if err := json.Unmarshal(cdx, &a); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(spdx, &b); err != nil {
		t.Fatal(err)
	}
	if len(a.Components) != len(b.Packages) {
		t.Errorf("CycloneDX has %d components, SPDX has %d packages; they must agree",
			len(a.Components), len(b.Packages))
	}
}

// TestSerialNumberIsDeterministic matters because the SBOM is committed as a
// release artifact: a random serial would make every regeneration a diff.
func TestSerialNumberIsDeterministic(t *testing.T) {
	// These were `!=` where `==` was meant, so each assertion could only
	// fail if the function was already correct. staticcheck caught the
	// identical-operands form; the inversion in the third check was the
	// real problem, and it was hiding behind the other two.
	if serialNumber("app") != serialNumber("app") {
		t.Error("serialNumber must be stable for the same repo")
	}
	if serialNumber("app") == serialNumber("other") {
		t.Error("serialNumber must differ between repos")
	}
	if spdxNamespace("app") != spdxNamespace("app") {
		t.Error("spdxNamespace must be stable for the same repo")
	}
	if spdxNamespace("app") == spdxNamespace("other") {
		t.Error("spdxNamespace must differ between repos")
	}
}

func TestWriteBothFormats(t *testing.T) {
	dir := t.TempDir()
	for _, f := range []Format{FormatCycloneDX, FormatSPDX} {
		p, err := Write(dir, "app", f, fixture())
		if err != nil {
			t.Fatalf("Write(%s): %v", f, err)
		}
		if _, err := os.Stat(p); err != nil {
			t.Errorf("expected %s to exist: %v", p, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "sbom.cdx.json")); err != nil {
		t.Error("CycloneDX file not written under the expected name")
	}
	if _, err := os.Stat(filepath.Join(dir, "sbom.spdx.json")); err != nil {
		t.Error("SPDX file not written under the expected name")
	}
}

func TestWriteRejectsUnknownFormat(t *testing.T) {
	_, err := Write(t.TempDir(), "app", Format("swid"), fixture())
	if err == nil {
		t.Error("expected an error for an unknown SBOM format")
	}
}

func TestEmptyComponentListIsValid(t *testing.T) {
	// An empty scan must still produce a schema-valid document, not null.
	for _, tc := range []struct {
		name string
		fn   func(string, []model.Component) ([]byte, error)
		key  string
	}{
		{"cyclonedx", marshalCycloneDX, "components"},
		{"spdx", marshalSPDX, "packages"},
	} {
		data, err := tc.fn("app", nil)
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string]any
		if err := json.Unmarshal(data, &doc); err != nil {
			t.Fatal(err)
		}
		v, present := doc[tc.key]
		if !present {
			t.Errorf("%s: %q key missing; an empty list must serialize as [] not be omitted",
				tc.name, tc.key)
		} else if v == nil {
			t.Errorf("%s: %q is null; schema validators reject null for a required array", tc.name, tc.key)
		}
	}
}

func TestSpdxLicenseHandling(t *testing.T) {
	cases := map[string]string{
		"":                  "NOASSERTION",
		"MIT":               "MIT",
		"Apache-2.0":        "Apache-2.0",
		"NOASSERTION":       "NOASSERTION",
		"MIT OR Apache-2.0": "MIT OR Apache-2.0",
	}
	for in, want := range cases {
		if got := spdxLicense(in); got != want {
			t.Errorf("spdxLicense(%q) = %q, want %q", in, got, want)
		}
	}
}

func isHex(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}

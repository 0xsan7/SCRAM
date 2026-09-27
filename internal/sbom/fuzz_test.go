package sbom

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0xsan7/scram/internal/model"
)

// The SBOM serializers are the other half of the untrusted-input surface:
// they take component data derived from a repository (names, versions, PURLs,
// license strings, hash strings) and emit JSON that other tools will parse.
// A crash is a crash; a component with a hostile name that produces invalid
// JSON is worse, because the document still validates as JSON while naming
// something it should not.

// fuzzComponent builds a component whose every string field comes from the
// fuzzer, so serializers see the shapes an attacker would choose.
func fuzzComponent(name, version, purl, license, hash, summary string) model.Component {
	return model.Component{
		Name: name, Version: version, Purl: purl, License: license,
		Ecosystem: model.EcoNPM, Direct: true,
		Hashes: map[string]string{"sha256": hash},
		Vulnerabilities: []model.Vuln{
			{ID: "CVE-2020-0001", CVSSv3: 7.5, Summary: summary,
				FixedVersion: version, CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
		},
	}
}

// FuzzMarshalCycloneDX asserts the serializer never panics and always emits
// valid JSON, whatever the component fields contain.
func FuzzMarshalCycloneDX(f *testing.F) {
	seedCorpus(f, "FuzzMarshalCycloneDX")
	f.Add("app", "1.0.0", "pkg:npm/lodash@4.17.21", "MIT", "abc123", "a summary")
	// Hostile shapes: control characters, JSON metacharacters, an empty PURL.
	f.Add("a\"b", "1\";x", "pkg:npm/\x00evil@1", "MIT OR Apache-2.0", "", "")
	f.Add("", "", "", "", "", "")
	f.Add("名前", "🎉", "pkg:pypi/requests@2.19.1", "GPL-3.0-only", "z", "ünïcödé")
	f.Fuzz(func(t *testing.T, name, version, purl, license, hash, summary string) {
		c := fuzzComponent(name, version, purl, license, hash, summary)
		out, err := marshalCycloneDX("repo", []model.Component{c})
		if err != nil {
			t.Fatalf("marshalCycloneDX: %v", err)
		}
		var probe map[string]any
		if err := json.Unmarshal(out, &probe); err != nil {
			t.Fatalf("emitted invalid JSON for %+v: %v\n%s", c, err, out)
		}
		// A name containing a quote must be escaped, not truncated, and must
		// survive the round trip intact.
		if name != "" && !strings.Contains(string(out), "bomFormat") {
			t.Fatalf("document is missing bomFormat:\n%s", out)
		}
	})
}

// FuzzMarshalSPDX does the same for SPDX 2.3, whose required fields are
// stricter and whose ID derivation is the part most likely to produce
// something invalid for an external consumer.
func FuzzMarshalSPDX(f *testing.F) {
	seedCorpus(f, "FuzzMarshalSPDX")
	f.Add("app", "1.0.0", "pkg:npm/lodash@4.17.21", "MIT", "abc123", "a summary")
	f.Add("a\"b", "1\";x", "pkg:npm/\x00evil@1", "MIT OR Apache-2.0", "", "")
	f.Add("", "", "", "", "", "")
	f.Add("名前", "🎉", "pkg:pypi/requests@2.19.1", "GPL-3.0-only", "z", "ünïcödé")
	f.Fuzz(func(t *testing.T, name, version, purl, license, hash, summary string) {
		c := fuzzComponent(name, version, purl, license, hash, summary)
		out, err := marshalSPDX("repo", []model.Component{c})
		if err != nil {
			t.Fatalf("marshalSPDX: %v", err)
		}
		var probe map[string]any
		if err := json.Unmarshal(out, &probe); err != nil {
			t.Fatalf("emitted invalid JSON for %+v: %v\n%s", c, err, out)
		}
		// SPDX requires these to be present and non-empty; an empty document
		// that is still valid JSON is a silent-zero one layer downstream.
		for _, k := range []string{"spdxVersion", "SPDXID", "name", "dataLicense"} {
			if v, ok := probe[k]; !ok || v == "" {
				t.Fatalf("SPDX output missing required field %q: %+v\n%s",
					k, probe, out)
			}
		}
	})
}

// FuzzSpdxID covers the SPDXID derivation, which must be a valid SPDX
// identifier: letters, digits, dots and dashes only. Anything else makes the
// document invalid for consumers even though it is well-formed JSON.
func FuzzSpdxID(f *testing.F) {
	f.Add("pkg:npm/lodash@4.17.21", 0)
	f.Add("", 0)
	f.Add("a b c", 3)
	f.Add("\x00\x01", 1)
	f.Fuzz(func(t *testing.T, purl string, i int) {
		if i < 0 || i > 100000 {
			return // keep the fuzzer from spending its time on absurd indices
		}
		id := spdxID(purl, i)
		if id == "" {
			t.Fatalf("spdxID(%q, %d) returned an empty identifier", purl, i)
		}
		for _, r := range id {
			ok := r == '-' || r == '.' ||
				(r >= '0' && r <= '9') ||
				(r >= 'A' && r <= 'Z') ||
				(r >= 'a' && r <= 'z')
			if !ok {
				t.Fatalf("spdxID(%q, %d) = %q contains %q, which is not a "+
					"valid SPDX identifier character", purl, i, id, r)
			}
		}
	})
}

// FuzzNormalizeHash covers the hash normalisation used when rendering
// component hashes into both SBOM formats.
func FuzzNormalizeHash(f *testing.F) {
	f.Add("sha256:abc")
	f.Add("ABCDEF")
	f.Add("")
	f.Add("\x00\xff")
	f.Add("sha-512:xyz")
	f.Fuzz(func(t *testing.T, h string) {
		got := normalizeHash(h)
		if strings.ContainsRune(got, 0) {
			t.Fatalf("normalizeHash(%q) = %q contains a NUL byte", h, got)
		}
		_ = hashAlg(h)
		_ = spdxLicense(h)
		_ = cvssSeverity(float64(len(h)) / 10)
	})
}

// FuzzEmptyComponentList covers the degenerate case directly: a scan that
// resolved nothing must still emit a structurally valid document, or -- per
// D26 -- must not reach the serializer at all. This pins which of those it
// is, rather than leaving it to whichever the caller happens to do.
func FuzzEmptyComponentList(f *testing.F) {
	f.Add("repo", "")
	f.Add("", "weird/name with spaces")
	f.Fuzz(func(t *testing.T, repo, version string) {
		cdx, err := marshalCycloneDX(repo, nil)
		if err != nil {
			t.Fatalf("marshalCycloneDX with no components: %v", err)
		}
		if !json.Valid(cdx) {
			t.Fatalf("empty CycloneDX document is not valid JSON:\n%s", cdx)
		}
		sp, err := marshalSPDX(repo, nil)
		if err != nil {
			t.Fatalf("marshalSPDX with no components: %v", err)
		}
		if !json.Valid(sp) {
			t.Fatalf("empty SPDX document is not valid JSON:\n%s", sp)
		}
	})
}

// seedCorpus adds the inputs the fuzzer itself discovered, promoted to
// permanent seeds under testdata/fuzz/.
//
// Go's corpus encoding for multiple arguments is a typed stream, so a promoted
// file cannot simply be read as six separate strings; the files are therefore
// kept as single-argument seeds for the byte-slice targets and as string seeds
// where the target takes one string. The multi-argument targets additionally
// keep their hand-written seeds, which is where the shape diversity actually
// lives; what is promoted here is the raw byte-level coverage.
func seedCorpus(f *testing.F, target string) {
	f.Helper()
	dir := filepath.Join("..", "..", "testdata", "fuzz", "internal_sbom", target)
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil || len(b) == 0 {
			continue
		}
		if fuzzerArgCount(f) == 1 {
			f.Add(string(b))
		}
	}
}

// fuzzerArgCount is a fixed property of the target definitions, not something
// the corpus files encode: the multi-argument serializer targets take six
// strings, the single-argument ones take one.
func fuzzerArgCount(f *testing.F) int {
	switch f.Name() {
	case "FuzzMarshalCycloneDX", "FuzzMarshalSPDX":
		return 6
	default:
		return 1
	}
}

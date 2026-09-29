package resolve

import (
	"context"
	"os"
	"sort"
	"testing"

	"github.com/0xsan7/scram/internal/vuln"
)

// TestTheTwoGoPathsFindTheSameVulnerabilities is the known-vulnerable
// roundtrip for the Go ecosystem, in its hardest form.
//
// A project that ships BOTH a go.sum and a go.mod is the natural control:
// the two files describe the same dependency set, so the two code paths must
// return the same vulnerabilities. They did not. The go.mod fallback set
// Name to the bare last path segment, the OSV client queries by Name, and OSV
// keys its Go ecosystem on the module path -- so "github.com/gin-gonic/gin"
// was looked up as "gin" and matched nothing, while the go.sum path found the
// advisories correctly. The go.mod scan reported CLEAN.
//
// Comparing the two paths is what exposed it, and it is a stronger assertion
// than either path alone: neither a correct PURL nor a plausible component
// name says anything about whether the lookup key is the one the registry
// indexes.
//
// This test is network-dependent by nature, so it is skipped unless
// SCRAM_LIVE_OSV=1, matching the other live checks in this project.
func TestTheTwoGoPathsFindTheSameVulnerabilities(t *testing.T) {
	requireLive(t)

	const base = "../../testdata/fixtures/gomod/real/aquasecurity/trivy"
	if _, err := os.Stat(base + "/go.sum"); err != nil {
		t.Skipf("corpus missing: %v (run scripts/fetch_corpus.py go)", err)
	}

	findings := func(filename string) map[string][]string {
		t.Helper()
		ctx := context.Background()
		r, err := GetFor("go", filename)
		if err != nil {
			t.Fatalf("GetFor(go, %s): %v", filename, err)
		}
		comps, err := ResolveFile(r, base, filename)
		if err != nil {
			t.Fatalf("ResolveFile(%s): %v", filename, err)
		}
		if len(comps) == 0 {
			t.Fatalf("%s resolved to zero components", filename)
		}
		// The PRODUCTION client, so the lookup key under test is the
		// production one. A test that hand-builds its own query would pass
		// even while the shipped code used the wrong key.
		c := vuln.NewClient(nil)
		if err := c.QueryOSV(ctx, comps); err != nil {
			t.Fatalf("QueryOSV(%s): %v", filename, err)
		}
		out := map[string][]string{}
		for _, comp := range comps {
			if len(comp.Vulnerabilities) == 0 {
				continue
			}
			ids := make([]string, 0, len(comp.Vulnerabilities))
			for _, v := range comp.Vulnerabilities {
				ids = append(ids, v.ID)
			}
			sort.Strings(ids)
			out[comp.Name] = ids
		}
		return out
	}

	fromSum, fromMod := findings("go.sum"), findings("go.mod")

	// The property that matters: a vulnerable dependency must be visible
	// through BOTH paths. If either is empty, the lookup key is wrong.
	if len(fromSum) == 0 {
		t.Fatal("the go.sum path found no vulnerabilities; the corpus entry is no longer a control")
	}
	if len(fromMod) == 0 {
		t.Fatal("the go.mod path found no vulnerabilities. This is the exact bug " +
			"fixed in af8e58f: the lookup key was the bare package name instead of " +
			"the module path, so OSV matched nothing and the scan reported CLEAN.")
	}

	// And they must agree on WHICH dependencies are vulnerable, not merely
	// on there being some.
	onlySum := diffKeys(fromSum, fromMod)
	onlyMod := diffKeys(fromMod, fromSum)
	for _, k := range onlySum {
		t.Errorf("vulnerable via go.sum but NOT via go.mod: %s -> %v", k, fromSum[k])
	}
	for _, k := range onlyMod {
		t.Errorf("vulnerable via go.mod but NOT via go.sum: %s -> %v", k, fromMod[k])
	}
	t.Logf("both paths agree on %d vulnerable modules", len(fromSum))
}

func diffKeys(a, b map[string][]string) []string {
	var out []string
	for k := range a {
		if _, ok := b[k]; !ok {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// requireLive gates a test that makes real network calls.
//
// The known-vulnerable roundtrip is the only assertion in this project that
// can prove a LOOKUP KEY is correct rather than merely well-formed: the
// registry has to be the real one. That makes it unsuitable for a unit-test
// run, so it is opt-in via SCRAM_LIVE_OSV=1 and skipped by default rather
// than being quietly deleted -- the offline form of the same property is
// TestKnownVulnerableRoundtripOffline, which replays recorded OSV responses.
func requireLive(t *testing.T) {
	t.Helper()
	if os.Getenv("SCRAM_LIVE_OSV") != "1" {
		t.Skip("set SCRAM_LIVE_OSV=1 to run live OSV roundtrip checks")
	}
}

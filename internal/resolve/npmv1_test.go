package resolve

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// D30: SCRAM parses npm lockfileVersion 1 (the legacy npm 5/6 nested
// "dependencies" tree) but has no real npm 6 lockfile in its corpus, because
// npm 6 is EOL and nothing the fetcher can reach still commits one. The v1
// path was therefore only ever exercised by hand-authored fixtures, which
// D24 says inherit the author's blind spots -- so it looked covered and was
// not.
//
// The fix is not a synthetic fixture pretending to be real data. It is to
// parse the file AND say plainly that its results are unverified.

func writeLock(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestNpmV1WarnsAndV2V3DoesNot is the core behaviour: the warning must appear
// for exactly the formats that lack corpus coverage, and stay silent
// otherwise. A warning that fires on everything is noise, and noise is how a
// real signal gets ignored.
func TestNpmV1WarnsAndV2V3DoesNot(t *testing.T) {
	cases := []struct {
		name        string
		body        string
		wantWarning bool
	}{
		{
			name: "v1 explicit",
			body: `{"name":"x","lockfileVersion":1,"requires":true,
			        "dependencies":{"lodash":{"version":"4.17.4"}}}`,
			wantWarning: true,
		},
		{
			// npm 4/5 predate the field entirely and wrote a v1-shaped tree.
			// Absent must NOT be read as "modern": that would apply the most
			// confidence to the least evidence.
			name:        "absent lockfileVersion",
			body:        `{"name":"x","requires":true,"dependencies":{"lodash":{"version":"4.17.4"}}}`,
			wantWarning: true,
		},
		{
			name:        "v2",
			body:        `{"name":"x","lockfileVersion":2,"packages":{"":{"name":"x"},"node_modules/lodash":{"version":"4.17.21"}}}`,
			wantWarning: false,
		},
		{
			name:        "v3",
			body:        `{"name":"x","lockfileVersion":3,"packages":{"":{"name":"x"},"node_modules/lodash":{"version":"4.17.21"}}}`,
			wantWarning: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := writeLock(t, c.body)
			got := WarningsFor(npmResolver{}, dir, "package-lock.json")
			if c.wantWarning && len(got) == 0 {
				t.Fatal("expected an npm v1 coverage warning, got none")
			}
			if !c.wantWarning && len(got) != 0 {
				t.Errorf("unexpected warning on a modern lockfile: %v", got)
			}
			if c.wantWarning {
				// The message has to be actionable and honest: it must name
				// the gap and say what to do, not merely say "v1".
				w := got[0]
				for _, want := range []string{"lockfileVersion 1", "real-world corpus fixtures", "npm 7+"} {
					if !strings.Contains(w, want) {
						t.Errorf("warning missing %q:\n%s", want, w)
					}
				}
			}
		})
	}
}

// TestNpmV1WarningDoesNotBreakAWorkingScan pins the distinction between a
// warning and a failure. A v1 lockfile must still resolve its components: the
// problem is unproven coverage, not unreadable data. If this ever becomes an
// error, SCRAM would refuse to scan every legacy repo outright, which is a
// different (and much worse) product decision than flagging one.
func TestNpmV1WarningDoesNotBreakAWorkingScan(t *testing.T) {
	dir := writeLock(t, `{"name":"x","lockfileVersion":1,"requires":true,
		"dependencies":{"lodash":{"version":"4.17.4"},"minimist":{"version":"1.2.0"}}}`)
	comps, err := ResolveFile(npmResolver{}, dir, "package-lock.json")
	if err != nil {
		t.Fatalf("a v1 lockfile with a coverage warning must still resolve: %v", err)
	}
	if len(comps) != 2 {
		t.Errorf("got %d components, want 2: a warning must not suppress results", len(comps))
	}
	if w := WarningsFor(npmResolver{}, dir, "package-lock.json"); len(w) != 1 {
		t.Errorf("got %d warnings, want 1", len(w))
	}
}

// TestNpmWarningIsNotResidueFromAPreviousRun guards against the warning being
// computed from stale state. WarningsFor re-reads the file every time, so
// switching a directory from v1 to v3 must clear it.
func TestNpmWarningIsNotResidueFromAPreviousRun(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "package-lock.json")

	if err := os.WriteFile(p, []byte(`{"lockfileVersion":1,"dependencies":{"a":{"version":"1.0.0"}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := WarningsFor(npmResolver{}, dir, "package-lock.json"); len(got) != 1 {
		t.Fatalf("v1: got %d warnings, want 1", len(got))
	}
	if err := os.WriteFile(p, []byte(`{"lockfileVersion":3,"packages":{"":{"name":"x"}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := WarningsFor(npmResolver{}, dir, "package-lock.json"); len(got) != 0 {
		t.Errorf("after rewriting as v3 the warning persisted: %v", got)
	}
}

// TestWarningsForIsSafeOnMissingAndMalformedFiles keeps the advisory path from
// becoming a crash path. A file that does not exist, or is not JSON, is the
// silent-zero invariant's problem to report, not this one's.
func TestWarningsForIsSafeOnMissingAndMalformedFiles(t *testing.T) {
	dir := t.TempDir()
	if got := WarningsFor(npmResolver{}, dir, "nope.json"); got != nil {
		t.Errorf("missing file: got %v, want nil", got)
	}
	if err := os.WriteFile(filepath.Join(dir, "bad.json"), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := WarningsFor(npmResolver{}, dir, "bad.json"); got != nil {
		t.Errorf("malformed file: got %v, want nil", got)
	}
}

// TestNpmV1CoverageIsRealAndClaimedHonestly is the honesty check.
//
// The warning tells the user "covered by N real-world corpus fixtures". If N
// were a hardcoded literal, that sentence would be a claim nobody verifies --
// exactly the D-series failure moved into user-facing text. So the count is
// derived from the corpus, and these tests assert the two agree.
//
// The first version of this file asserted the corpus contained NO v1 files,
// which was true when written and is now false. The test was updated rather
// than deleted, because "the corpus gained coverage" is exactly the event it
// was written to detect.
func TestNpmV1CoverageIsRealAndClaimedHonestly(t *testing.T) {
	files := corpusFiles(t, filepath.Join("npm", "real"), isAnyLockfile)
	if len(files) == 0 {
		t.Skip("no npm corpus fixtures present")
	}
	var v1 []string
	for _, f := range files {
		dir := filepath.Dir(f)
		if w := WarningsFor(npmResolver{}, dir, filepath.Base(f)); len(w) > 0 {
			v1 = append(v1, filepath.Base(dir))
		}
	}
	if len(v1) == 0 {
		t.Fatal("corpus contains no v1-shaped npm lockfiles, so the v1 code " +
			"path has no real-world coverage. Either add fixtures or remove " +
			"the v1 warning; do not let the claim and the corpus disagree")
	}
	// Every v1 fixture must actually resolve, or "covered by N fixtures"
	// is true only in the most literal sense.
	for _, f := range files {
		dir := filepath.Dir(f)
		if w := WarningsFor(npmResolver{}, dir, filepath.Base(f)); len(w) == 0 {
			continue
		}
		comps, err := ResolveFile(npmResolver{}, dir, filepath.Base(f))
		if err != nil {
			t.Errorf("%s: v1 fixture failed to resolve: %v", filepath.Base(dir), err)
		}
		if len(comps) == 0 {
			t.Errorf("%s: v1 fixture resolved 0 components", filepath.Base(dir))
		}
	}
	t.Logf("v1 coverage: %d real fixtures (%v)", len(v1), v1)
}

// TestNpmV1WarningStatesTheRealCount checks the number in the message equals
// the corpus count, so the sentence cannot drift into a fabricated claim.
func TestNpmV1WarningStatesTheRealCount(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"),
		[]byte(`{"lockfileVersion":1,"dependencies":{"a":{"version":"1.0.0"}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	got := WarningsFor(npmResolver{}, dir, "package-lock.json")
	if len(got) != 1 {
		t.Fatalf("want 1 warning, got %d", len(got))
	}
	n := npmV1CorpusCount()
	if n == 0 {
		t.Skip("no v1 fixtures in the corpus")
	}
	if !strings.Contains(got[0], fmt.Sprintf("covered by %d real-world corpus fixtures", n)) {
		t.Errorf("warning does not state the real corpus count %d:\n%s", n, got[0])
	}
}

// TestNpmCorpusCoversEveryLockfileVersion pins the exact per-version counts.
//
// Presence alone is not coverage: one v1 fixture would leave the v2 path (a
// different code branch, "packages" + "dependencies") unexercised without
// any test failing. These are the current counts, and a change to them is a
// deliberate act that must update this test and LIMITATIONS.md together.
func TestNpmCorpusCoversEveryLockfileVersion(t *testing.T) {
	files := corpusFiles(t, filepath.Join("npm", "real"), isAnyLockfile)
	if len(files) == 0 {
		t.Skip("no npm corpus fixtures present")
	}
	counts := map[string]int{}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		var probe struct {
			LockfileVersion *int `json:"lockfileVersion"`
		}
		if err := json.Unmarshal(b, &probe); err != nil {
			t.Errorf("%s: not valid JSON: %v", f, err)
			continue
		}
		// Absent means npm 5 or earlier, which is the v1 tree.
		v := "1"
		if probe.LockfileVersion != nil {
			v = strconv.Itoa(*probe.LockfileVersion)
		}
		counts[v]++
	}
	want := map[string]int{"1": 6, "2": 1, "3": 9}
	if len(counts) < 3 {
		t.Errorf("npm corpus covers only lockfile versions %v; every major "+
			"version in production needs at least one fixture", counts)
	}
	for v, n := range want {
		if counts[v] != n {
			t.Errorf("lockfileVersion %s: have %d fixtures, want %d (all: %v)",
				v, counts[v], n, counts)
		}
	}
}

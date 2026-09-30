package resolve

// This file exists for one thing: to keep diff_vulns.py's alias
// canonicalization honest. The comparator is a Python script, so its
// behaviour is pinned from here via the real subprocess rather than by
// re-implementing the logic in Go, which would test a copy instead of the
// thing that runs.

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const diffVulnsScript = "../../scripts/diff_vulns.py"

// runCanonicalizer executes diff_vulns.canonical with a stubbed alias table
// and returns the alias classes it produced.
//
// The alias table travels on stdin rather than inline: it is multi-line JSON,
// and embedding a multi-line literal in a `python3 -c` program is a quoting
// trap that fails in a way that looks like the code under test being broken.
func runCanonicalizer(t *testing.T, ids []string, aliasJSON string) int {
	t.Helper()
	full, err := filepath.Abs(diffVulnsScript)
	if err != nil {
		t.Fatal(err)
	}
	prog := "import importlib.util, json, sys" + "\n" +
		"spec = importlib.util.spec_from_file_location('dv', " + shellQuote(full) + ")" + "\n" +
		"m = importlib.util.module_from_spec(spec)" + "\n" +
		"try:" + "\n    spec.loader.exec_module(m)" + "\n" +
		"except SystemExit:" + "\n    pass" + "\n" +
		"payload = json.load(sys.stdin)" + "\n" +
		"m.aliases_for = lambda v: set(payload['aliases'].get(v, [v]))" + "\n" +
		"print(json.dumps(sorted(m.canonical(payload['ids']))))" + "\n"

	cmd := exec.Command(pythonCmd(t), "-c", prog)
	cmd.Dir = repoRoot(t)
	cmd.Stdin = strings.NewReader(mustJSON(t, map[string]any{
		"aliases": json.RawMessage(aliasJSON),
		"ids":     ids,
	}))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("canonicalizer failed: %v\n%s", err, out)
	}
	var classes []string
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(out))), &classes); err != nil {
		t.Fatalf("canonicalizer output is not JSON: %v\n%s", err, out)
	}
	return len(classes)
}

func runCanonicalNames(t *testing.T, ids []string, aliasJSON string) []string {
	t.Helper()
	full, err := filepath.Abs(diffVulnsScript)
	if err != nil {
		t.Fatal(err)
	}
	prog := "import importlib.util, json, sys" + "\n" +
		"spec = importlib.util.spec_from_file_location('dv', " + shellQuote(full) + ")" + "\n" +
		"m = importlib.util.module_from_spec(spec)" + "\n" +
		"try:" + "\n    spec.loader.exec_module(m)" + "\n" +
		"except SystemExit:" + "\n    pass" + "\n" +
		"payload = json.load(sys.stdin)" + "\n" +
		"m.aliases_for = lambda v: set(payload['aliases'].get(v, [v]))" + "\n" +
		"print(json.dumps(sorted(m.canonical(payload['ids']))))" + "\n"

	cmd := exec.Command(pythonCmd(t), "-c", prog)
	cmd.Dir = repoRoot(t)
	cmd.Stdin = strings.NewReader(mustJSON(t, map[string]any{
		"aliases": json.RawMessage(aliasJSON),
		"ids":     ids,
	}))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("canonicalizer failed: %v\n%s", err, out)
	}
	var names []string
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(out))), &names); err != nil {
		t.Fatalf("canonicalizer output is not JSON: %v\n%s", err, out)
	}
	return names
}

// pythonCmd returns the interpreter to use, or skips the test.
//
// These tests drive scripts/diff_vulns.py because re-implementing its logic
// in Go would test a copy, not the thing that runs. The interpreter is
// resolved per platform: windows-latest provides `python`, and `python3` is
// not reliably on PATH there under that exact name -- which is why the first
// version of this file failed on both Windows Go versions.
func pythonCmd(t *testing.T) string {
	t.Helper()
	candidates := []string{"python3", "python"}
	if runtime.GOOS == "windows" {
		candidates = []string{"python", "python3"}
	}
	for _, c := range candidates {
		if p, err := exec.LookPath(c); err == nil {
			return p
		}
	}
	t.Skip("no python interpreter on PATH; skipping diff_vulns.py behaviour tests")
	return ""
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func repoRoot(t *testing.T) string {
	t.Helper()
	d, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// TestAliasClassesMergeTransitively pins the one property that keeps the
// comparator from inventing disagreements.
//
// The grype/SCRAM "5 vs 7" difference on lodash 4.17.11 was NOT a missing
// advisory. OSV returns a record per alias rather than one per advisory, so
// two of the seven records were reciprocally aliased to two of the other five.
// A comparator that compares id strings reports that as SCRAM missing two
// findings, which is a false accusation of a real product bug.
//
// The harder case is a CHAIN: A -> B -> C, with only A and C present in the
// two tools' output. Unioning each id with its direct aliases merges nothing
// there, because B is in neither set. Only transitive closure catches it. No
// such chain exists in the lodash data -- deleting the closure loop changes
// no observed result, which is why this test exists rather than a comment:
// the loop is insurance, and insurance that has never been exercised is
// indistinguishable from a no-op.
func TestAliasClassesMergeTransitively(t *testing.T) {
	aliases := `{
		"A": ["B"],
		"B": ["A", "C"],
		"C": ["B"],
		"LONELY": ["LONELY"]
	}`

	// A and C are the same advisory, reached through B, which neither tool
	// reported. They must collapse to ONE class.
	if got := runCanonicalizer(t, []string{"A", "C"}, aliases); got != 1 {
		t.Errorf("A and C alias each other through B; expected 1 class, got %d", got)
	}

	// A, B and C together: still one class.
	if got := runCanonicalizer(t, []string{"A", "B", "C"}, aliases); got != 1 {
		t.Errorf("expected A, B, C to form 1 class, got %d", got)
	}

	// An unrelated advisory must not be dragged in.
	if got := runCanonicalizer(t, []string{"A", "C", "LONELY"}, aliases); got != 2 {
		t.Errorf("expected 2 classes (A/C and LONELY), got %d", got)
	}
}

// TestAliasClassesCollapseTheRealLodashPair is the regression for the actual
// investigation: the two ids grype reported and SCRAM did not are aliases of
// two SCRAM did report.
func TestAliasClassesCollapseTheRealLodashPair(t *testing.T) {
	// The real OSV records for lodash 4.17.11, verbatim. A CVE is a leaf:
	// OSV returns no alias list for one, which the stub models as [v] so the
	// transitive walk terminates the way it does against the real API.
	aliases := `{
		"GHSA-29mw-wpgm-hmr9": ["CVE-2020-28500"],
		"GHSA-35jh-r3h4-6jhm": ["CVE-2021-23337", "CVE-2026-4800", "GHSA-r5fr-rjxr-66jc"],
		"GHSA-f23m-r3pf-42rh": ["CVE-2025-13465", "CVE-2026-2950", "GHSA-xxjr-mmjv-4gpg"],
		"GHSA-jf85-cpcp-j695": ["CVE-2019-10744", "SNYK-JS-LODASH-450202"],
		"GHSA-p6mc-m468-83gw": ["CVE-2020-8203"],
		"GHSA-r5fr-rjxr-66jc": ["CVE-2021-23337", "CVE-2026-4800", "GHSA-35jh-r3h4-6jhm"],
		"GHSA-xxjr-mmjv-4gpg": ["CVE-2025-13465", "CVE-2026-2950", "GHSA-f23m-r3pf-42rh"]
	}`
	seven := []string{
		"GHSA-29mw-wpgm-hmr9", "GHSA-35jh-r3h4-6jhm", "GHSA-f23m-r3pf-42rh",
		"GHSA-jf85-cpcp-j695", "GHSA-p6mc-m468-83gw", "GHSA-r5fr-rjxr-66jc",
		"GHSA-xxjr-mmjv-4gpg",
	}
	five := []string{
		"GHSA-29mw-wpgm-hmr9", "GHSA-35jh-r3h4-6jhm", "GHSA-f23m-r3pf-42rh",
		"GHSA-jf85-cpcp-j695", "GHSA-p6mc-m468-83gw",
	}
	if got := runCanonicalizer(t, seven, aliases); got != 5 {
		t.Errorf("OSV's 7 records should be 5 advisories, got %d classes", got)
	}
	if got := runCanonicalizer(t, five, aliases); got != 5 {
		t.Errorf("SCRAM's 5 records should be 5 advisories, got %d classes", got)
	}
}

// TestAliasClassRepresentativeIgnoresWhichToolReportedIt is the regression for
// the SECOND alias bug, found only after the first was fixed.
//
// After the transitive walk was correct, four PYSEC ids still appeared as
// "SCRAM only" while grype reported the corresponding GHSAs. The union was
// right; choosing the class REPRESENTATIVE was not. Classes were built from
// the input ids only, so the representative was picked from whichever names
// the tools happened to use, and two tools landed on different names for the
// same class.
//
// Here one tool reports a PYSEC id and the other reports an id that is only
// reachable as an intermediate alias -- never named by either tool directly.
// The class must still get one representative, chosen from the whole closure.
func TestAliasClassRepresentativeIgnoresWhichToolReportedIt(t *testing.T) {
	// GRYPE-ONLY-ID is an alias of PYSEC-ID but is not itself an alias of
	// anything in the input, so it can only be reached by walking.
	aliases := `{
		"PYSEC-ID": ["CVE-2099-0001", "GHSA-missing-only"],
		"GHSA-missing-only": ["CVE-2099-0001", "PYSEC-ID"]
	}`

	scramSide := []string{"PYSEC-ID"}
	grypeSide := []string{"GHSA-missing-only"}

	// Each tool, canonicalized alone, must land on the same name.
	cs := runCanonicalNames(t, scramSide, aliases)
	cg := runCanonicalNames(t, grypeSide, aliases)
	if len(cs) != 1 || len(cg) != 1 {
		t.Fatalf("expected 1 class each, got scram=%v grype=%v", cs, cg)
	}
	if cs[0] != cg[0] {
		t.Errorf("same advisory canonicalized to different names: scram=%v grype=%v",
			cs, cg)
	}
	if cs[0] != "CVE-2099-0001" {
		t.Errorf("expected the class CVE as representative, got %q", cs[0])
	}
}

// TestAliasLookupFailureIsNotSilent guards the bug that made all of the above
// necessary.
//
// aliases_for originally caught every exception and returned {vid}, so on a
// machine whose urllib has no CA bundle the canonicalizer silently became the
// identity function and compared raw id strings -- reporting aliases as
// findings. It must raise instead, and only degrade when explicitly asked.
//
// This test drives the REAL _fetch_alias_group, not a stub of aliases_for.
// An earlier version of this test stubbed aliases_for itself, which meant it
// could not see the swallow inside _fetch_alias_group: reintroducing the
// original bug passed. That is D45's exact pattern -- a guard that only
// exercises the spelling of the defect it claims to catch -- found in the
// guard written to prevent D45's exact pattern.
func TestAliasLookupFailureIsNotSilent(t *testing.T) {
	full, err := filepath.Abs(diffVulnsScript)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name    string
		exc     string
		wantErr bool
	}{
		// The original bug: any exception becomes {vid}, silently.
		{"SSL failure", "URLError", true},
		{"connection reset", "ConnectionResetError", true},
		// 404 is a DEFINITIVE answer -- no record under that id -- and must
		// not be treated as a failure.
		{"404 no record", "HTTPError404", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prog := "import importlib.util, sys, urllib.error, socket" + "\n" +
				"spec = importlib.util.spec_from_file_location('dv', " + shellQuote(full) + ")" + "\n" +
				"m = importlib.util.module_from_spec(spec)" + "\n" +
				"try:" + "\n    spec.loader.exec_module(m)" + "\n" +
				"except SystemExit:" + "\n    pass" + "\n" +
				"def boom(*a, **k):" + "\n" +
				"    mode = sys.argv[1]" + "\n" +
				"    if mode == 'URLError':" + "\n" +
				"        raise urllib.error.URLError('ssl')" + "\n" +
				"    if mode == 'ConnectionResetError':" + "\n" +
				"        raise ConnectionResetError('reset')" + "\n" +
				"    raise urllib.error.HTTPError('u', 404, 'Not Found', {}, None)" + "\n" +
				"m._ssl_context = lambda: None" + "\n" +
				"import urllib.request" + "\n" +
				"urllib.request.urlopen = boom" + "\n" +
				"m.aliases_for.__globals__['_ALIAS_CACHE'].clear()" + "\n" +
				"try:" + "\n" +
				"    g = m.aliases_for('GHSA-test')" + "\n" +
				"    print('NO_RAISE ' + ','.join(sorted(g)))" + "\n" +
				"except Exception as e:" + "\n" +
				"    print('RAISED ' + type(e).__name__)" + "\n"

			cmd := exec.Command(pythonCmd(t), "-c", prog, tc.exc)
			cmd.Dir = repoRoot(t)
			cmd.Env = append(os.Environ(),
				"TMPDIR="+t.TempDir()) // don't touch the real cache
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("harness failed: %v\n%s", err, out)
			}
			got := strings.TrimSpace(string(out))
			if tc.wantErr && !strings.Contains(got, "RAISED") {
				t.Errorf("%s: aliases_for swallowed the failure and returned %q; "+
					"a canonicalizer that cannot fetch must not degrade silently",
					tc.name, got)
			}
			if !tc.wantErr && !strings.Contains(got, "NO_RAISE") {
				t.Errorf("%s: expected a terminal 404 answer, got %q", tc.name, got)
			}
		})
	}
}

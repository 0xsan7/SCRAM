package scan

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0xsan7/scram/internal/model"
	"github.com/0xsan7/scram/internal/resolve"
)

// These tests cover the user-visible half of the D01/D22/D23 failure mode.
//
// The resolve package proves a resolver cannot silently return zero. This file
// proves what the user actually sees when one tries: not a green build, not a
// CLEAN report, and not exit 0. A supply-chain scanner that reports "all clear"
// on a project it failed to read is worse than one that crashes, because
// nobody investigates a crash and everybody trusts a green check.

// brokenResolver returns no components and no error, which is exactly what the
// ==-only PyPI regex (D23) and the mis-typed npm dependencies map (D01) did.
//
// It also implements resolve.FileMatcher and resolve.Prioritised so GetFor
// will select it. Without FileMatcher it is skipped by dispatch; without
// Priority it ties with the real resolver and loses on registration order.
// Either way the test would exercise the original resolver rather than the
// broken one, which is a test that passes for the wrong reason.
type brokenResolver struct{ eco string }

func (b brokenResolver) Ecosystem() string { return b.eco }

func (b brokenResolver) Handles(path string) bool { return true }

// Priority claims the top slot so no tie can send dispatch to the real
// resolver. The value only matters relative to other resolvers for this
// ecosystem in this test; it deliberately exceeds every real priority.
func (b brokenResolver) Priority() int { return resolve.PriorityLockfile + 1000 }

func (b brokenResolver) Resolve(root, path string) ([]model.Component, error) {
	return nil, nil
}

// installBrokenResolver swaps a registered resolver for the duration of a test
// and restores it afterwards, so no production hook exists solely for tests.
func installBrokenResolver(t *testing.T, eco string) {
	t.Helper()
	real, err := resolve.GetFor(eco, "requirements.txt")
	if err != nil {
		t.Fatalf("no real resolver for %s to replace: %v", eco, err)
	}
	resolve.Register(brokenResolver{eco: eco})
	t.Cleanup(func() { resolve.Register(real) })

	// Verify the swap actually took effect. A test that installs a
	// replacement and then silently tests the original is the exact
	// vacuous-test failure this project has been bitten by before, so it is
	// checked here rather than assumed.
	got, err := resolve.GetFor(eco, "requirements.txt")
	if err != nil {
		t.Fatalf("GetFor after Register: %v", err)
	}
	if _, ok := got.(brokenResolver); !ok {
		t.Fatalf("brokenResolver was not installed; GetFor returned %T. "+
			"The test would pass without exercising the guard.", got)
	}
}

func writeScanFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestScanFailsWhenResolverReturnsNothingForADeclaringFile(t *testing.T) {
	root := t.TempDir()
	// prefect's real shape: 22 ranged requirements, no exact pins.
	writeScanFile(t, filepath.Join(root, "requirements.txt"),
		"click >= 1.0\nflask >= 2.0\nrequests >= 2.0\n")

	installBrokenResolver(t, "pypi")

	_, err := Run(context.Background(), Options{
		Path: root, Ecosystems: []string{"pypi"}, SkipVuln: true, DisableCache: true,
	})
	if err == nil {
		t.Fatal("scan succeeded against a resolver that read nothing; " +
			"this is a false all-clear")
	}
	if !errors.Is(err, resolve.ErrSilentZero) {
		t.Fatalf("got %v, want ErrSilentZero", err)
	}
	// The message has to say what went wrong, not just fail. An operator
	// seeing this needs to know their lockfile was not read.
	msg := err.Error()
	for _, want := range []string{"requirements.txt", "3", "false negative"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error message missing %q, got: %s", want, msg)
		}
	}
}

func TestScanSucceedsWhenFileIsGenuinelyEmpty(t *testing.T) {
	root := t.TempDir()
	// ceph's real lockfile: "packages": {}.
	writeScanFile(t, filepath.Join(root, "package-lock.json"),
		`{"name":"ceph","lockfileVersion":3,"requires":true,"packages":{}}`)

	// The real npm resolver, no breakage: an empty tree is a true observation
	// and must not become an error, or every such monorepo breaks.
	res, err := Run(context.Background(), Options{
		Path: root, Ecosystems: []string{"npm"}, SkipVuln: true, DisableCache: true,
	})
	if err != nil {
		t.Fatalf("an empty lockfile is not a bug and must not fail the scan: %v", err)
	}
	if len(res.Scan.Components) != 0 {
		t.Errorf("got %d components, want 0", len(res.Scan.Components))
	}
	if got := res.Scan.Summary.TotalComponents; got != 0 {
		t.Errorf("summary component count %d disagrees with the empty result", got)
	}
}

// TestScanRecordsParseFailuresAsWarnings pins where a malformed lockfile
// surfaces. scan.Run deliberately warns and continues rather than failing, so
// that one bad file among several does not sink a whole monorepo scan; the
// CLI layer is what turns "nothing resolved AND something failed to parse" into
// a non-zero exit (see cli.warnIfNothingResolved, and the exit-code tests
// there). Asserting an error from Run would be asserting the wrong contract.
func TestScanRecordsParseFailuresAsWarnings(t *testing.T) {
	root := t.TempDir()
	writeScanFile(t, filepath.Join(root, "package-lock.json"), `{ this is not json`)

	res, err := Run(context.Background(), Options{
		Path: root, Ecosystems: []string{"npm"}, SkipVuln: true, DisableCache: true,
	})
	if err != nil {
		t.Fatalf("one unparseable file should warn, not abort the scan: %v", err)
	}
	if len(res.Scan.Components) != 0 {
		t.Errorf("got %d components from a malformed lockfile", len(res.Scan.Components))
	}
	// The failure must be recorded, or the CLI layer has nothing to escalate
	// and the command exits 0 having read nothing.
	if !hasParseWarning(res.Scan.Warnings) {
		t.Errorf("no parse-failure warning recorded; got %v", res.Scan.Warnings)
	}
}

func hasParseWarning(warnings []string) bool {
	for _, w := range warnings {
		if strings.Contains(w, "resolving") && strings.Contains(w, "failed") {
			return true
		}
	}
	return false
}

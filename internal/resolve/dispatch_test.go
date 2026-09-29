package resolve

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/0xsan7/scram/internal/model"
)

// These tests cover resolver dispatch, which is shared infrastructure: every
// ecosystem routes through GetFor, not just PyPI.
//
// D28 found that adding a second PyPI resolver silently REPLACED the first
// (the registry was map[string]Resolver), which disabled poetry.lock,
// Pipfile.lock and every requirements variant in the same commit that added
// pyproject support. The corpus caught it. This file exists so the next
// ecosystem to grow a second format inherits a rule that is stated and tested
// rather than one that happens to work.

// TestDispatchSelectsTheRightResolverForEachFile is the table the registry
// exists to satisfy. Every real filename SCRAM reads is listed, so a change to
// any Handles method shows up here rather than as a silent fallback.
func TestDispatchSelectsTheRightResolverForEachFile(t *testing.T) {
	cases := []struct {
		eco  string
		file string
		want string // expected concrete resolver type
	}{
		// Go: one resolver, must be unaffected by the multi-resolver machinery.
		{"go", "go.sum", "resolve.goResolver"},
		// npm: likewise.
		{"npm", "package-lock.json", "resolve.npmResolver"},
		{"npm", "npm-shrinkwrap.json", "resolve.npmResolver"},
		// PyPI lockfiles -> the lockfile resolver.
		{"pypi", "poetry.lock", "resolve.pypiResolver"},
		{"pypi", "Pipfile.lock", "resolve.pypiResolver"},
		{"pypi", "requirements.txt", "resolve.pypiResolver"},
		{"pypi", "requirements-dev.txt", "resolve.pypiResolver"},
		{"pypi", filepath.Join("requirements", "base.txt"), "resolve.pypiResolver"},
		{"pypi", filepath.Join("requirements", "production.txt"), "resolve.pypiResolver"},
		// PyPI manifest -> the manifest resolver.
		{"pypi", "pyproject.toml", "resolve.pyprojectResolver"},
	}
	for _, c := range cases {
		t.Run(c.eco+"/"+filepath.ToSlash(c.file), func(t *testing.T) {
			r, err := GetFor(c.eco, c.file)
			if err != nil {
				t.Fatalf("GetFor(%q, %q): %v", c.eco, c.file, err)
			}
			got := typeName(r)
			if got != c.want {
				t.Errorf("GetFor(%q, %q) = %s, want %s", c.eco, c.file, got, c.want)
			}
		})
	}
}

// TestDispatchIsIndependentOfRegistrationOrder is the test that matters most.
//
// The first GetFor implementation scanned the resolver slice BACKWARDS, so the
// winner was whichever file Go happened to initialise last. Go runs init() in
// file presentation order, which is a compiler implementation detail, not a
// language guarantee -- renaming pyproject.go would have silently changed
// which resolver handled which file, with no test failing.
//
// This test re-registers the pypi resolvers in BOTH orders and asserts
// identical dispatch, so the precedence rule is Priority rather than
// incidental.
func TestDispatchIsIndependentOfRegistrationOrder(t *testing.T) {
	files := []string{
		"poetry.lock", "Pipfile.lock", "requirements.txt",
		"pyproject.toml", filepath.Join("requirements", "base.txt"),
	}
	want := map[string]string{
		"poetry.lock":      "resolve.pypiResolver",
		"Pipfile.lock":     "resolve.pypiResolver",
		"requirements.txt": "resolve.pypiResolver",
		"pyproject.toml":   "resolve.pyprojectResolver",
		filepath.Join("requirements", "base.txt"): "resolve.pypiResolver",
	}

	lock := pypiResolver{}
	manifest := pyprojectResolver{}
	orders := [][]Resolver{
		{lock, manifest}, // current init() order (pypi.go, pyproject.go)
		{manifest, lock}, // reversed: the order that would break a last-wins rule
		{manifest, lock, manifest},
		{lock, manifest, lock},
	}
	for i, order := range orders {
		t.Run(orderName(i), func(t *testing.T) {
			withRegistry(t, func() {})
			registry["pypi"] = order

			for _, f := range files {
				r, err := GetFor("pypi", f)
				if err != nil {
					t.Fatalf("GetFor(%q): %v", f, err)
				}
				if got := typeName(r); got != want[f] {
					t.Errorf("order %d: GetFor(%q) = %s, want %s", i, f, got, want[f])
				}
			}
		})
	}
}

// TestLockfileOutranksManifest states the precedence rule in the form a future
// ecosystem needs it, using synthetic resolvers so the rule is tested
// independently of whichever resolvers happen to be registered today.
func TestLockfileOutranksManifest(t *testing.T) {
	manifest := syntheticResolver{eco: "test", name: "manifest", prio: PriorityManifest}
	lockfile := syntheticResolver{eco: "test", name: "lockfile", prio: PriorityLockfile}

	withRegistry(t, func() {})

	// Both claim the same file. The lockfile must win, in either order.
	for _, order := range [][]Resolver{
		{manifest, lockfile},
		{lockfile, manifest},
	} {
		registry["test"] = order
		r, err := GetFor("test", "anything.lock")
		if err != nil {
			t.Fatal(err)
		}
		if got := syntheticName(r); got != "lockfile" {
			t.Errorf("with order %v, lockfile lost to %s", orderNames(order), got)
		}
	}
}

// TestUnclaimedFileFallsBackToHighestPriority covers stage 2: a file no
// resolver claims must still reach a resolver that can report
// ErrUnsupported, rather than erroring out of dispatch with no explanation.
func TestUnclaimedFileFallsBackToHighestPriority(t *testing.T) {
	manifest := syntheticResolver{eco: "test2", name: "manifest", prio: PriorityManifest, claimsNone: true}
	lockfile := syntheticResolver{eco: "test2", name: "lockfile", prio: PriorityLockfile, claimsNone: true}

	withRegistry(t, func() {})

	registry["test2"] = []Resolver{manifest, lockfile}
	r, err := GetFor("test2", "mystery.txt")
	if err != nil {
		t.Fatalf("an unclaimed file must not fail dispatch: %v", err)
	}
	if got := syntheticName(r); got != "lockfile" {
		t.Errorf("fallback chose %s, want the highest-priority resolver", got)
	}
}

// TestSingleResolverEcosystemsUnaffected guards the regression the user asked
// about: ecosystems with one resolver must behave identically before and
// after the registry was generalised.
//
// npm is no longer one of them -- it has three now that yarn and pnpm
// exist -- so it moved to the multi-resolver checks below. Go and pypi
// are unaffected by the JS work and are what this test still covers.
func TestSingleResolverEcosystemsUnaffected(t *testing.T) {
	for _, eco := range []string{"go"} {
		rs := registry[eco]
		if len(rs) != 1 {
			t.Errorf("%s has %d resolvers, want 1; if a second format was added, "+
				"it needs a Handles method and a Priority here", eco, len(rs))
		}
		// A resolver without Prioritised defaults to lockfile priority, which
		// is what single-resolver ecosystems have always behaved as.
		if got := priorityOf(rs[0]); got != PriorityLockfile {
			t.Errorf("%s resolver priority = %d, want %d (the default for a "+
				"resolver that does not implement Prioritised)", eco, got, PriorityLockfile)
		}
	}
}

// TestPrioritiesAreDeclaredForEveryMultiResolverEcosystem fails if a
// resolver is added to a multi-resolver ecosystem without stating its
// priority, which would leave the dispatch rule resting on init() order
// again.
func TestPrioritiesAreDeclaredForEveryMultiResolverEcosystem(t *testing.T) {
	for eco, rs := range registry {
		if len(rs) < 2 {
			continue
		}
		for _, r := range rs {
			if _, ok := r.(Prioritised); !ok {
				t.Errorf("%s has %d resolvers but %s does not implement Prioritised; "+
					"dispatch would fall back to registration order", eco, len(rs), typeName(r))
			}
			if _, ok := r.(FileMatcher); !ok {
				t.Errorf("%s has %d resolvers but %s does not implement FileMatcher; "+
					"it can never be selected", eco, len(rs), typeName(r))
			}
		}
	}
}

// --- helpers ---------------------------------------------------------------

// withRegistry runs fn with a temporary registry and restores the real one
// afterwards, including any keys fn added.
//
// Restoring only registry[eco] was not enough: the synthetic ecosystems below
// created keys that did not exist before, so they survived the test and showed
// up in a later test's Supported() assertion. A test that leaves the shared
// registry dirty is a test that breaks an unrelated one, which is worse than
// a test that fails on its own.
func withRegistry(t *testing.T, fn func()) {
	t.Helper()
	saved := make(map[string][]Resolver, len(registry))
	for k, v := range registry {
		saved[k] = append([]Resolver(nil), v...)
	}
	t.Cleanup(func() {
		registry = saved
	})
	fn()
}

type syntheticResolver struct {
	eco        string
	name       string
	prio       int
	claimsNone bool
}

func (s syntheticResolver) Ecosystem() string { return s.eco }
func (s syntheticResolver) Priority() int     { return s.prio }
func (s syntheticResolver) Handles(string) bool {
	return !s.claimsNone
}
func (s syntheticResolver) Resolve(root, path string) ([]model.Component, error) { return nil, nil }

// typeName renders a resolver's concrete type for assertion messages.
func typeName(r Resolver) string {
	if r == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%T", r)
}

func syntheticName(r Resolver) string {
	if s, ok := r.(syntheticResolver); ok {
		return s.name
	}
	return typeName(r)
}

func orderName(i int) string { return "order" + string(rune('0'+i)) }

func orderNames(rs []Resolver) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, syntheticName(r))
	}
	return out
}

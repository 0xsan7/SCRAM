package detect

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0xsan7/scram/internal/model"
	"github.com/0xsan7/scram/internal/resolve"
)

func mk(t *testing.T, root string, files ...string) {
	t.Helper()
	for _, f := range files {
		p := filepath.Join(root, f)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDetectAllEcosystems(t *testing.T) {
	root := t.TempDir()
	mk(t, root,
		"package.json", "package-lock.json",
		"requirements.txt",
		"go.mod", "go.sum",
	)

	got, err := Detect(root)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]string{}
	for _, p := range got {
		found[p.Ecosystem] = p.File
	}
	for eco, wantFile := range map[string]string{
		"npm":  "package-lock.json",
		"pypi": "requirements.txt",
		"go":   "go.sum",
	} {
		if found[eco] != wantFile {
			t.Errorf("%s: got file %q, want %q (all: %+v)", eco, found[eco], wantFile, got)
		}
	}
}

func TestDetectPrefersLockfileOverManifest(t *testing.T) {
	// requirements.txt and poetry.lock are both PyPI; the lockfile pins
	// exact versions, so it must win.
	root := t.TempDir()
	mk(t, root, "requirements.txt", "poetry.lock")
	got, err := Detect(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range got {
		if p.Ecosystem == "pypi" && p.File != "poetry.lock" {
			t.Errorf("got %q, want poetry.lock (the lockfile pins versions)", p.File)
		}
	}
}

func TestDetectSkipsVendoredDirectories(t *testing.T) {
	// A vendored project's lockfiles must not be scanned as if they were the
	// host repo's own dependencies; that double-counts everything.
	root := t.TempDir()
	mk(t, root,
		"package-lock.json",
		"node_modules/some-dep/package.json",
		"node_modules/some-dep/package-lock.json",
		"vendor/thing/go.mod",
		"vendor/thing/go.sum",
	)

	got, err := Detect(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range got {
		if filepath.Dir(p.File) != "." {
			t.Errorf("found a project inside %q, which should have been skipped: %+v", filepath.Dir(p.File), got)
		}
	}
	if len(got) != 1 {
		t.Errorf("got %d projects, want 1 (only the root): %+v", len(got), got)
	}
}

func TestDetectMonorepoSubdirectory(t *testing.T) {
	// A subdirectory that is not a vendored path IS part of the repo.
	root := t.TempDir()
	mk(t, root,
		"package-lock.json",
		"apps/web/package.json",
		"apps/web/package-lock.json",
	)
	got, err := Detect(root)
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, p := range got {
		paths = append(paths, p.File)
	}
	if len(got) != 2 {
		t.Errorf("got %d projects %v, want 2 (root and apps/web)", len(got), paths)
	}
}

func TestDetectEmptyRepo(t *testing.T) {
	got, err := Detect(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("got %+v, want no projects", got)
	}
}

func TestDetectMissingRoot(t *testing.T) {
	if _, err := Detect(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Error("expected an error for a nonexistent path")
	}
}

// TestDetectResultsAreStable matters because the scan output must be
// reproducible run to run; map iteration order would otherwise leak into the
// component ordering.
func TestDetectResultsAreStable(t *testing.T) {
	root := t.TempDir()
	mk(t, root,
		"package-lock.json", "requirements.txt", "go.sum",
		"apps/web/package-lock.json",
	)
	first, err := Detect(root)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		again, err := Detect(root)
		if err != nil {
			t.Fatal(err)
		}
		if len(again) != len(first) {
			t.Fatalf("run %d returned %d projects, first run returned %d", i, len(again), len(first))
		}
		for j := range first {
			if again[j] != first[j] {
				t.Errorf("run %d position %d: got %+v, want %+v", i, j, again[j], first[j])
			}
		}
	}
}

// mustWrite is a small helper so the tests below read as setup rather than
// error handling.
func mustWrite(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestDetectorAndResolverAgreeOnFilenames is the guard for D37.
//
// The resolver has handled requirements-dev.txt, dev.txt, test.txt and eight
// other requirements filenames since D23, while the detector only ever looked
// for requirements.txt. A resolver that can read a file the detector will not
// look for is a capability nobody has -- and because the file was never
// detected, the silent-zero invariant (D26) had nothing to fire on: there was
// no resolver call that could return zero. psf/requests, a real corpus
// fixture, scanned as zero components and exited 0.
//
// This asserts the two lists agree in the direction that matters: every
// filename a resolver claims must be detectable.
func TestDetectorAndResolverAgreeOnFilenames(t *testing.T) {
	detected := map[string]bool{}
	for _, c := range candidates {
		detected[strings.ToLower(c.File)] = true
	}
	// Every filename the pypi resolver claims, taken from the resolver
	// itself rather than copied, so the two cannot drift.
	probe, err := resolve.GetFor(model.EcoPyPI, "requirements.txt")
	if err != nil {
		t.Fatalf("no pypi resolver: %v", err)
	}
	pm, ok := probe.(resolve.FileMatcher)
	if !ok {
		t.Fatalf("the pypi resolver does not implement FileMatcher, so the "+
			"two lists cannot be compared: %T", probe)
	}
	for _, name := range []string{
		"poetry.lock", "pipfile.lock", "requirements.txt", "requirements-dev.txt",
		"requirements-prod.txt", "requirements-prod.dev.txt", "base.txt",
		"main.txt", "production.txt", "test.txt", "common.txt",
		"constraints.txt", "dev.txt", "lint.txt", "types.txt",
		"pyproject.toml",
	} {
		if !pm.Handles(name) {
			continue // the resolver does not claim it, so it need not be detected
		}
		if !detected[name] {
			t.Errorf("the resolver handles %q but the detector never looks "+
				"for it: the file is invisible end to end, and the "+
				"silent-zero invariant cannot catch a file that is never "+
				"detected", name)
		}
	}
	for _, eco := range []string{model.EcoNPM, model.EcoGo} {
		for _, c := range candidates {
			if c.Ecosystem != eco {
				continue
			}
			r, err := resolve.GetFor(eco, c.File)
			if err != nil {
				t.Errorf("%s: detector lists %q but no resolver claims it: %v",
					eco, c.File, err)
				continue
			}
			// A resolver need not implement FileMatcher when it is the only
			// one for its ecosystem: GetFor falls back to it, so it is
			// reachable and there is nothing to compare.
			if fm, ok := r.(resolve.FileMatcher); ok && !fm.Handles(c.File) {
				t.Errorf("%s: detector lists %q but the resolver does not "+
					"claim it; the file would be detected and then fail to "+
					"resolve", eco, c.File)
			}
		}
	}
}

// TestRequirementsVariantsAreDetected is the end-to-end version: a real
// requirements-dev.txt must produce components, not a clean scan.
func TestRequirementsVariantsAreDetected(t *testing.T) {
	for _, name := range []string{"requirements-dev.txt", "dev.txt", "test.txt"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			body := "pytest>=2.8.0,<10\npytest-cov\nhttpbin~=0.10.0\n"
			if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
			projs, err := Detect(dir)
			if err != nil {
				t.Fatalf("Detect: %v", err)
			}
			if len(projs) == 0 {
				t.Fatalf("%s was not detected at all", name)
			}
			if projs[0].Ecosystem != model.EcoPyPI {
				t.Fatalf("detected as %q, want pypi", projs[0].Ecosystem)
			}
			// Resolve through the same path the scan uses, so this test
			// covers detection AND resolution together.
			r, err := resolve.GetFor(projs[0].Ecosystem, projs[0].File)
			if err != nil {
				t.Fatalf("no resolver for %q: %v", projs[0].File, err)
			}
			comps, err := resolve.ResolveFile(r, dir, projs[0].File)
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			if len(comps) != 3 {
				t.Errorf("got %d components, want 3: %+v", len(comps), comps)
			}
		})
	}
}

// TestLockfileStillWinsOverRequirementsVariants pins the precedence: adding
// the requirements fallbacks must not change which file a project with both a
// lockfile and a requirements variant is read through.
func TestLockfileStillWinsOverRequirementsVariants(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "poetry.lock"),
		"[[package]]\nname = \"requests\"\nversion = \"2.19.1\"\n")
	mustWrite(t, filepath.Join(dir, "requirements.txt"), "flask\nwerkzeug\n")
	mustWrite(t, filepath.Join(dir, "requirements-dev.txt"), "pytest\n")

	projs, err := Detect(dir)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(projs) != 1 {
		t.Fatalf("want 1 project, got %d: %+v", len(projs), projs)
	}
	if !strings.EqualFold(projs[0].File, "poetry.lock") {
		t.Errorf("got %q, want poetry.lock: a lockfile outranks every "+
			"requirements variant", projs[0].File)
	}
}

package detect

import (
	"os"
	"path/filepath"
	"testing"
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

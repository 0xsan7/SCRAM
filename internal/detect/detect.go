// Package detect identifies which ecosystems a repo uses, based on the
// manifest/lockfiles present. No build step is run — SCRAM parses lockfiles
// directly (FR-101).
package detect

import (
	"os"
	"path/filepath"
	"sort"
)

// Project pairs an ecosystem with the specific file that pins its versions.
// Lockfiles are preferred over manifests because a manifest lists ranges
// ("^4.17.0") rather than the exact version actually shipped.
type Project struct {
	Ecosystem string
	// File is the lockfile path, relative to the repo root when possible.
	File string
	// RelPath is the manifest path that declared the dependency, if any.
	RelPath string
	// Direct is true for the root project's own manifest.
	Direct bool
}

// candidates are checked in order; the first hit per ecosystem per directory
// wins.
//
// Order matters within an ecosystem: lockfiles come before bare manifests,
// because a lockfile pins exact resolved versions while a manifest lists
// ranges. Scanning the manifest when a lockfile is present would understate
// or misreport the dependency set.
//
// pyproject.toml sits after poetry.lock deliberately. A pyproject.toml
// declares ranges ("starlette>=0.46.0"), not the versions actually installed,
// so a project with both must be read through the lock. pyproject.toml is the
// last resort and covers the large population of modern Python projects that
// ship no lockfile at all -- see D27.
var candidates = []Project{
	{Ecosystem: "npm", File: "package-lock.json", RelPath: "package.json"},
	{Ecosystem: "npm", File: "npm-shrinkwrap.json", RelPath: "package.json"},
	{Ecosystem: "pypi", File: "poetry.lock", RelPath: "pyproject.toml"},
	{Ecosystem: "pypi", File: "Pipfile.lock", RelPath: "Pipfile"},
	// The requirements variants, most-specific first. Only the FIRST hit per
	// ecosystem per directory is used, so listing them is a fallback chain:
	// a project with both requirements.txt and requirements-dev.txt is
	// scanned through the former.
	//
	// These were missing until the differential test against syft (D37).
	// The resolver had handled all of them since D23, but the DETECTOR never
	// looked for them, so `requirements-dev.txt` was invisible end to end:
	// psf/requests, which is in the real corpus, reported zero components
	// and exited 0. The silent-zero invariant could not catch it, because
	// the file was never detected in the first place -- there was no
	// resolver call to return zero from.
	//
	// A resolver that can read a file the detector will not look for is a
	// capability nobody has, and nothing in the type said so. The
	// TestDetectorAndResolverAgreeOnFilenames test now fails if the two
	// lists drift apart again.
	{Ecosystem: "pypi", File: "requirements.txt", RelPath: "requirements.txt"},
	{Ecosystem: "pypi", File: "requirements-dev.txt", RelPath: "requirements-dev.txt"},
	{Ecosystem: "pypi", File: "requirements-prod.txt", RelPath: "requirements-prod.txt"},
	{Ecosystem: "pypi", File: "requirements-prod.dev.txt", RelPath: "requirements-prod.dev.txt"},
	{Ecosystem: "pypi", File: "dev.txt", RelPath: "dev.txt"},
	{Ecosystem: "pypi", File: "test.txt", RelPath: "test.txt"},
	{Ecosystem: "pypi", File: "lint.txt", RelPath: "lint.txt"},
	{Ecosystem: "pypi", File: "types.txt", RelPath: "types.txt"},
	{Ecosystem: "pypi", File: "production.txt", RelPath: "production.txt"},
	{Ecosystem: "pypi", File: "main.txt", RelPath: "main.txt"},
	{Ecosystem: "pypi", File: "base.txt", RelPath: "base.txt"},
	{Ecosystem: "pypi", File: "common.txt", RelPath: "common.txt"},
	{Ecosystem: "pypi", File: "constraints.txt", RelPath: "constraints.txt"},
	{Ecosystem: "pypi", File: "pyproject.toml", RelPath: "pyproject.toml"},
	{Ecosystem: "go", File: "go.sum", RelPath: "go.mod"},
}

// CandidateFilenames returns every filename the detector looks for, so user-
// facing messages can name the real list instead of a hand-kept copy of it.
func CandidateFilenames() []string {
	seen := map[string]bool{}
	var out []string
	for _, c := range candidates {
		f := c.File
		if seen[f] {
			continue
		}
		seen[f] = true
		out = append(out, f)
	}
	return out
}

// maxDepth bounds how deep the subdirectory walk goes. Three levels covers
// the common monorepo layouts (apps/web, services/api, packages/ui) without
// walking an arbitrarily large tree, and without descending into vendored or
// build directories, which skipDir already excludes.
const maxDepth = 3

// Detect returns every supported project found under root. Manifests and
// lockfiles inside vendored/build directories are ignored so that a repo
// doesn't get scanned twice because it vendors another project.
func Detect(root string) ([]Project, error) {
	if _, err := os.Stat(root); err != nil {
		return nil, err
	}
	var found []Project

	var walk func(dir, rel string, depth int)
	walk = func(dir, rel string, depth int) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}

		// taken guards against picking two files for the same ecosystem in
		// one directory. It is per-directory, so a monorepo's apps/web can
		// use a different lockfile format than its root.
		taken := map[string]bool{}

		for _, c := range candidates {
			if _, err := os.Stat(filepath.Join(dir, c.File)); err != nil {
				continue
			}
			// One project per ecosystem per directory. candidates is ordered
			// lockfile-first, so the first match is the most precise source
			// available. Scanning a coarser manifest alongside it would merge
			// two different views of the same dependency set.
			if taken[c.Ecosystem] {
				continue
			}
			taken[c.Ecosystem] = true
			found = append(found, Project{
				Ecosystem: c.Ecosystem,
				File:      joinRel(rel, c.File),
				RelPath:   joinRel(rel, c.RelPath),
				Direct:    true,
			})
		}

		if depth >= maxDepth {
			return
		}
		for _, e := range entries {
			if !e.IsDir() || skipDir(e.Name()) {
				continue
			}
			walk(filepath.Join(dir, e.Name()), e.Name(), depth+1)
		}
	}

	walk(root, ".", 0)

	sort.Slice(found, func(i, j int) bool {
		if found[i].Ecosystem != found[j].Ecosystem {
			return found[i].Ecosystem < found[j].Ecosystem
		}
		return found[i].File < found[j].File
	})
	return found, nil
}

func skipDir(name string) bool {
	switch name {
	case "node_modules", "vendor", ".git", "testdata", "dist", "build",
		".venv", "venv", "site-packages", "third_party", "examples":
		return true
	}
	return false
}

func joinRel(dir, file string) string {
	if dir == "." {
		return file
	}
	return filepath.Join(dir, file)
}

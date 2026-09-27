// Command corpus-check runs every resolver against the real-world lockfile
// corpus and reports what resolved, what didn't, and what looks wrong.
//
// This is a diagnostic, not a pass/fail test: a "0 components" result is
// reported loudly rather than skipped, because a scanner that silently reads
// nothing is the exact failure mode D01 documented.
//
//	go run ./cmd/corpus-check
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/0xsan7/scram/internal/detect"
	"github.com/0xsan7/scram/internal/resolve"
)

type result struct {
	Path      string
	Ecosystem string
	Count     int
	Err       error
	Version   int
	Keys      []string
	Suspect   string
	// Empty marks a lockfile that genuinely declares no dependencies, which
	// is a different fact from "the resolver found nothing".
	Empty bool
}

// lockfileDeclaresNothing reports whether a lockfile file itself contains no
// dependency declarations, independently of any resolver. Used to tell a real
// empty lockfile apart from a silent parse failure, which is the D01/D22/D25
// failure class: a document the resolver could not read looks exactly like a
// clean repo from the outside.
func lockfileDeclaresNothing(path string) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false // unreadable is not "empty"; let the caller report it
	}
	base := filepath.Base(path)
	if base == "package-lock.json" {
		var doc struct {
			Packages     map[string]json.RawMessage `json:"packages"`
			Dependencies map[string]json.RawMessage `json:"dependencies"`
		}
		if json.Unmarshal(b, &doc) != nil {
			return false // not JSON: a parse failure, not an empty tree
		}
		return len(doc.Packages) == 0 && len(doc.Dependencies) == 0
	}
	// Text formats: any non-comment, non-option, non-VCS line is a dependency.
	for _, raw := range strings.Split(string(b), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		if strings.Contains(line, "://") {
			continue
		}
		return false
	}
	return true
}

func main() {
	root := "testdata/fixtures"
	var results []result

	// Walk every corpus file.
	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		base := filepath.Base(p)
		var eco string
		switch base {
		case "package-lock.json":
			eco = "npm"
		case "poetry.lock", "requirements.txt", "requirements-dev.txt", "Pipfile.lock":
			eco = "pypi"
		case "go.sum":
			eco = "go"
		default:
			return nil
		}
		// Only the corpus, not the curated fixtures.
		if !strings.Contains(p, string(os.PathSeparator)+"real"+string(os.PathSeparator)) &&
			!strings.Contains(p, "/real/") {
			return nil
		}

		dir := filepath.Dir(p)
		rel, _ := filepath.Rel(root, p)
		r := result{Path: rel, Ecosystem: eco}

		res, rerr := resolve.GetFor(eco, base)
		if rerr != nil {
			r.Err = fmt.Errorf("no resolver: %w", rerr)
			results = append(results, r)
			return nil
		}
		// Go through ResolveFile so the silent-zero invariant applies here
		// too. A diagnostic that reports "0 components" without knowing
		// whether the file declared any is exactly the false-negative shape
		// this whole check exists to catch, so the diagnostic must not
		// commit it either.
		comps, cerr := resolve.ResolveFile(res, dir, base)
		r.Err = cerr
		r.Count = len(comps)

		// A real project should never resolve to nothing, but "nothing" has two
		// very different causes: a lockfile that genuinely declares no
		// packages (ceph commits an 83-byte one, "packages": {}), and a
		// lockfile the resolver silently failed to read. Only the second is a
		// bug, so they are reported separately rather than merged into one
		// alarming "0 components" line.
		if cerr == nil && len(comps) == 0 && !lockfileDeclaresNothing(p) {
			r.Suspect = "resolved to ZERO components from a lockfile that declares dependencies"
		}
		if cerr == nil && len(comps) == 0 && lockfileDeclaresNothing(p) {
			r.Empty = true
		}
		if cerr != nil {
			r.Suspect = "parse error"
		}
		// npm: record the lockfile shape so coverage gaps are visible.
		if eco == "npm" {
			if b, err := os.ReadFile(p); err == nil {
				var doc struct {
					LockfileVersion int             `json:"lockfileVersion"`
					Packages        json.RawMessage `json:"packages"`
					Dependencies    json.RawMessage `json:"dependencies"`
				}
				if json.Unmarshal(b, &doc) == nil {
					r.Version = doc.LockfileVersion
					if len(doc.Packages) > 0 {
						r.Keys = append(r.Keys, "packages")
					}
					if len(doc.Dependencies) > 0 {
						r.Keys = append(r.Keys, "dependencies")
					}
				}
			}
		}
		results = append(results, r)
		return nil
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "walk: %v\n", err)
		os.Exit(1)
	}

	sort.Slice(results, func(i, j int) bool {
		if results[i].Ecosystem != results[j].Ecosystem {
			return results[i].Ecosystem < results[j].Ecosystem
		}
		return results[i].Path < results[j].Path
	})

	byEco := map[string]int{}
	byVersion := map[int]int{}
	var suspects []result
	total := 0

	fmt.Printf("%-6s %-5s %-7s %-9s %s\n", "ECO", "VER", "COMPS", "KEYS", "PATH")
	fmt.Println(strings.Repeat("-", 100))
	for _, r := range results {
		byEco[r.Ecosystem]++
		total += r.Count
		ver := "-"
		if r.Version > 0 {
			ver = fmt.Sprintf("v%d", r.Version)
			byVersion[r.Version]++
		}
		keys := strings.Join(r.Keys, "+")
		if keys == "" {
			keys = "-"
		}
		status := ""
		if r.Err != nil {
			status = "  ERR: " + r.Err.Error()
		} else if r.Suspect != "" {
			status = "  <-- " + r.Suspect
			suspects = append(suspects, r)
		}
		fmt.Printf("%-6s %-5s %-7d %-9s %s%s\n", r.Ecosystem, ver, r.Count, keys, r.Path, status)
	}

	fmt.Println()
	empties := 0
	for _, r := range results {
		if r.Empty {
			empties++
		}
	}
	if empties > 0 {
		fmt.Printf("  %d lockfile(s) genuinely declare no dependencies (not a bug)\n", empties)
	}
	fmt.Println("=== summary ===")
	for _, e := range []string{"go", "npm", "pypi"} {
		fmt.Printf("  %-5s %d files\n", e, byEco[e])
	}
	fmt.Println("  lockfileVersion coverage:", versionKeys(byVersion))
	fmt.Printf("  total components resolved: %d\n", total)

	if len(suspects) > 0 {
		fmt.Println()
		fmt.Printf("=== %d SUSPECT(S) — real bug candidates ===\n", len(suspects))
		for _, s := range suspects {
			fmt.Printf("  %s: %s\n", s.Path, s.Suspect)
		}
		os.Exit(1)
	}
	fmt.Println("\nall corpus lockfiles resolved non-empty")
}

func versionKeys(m map[int]int) string {
	if len(m) == 0 {
		return "none"
	}
	ks := make([]int, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Ints(ks)
	var b strings.Builder
	for _, k := range ks {
		fmt.Fprintf(&b, "v%d=%d ", k, m[k])
	}
	return strings.TrimSpace(b.String())
}

var _ = detect.Detect

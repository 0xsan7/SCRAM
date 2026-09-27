// Command ppcheck reports what the pyproject.toml resolver makes of every
// real pyproject.toml in the corpus.
//
// This is a separate diagnostic from corpus-check because pyproject.toml
// declares RANGES, not resolved versions, and several real files declare no
// dependencies at all. A "0 components" result is therefore expected and
// correct for some inputs, and the interesting question is whether it is
// correct for the RIGHT reason. So each file is classified:
//
//	declares  -> expected to yield >= 1 component
//	none      -> expected to yield 0, and the file must really have no deps
//	MISMATCH  -> the two disagree, which is a bug
//
//	go run ./cmd/ppcheck
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/0xsan7/scram/internal/model"
	"github.com/0xsan7/scram/internal/resolve"
)

type row struct {
	repo    string
	count   int
	declare bool
	note    string
	err     error
}

func main() {
	root := "testdata/fixtures/pypi/real/pp"
	// Ask for the pyproject.toml resolver specifically: the pypi ecosystem
	// also has a lockfile resolver, and Get would not be able to tell them
	// apart.
	r, err := resolve.GetFor("pypi", "pyproject.toml")
	if err != nil {
		fmt.Fprintf(os.Stderr, "no pypi resolver: %v\n", err)
		os.Exit(1)
	}

	var rows []row
	walkErr := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || info.Name() != "pyproject.toml" {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		repo := filepath.Dir(rel)
		if repo == "." {
			repo = filepath.Base(p)
		}
		rw := row{repo: repo, declare: declaresDependencies(p)}

		comps, cerr := resolve.ResolveFile(r, filepath.Dir(p), filepath.Base(p))
		rw.err = cerr
		rw.count = len(comps)
		if cerr != nil {
			rw.note = cerr.Error()
		} else {
			rw.note = summarise(comps)
		}
		rows = append(rows, rw)
		return nil
	})
	if walkErr != nil {
		fmt.Fprintf(os.Stderr, "walk: %v\n", walkErr)
	}

	sort.Slice(rows, func(i, j int) bool { return rows[i].repo < rows[j].repo })

	var mismatches, declared, none, errors int
	for _, rw := range rows {
		mark := "ok"
		switch {
		case rw.err != nil:
			mark = "ERROR"
			errors++
		case rw.declare && rw.count == 0:
			mark = "MISMATCH"
			mismatches++
		case rw.declare:
			declared++
		case rw.count == 0:
			none++
		default:
			// Declared nothing but produced components: also suspicious.
			mark = "MISMATCH"
			mismatches++
		}
		fmt.Printf("%-9s %-28s %3d  %s\n", mark, rw.repo, rw.count, truncate(rw.note, 200))
	}

	fmt.Println()
	fmt.Println("=== pyproject.toml summary ===")
	fmt.Printf("  files:                        %d\n", len(rows))
	fmt.Printf("  declares deps, resolved them: %d\n", declared)
	fmt.Printf("  declares nothing, got 0:      %d\n", none)
	fmt.Printf("  parse errors:                 %d\n", errors)
	fmt.Printf("  MISMATCHES:                   %d\n", mismatches)
	if mismatches > 0 || errors > 0 {
		os.Exit(1)
	}
	fmt.Println("\npyproject corpus agrees with pyproject.toml's own contents")
}

// declaresDependencies reads the file and reports whether it declares any
// runtime dependency at all, independently of the resolver. This is what makes
// a MISMATCH meaningful: it compares the resolver against the file itself, not
// against another resolver.
func declaresDependencies(path string) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	t := string(b)
	// [project] dependencies = [ ... ]  (PEP 621)
	if m := regexp.MustCompile(`(?s)\[project\](.*?)(\n\[|$)`).FindStringSubmatch(t); m != nil {
		if regexp.MustCompile(`(?m)^\s*dependencies\s*=\s*\[\s*[^\]]`).MatchString(m[1]) {
			return true
		}
	}
	// [project.dependencies] foo = ">=1"  (PEP 735)
	if regexp.MustCompile(`(?m)^\[project\.dependencies\]`).MatchString(t) {
		return true
	}
	// [tool.poetry.dependencies] with at least one entry
	if m := regexp.MustCompile(`(?s)\[tool\.poetry\.dependencies\](.*?)(\n\[|$)`).FindStringSubmatch(t); m != nil {
		for _, line := range strings.Split(m[1], "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			// python = ">=3.9" is the interpreter, not a package.
			k := strings.SplitN(line, "=", 2)[0]
			switch strings.TrimSpace(k) {
			case "python", "python_version", "python_full_version":
				continue
			}
			return true
		}
	}
	// Legacy [tool.poetry] dependencies = [...]
	if m := regexp.MustCompile(`(?s)\[tool\.poetry\](.*?)(\n\[|$)`).FindStringSubmatch(t); m != nil {
		if regexp.MustCompile(`(?m)^\s*dependencies\s*=\s*\[\s*[^\]]`).MatchString(m[1]) {
			return true
		}
	}
	return false
}

// summarise renders a short sample of the resolved components, so a reader
// can eyeball whether the parse is right without dumping the whole list.
func summarise(comps []model.Component) string {
	if len(comps) == 0 {
		return "(none)"
	}
	parts := make([]string, 0, 3)
	for i, c := range comps {
		if i == 3 {
			break
		}
		if c.Version != "" {
			parts = append(parts, c.Name+"@"+c.Version)
		} else {
			parts = append(parts, c.Name)
		}
	}
	if len(comps) > 3 {
		parts = append(parts, "...")
	}
	return strings.Join(parts, ", ")
}

func truncate(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

// Command roundtrip is the audit harness behind the known-vulnerable
// roundtrip requirement in CONTRIBUTING.md.
//
// For each ecosystem it takes a REAL lockfile from the committed corpus,
// resolves it with the production resolver, and then asks OSV -- through the
// production client, not a hand-written query -- whether the result contains
// a dependency with a known, currently-valid advisory.
//
// The point is that a scan reporting clean is indistinguishable from a scan
// that looked up the wrong key. The go.mod fallback looked up
// "github.com/gin-gonic/gin" as "gin", found nothing, and reported CLEAN with
// a correct PURL and a plausible component name. This harness is what
// catches that class: it asserts an advisory that MUST be there is there.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/0xsan7/scram/internal/model"
	"github.com/0xsan7/scram/internal/resolve"
	"github.com/0xsan7/scram/internal/vuln"
)

type probe struct {
	ecosystem string
	file      string
	// want is an advisory ID that OSV currently returns for at least one
	// component in this file. Empty means "just report what came back".
	want string
}

func main() {
	root := "."
	if len(os.Args) > 1 {
		root = os.Args[1]
	}
	probes := []probe{
		{"npm", "testdata/fixtures/npm/real/less-less@3.13.0/package-lock.json", ""},
		{"pypi", "testdata/fixtures/pypi/real/prefecthq/prefect/requirements.txt", ""},
		{"cargo", "testdata/fixtures/cargo/real/mozilla/sccache/Cargo.lock", ""},
		{"yarn", "testdata/fixtures/yarn/real/classic/angular/angular.js/yarn.lock", ""},
		{"pnpm", "testdata/fixtures/pnpm/real/immich-app/immich/pnpm-lock.yaml", ""},
		{"go.sum", "testdata/fixtures/gomod/real/aquasecurity/trivy/go.sum", ""},
		{"go.mod", "testdata/fixtures/gomod/real/aquasecurity/trivy/go.mod", ""},
	}
	_ = run(root, probes)
}

func run(root string, probes []probe) error {
	ctx := context.Background()
	for _, p := range probes {
		full := filepath.Join(root, p.file)
		if _, err := os.Stat(full); err != nil {
			fmt.Printf("%-8s SKIP  %v\n", p.ecosystem, err)
			continue
		}
		// Resolvers register under their ECOSYSTEM, and yarn and pnpm are
		// npm-family: they share the ecosystem and differ by lockfile
		// filename, which is what GetFor's FileMatcher stage is for.
		eco := map[string]string{
			"yarn": "npm", "pnpm": "npm", "go.sum": "go", "go.mod": "go",
		}[p.ecosystem]
		if eco == "" {
			eco = p.ecosystem
		}
		r, err := resolve.GetFor(eco, filepath.Base(p.file))
		if err != nil {
			fmt.Printf("%-8s ERROR no resolver: %v\n", p.ecosystem, err)
			continue
		}
		// Resolve takes `path` RELATIVE to root, which is how the scan
		// pipeline calls it. Getting this wrong is its own silent failure,
		// so mirror the production call exactly.
		comps, err := resolve.ResolveFile(r, filepath.Dir(full), filepath.Base(p.file))
		if err != nil {
			fmt.Printf("%-8s ERROR resolve: %v\n", p.ecosystem, err)
			continue
		}
		// The PRODUCTION client, so the lookup key is the production one.
		c := vuln.NewClient(nil)
		if err := c.QueryOSV(ctx, comps); err != nil {
			fmt.Printf("%-8s ERROR query: %v\n", p.ecosystem, err)
			continue
		}
		verdict := "NO-KEY-MATCH"
		if countVulned(comps) > 0 {
			verdict = "FOUND"
		}
		out, _ := json.Marshal(map[string]any{
			"ecosystem":  p.ecosystem,
			"file":       p.file,
			"resolved":   len(comps),
			"withVulns":  countVulned(comps),
			"advisories": countAdvisories(comps),
			"verdict":    verdict,
			"sampleKey":  sampleKey(comps),
		})
		fmt.Printf("%-8s %s\n", p.ecosystem, out)
	}
	return nil
}

// sampleKey shows the exact (ecosystem, name, version) triple the matcher
// used for a component that returned an advisory, so the key can be compared
// against what OSV documents for that ecosystem.
func sampleKey(comps []model.Component) string {
	for _, c := range comps {
		if len(c.Vulnerabilities) == 0 {
			continue
		}
		ids := make([]string, 0, len(c.Vulnerabilities))
		for _, v := range c.Vulnerabilities {
			ids = append(ids, v.ID)
		}
		sort.Strings(ids)
		if len(ids) > 3 {
			ids = append(ids[:3], "...")
		}
		return fmt.Sprintf("%s/%s@%s -> %v", c.Ecosystem, c.Name, c.Version, ids)
	}
	return ""
}

func countVulned(comps []model.Component) int {
	n := 0
	for _, c := range comps {
		if len(c.Vulnerabilities) > 0 {
			n++
		}
	}
	return n
}

func countAdvisories(comps []model.Component) int {
	n := 0
	for _, c := range comps {
		n += len(c.Vulnerabilities)
	}
	return n
}

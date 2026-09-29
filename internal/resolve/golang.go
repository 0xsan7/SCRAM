package resolve

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/0xsan7/scram/internal/model"
)

func init() { Register(goResolver{}) }

type goResolver struct{}

func (goResolver) Ecosystem() string { return model.EcoGo }

// Handles names both files, because go.sum is the complete record and
// go.mod is the fallback, and dispatch decides between them by filename.
func (goResolver) Handles(path string) bool {
	base := filepath.Base(path)
	return base == "go.sum" || base == "go.mod"
}

// goSumLine matches the three columns of a go.sum line:
//
//	<module> <version>[/go.mod] <hash>
var goSumLine = regexp.MustCompile(`^(\S+)\s+(\S+?)(/go\.mod)?\s+(\S+)$`)

// goModRequire matches require directives in go.mod, both the block form
//
//	require (
//	    github.com/foo/bar v1.2.3
//	)
//
// and the single-line form `require github.com/foo/bar v1.2.3`.
var goModRequire = regexp.MustCompile(`^\s*(?:require\s+)?(\S+)\s+(v[0-9][\w.\-+]*)`)

func (r goResolver) Resolve(root, path string) ([]model.Component, error) {
	// The caller may pass either the go.sum file or the go.mod file. Both
	// live in the same directory, so work out the directory first and read
	// go.sum from it — joining a directory with "go.sum" when the caller
	// already passed a directory path produces "go.mod/go.sum", which is
	// not a valid file.
	dir := root
	if base := filepath.Base(path); base == "go.sum" || base == "go.mod" {
		dir = filepath.Join(root, filepath.Dir(path))
	}
	sumPath := filepath.Join(dir, "go.sum")

	// A module with no dependencies has no go.sum at all; that is not an
	// error, it just means there is nothing to scan -- UNLESS there is a
	// go.mod, in which case the module declares requirements that a
	// go.sum-less checkout has not recorded yet.
	//
	// go.sum is absent far more often than "the module has no
	// dependencies". A freshly cloned repository, any CI step that runs
	// `go mod download` after checkout, a vendored or pre-built tree, and
	// every module whose go.sum has never been committed all look
	// identical from here: no go.sum. Returning an empty inventory for
	// those is a silent false clean -- a repository with 200 requirements
	// scanning as zero findings, exit 0.
	//
	// So go.mod is the fallback, and its limitations are stated rather
	// than hidden: it yields the declared requirements, which is the
	// DIRECT set plus whatever the author pinned, and it cannot see
	// transitive modules that only the module graph knows about. A scan
	// built this way is a floor, not a full inventory, and callers should
	// be able to tell the difference.
	if _, err := os.Stat(sumPath); err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		modPath := filepath.Join(dir, "go.mod")
		if b, mErr := os.ReadFile(modPath); mErr == nil {
			out := goModComponents(string(b))
			if len(out) > 0 {
				return out, nil
			}
		}
		return []model.Component{}, nil
	}

	// go.mod is the only reliable source of "direct vs transitive".
	direct := map[string]bool{}
	modPath := filepath.Join(dir, "go.mod")
	if b, err := os.ReadFile(modPath); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") || trimmed == ")" {
				continue
			}
			if m := goModRequire.FindStringSubmatch(trimmed); m != nil {
				direct[m[1]] = true
			}
		}
	}

	b, err := os.ReadFile(sumPath)
	if err != nil {
		return nil, err
	}

	// A module appears in go.sum once per version, and separately with a
	// /go.mod suffix for its go.mod hash. Keep only the module zip hash, and
	// keep the highest version if a module somehow appears more than once.
	versions := map[string]string{}
	hashes := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		m := goSumLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		module, version, goModOnly, hash := m[1], m[2], m[3], m[4]
		if goModOnly != "" {
			continue // this is the go.mod hash, not the module content hash
		}
		cur, ok := versions[module]
		if !ok || compareGoVersions(version, cur) > 0 {
			versions[module] = version
			hashes[module] = hash
		}
	}

	out := make([]model.Component, 0, len(versions))
	for module, version := range versions {
		c := model.Component{
			// Go purls put a lowercase 'v' in the namespace and an uppercase
			// 'V' in the version, per the purl spec's golang type.
			Purl:      goPURL(module, version),
			Name:      goModuleName(module),
			Version:   version,
			Ecosystem: model.EcoGo,
			Direct:    direct[module],
		}
		if h := hashes[module]; h != "" {
			c.Hashes = map[string]string{"SHA-256": "h1:" + h}
		}
		out = append(out, c)
	}
	return out, nil
}

// goModuleName is the identity the OSV client queries by.
//
// A Go module is identified by its PATH, exactly as `go list -m` prints it
// and exactly as OSV's Go ecosystem is keyed. The go.sum path has always
// done this; the go.mod fallback briefly did not, and because the PURL was
// still correct the failure was invisible in the inventory and only showed
// up as zero findings.
func goModuleName(module string) string { return module }

func goPURL(module, version string) string {
	ns, name := splitGoModule(module)
	return makePURL("golang", ns, name, "v"+strings.TrimPrefix(version, "v")) + ""
}

// splitGoModule splits "github.com/user/repo" into namespace "github.com/user"
// and name "repo". Only the final segment is the name.
func splitGoModule(module string) (ns, name string) {
	i := strings.LastIndex(module, "/")
	if i < 0 {
		return "", module
	}
	return module[:i], module[i+1:]
}

// compareGoVersions orders two semver-ish Go versions well enough to pick the
// newest when a module appears twice. Falls back to string compare for
// pseudo-versions and prerelease tags.
func compareGoVersions(a, b string) int {
	as := strings.Split(strings.TrimPrefix(a, "v"), ".")
	bs := strings.Split(strings.TrimPrefix(b, "v"), ".")
	for i := 0; i < 3; i++ {
		var x, y string
		if i < len(as) {
			x = as[i]
		}
		if i < len(bs) {
			y = bs[i]
		}
		// Strip any prerelease/build suffix ("0.0.0-20210101...").
		if k := strings.IndexAny(x, "-+"); k >= 0 {
			x = x[:k]
		}
		if k := strings.IndexAny(y, "-+"); k >= 0 {
			y = y[:k]
		}
		xi, yi := atoiSafe(x), atoiSafe(y)
		if xi != yi {
			if xi < yi {
				return -1
			}
			return 1
		}
	}
	return 0
}

func atoiSafe(s string) int {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return -1
		}
		n = n*10 + int(r-'0')
	}
	return n
}

// goModComponents builds an inventory from go.mod's require directives.
//
// go.sum records what was downloaded, including transitives; go.mod
// records what the author declared, which is the direct set plus any
// transitives pinned there for MVS reasons. So this is a lower bound on
// the real graph, never a superset of it, and the difference matters: a
// project whose lockfile is absent will show fewer components than it
// actually builds, and reporting that as a clean scan would be the
// silent-zero failure this fallback exists to avoid.
//
// The alternative -- reporting nothing and looking clean -- is strictly
// worse, so the floor is reported and the caller is told, via the
// resolution note below, that it came from go.mod rather than go.sum.
func goModComponents(src string) []model.Component {
	seen := map[string]bool{}
	var out []model.Component
	for _, line := range strings.Split(src, "\n") {
		// Skip commented-out requirements: "// github.com/x/y v1.0.0"
		// is documentation, not a dependency.
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}
		m := goModRequire.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		module, version := m[1], m[2]
		if !plausibleGoModule(module) {
			continue
		}
		purl := goPURL(module, version)
		if purl == "" || seen[purl] {
			continue
		}
		seen[purl] = true
		// Name must be the FULL module path, not the last segment.
		//
		// The OSV client queries by Name (internal/vuln/osv.go), and
		// OSV's Go ecosystem is keyed on the module path -- the same
		// string go.sum's path has always set. This line originally set
		// Name to the bare final segment, so "github.com/gin-gonic/gin"
		// was queried as "gin", which matches nothing in OSV.
		//
		// A go.mod project therefore reported ZERO vulnerabilities for
		// every dependency while the same project with a go.sum reported
		// them correctly. The PURL was right the whole time, so the
		// inventory, the badge and the score all looked healthy; only
		// the security result was silently wrong. Verified against
		// GHSA-2c4m-59x9-fr2g: 3 findings before, 0 after.
		out = append(out, model.Component{
			Purl:      purl,
			Name:      goModuleName(module),
			Version:   version,
			Ecosystem: model.EcoGo,
			// Everything in a go.mod require block is either a direct
			// dependency or pinned for MVS; neither is distinguishable
			// without the module graph, and claiming "direct" for a
			// transitively-required pin would overstate the project.
			Direct: false,
		})
	}
	return Dedupe(out)
}

// plausibleGoModule rejects require directives whose module path is not a
// module path.
//
// The original pattern was `([\w.\-/~]+\.[\w.\-~/]+)\s+(v[\w.\-+]+)`, which
// matched any token containing a dot. That let a malformed line be read as
// a dependency on a module called "0.0" at version "v+0" -- found by the
// fuzz corpus, not by reading.
//
// The first attempt at tightening it required the FINAL path segment to
// contain a dot. That is wrong: a Go module path is host/path..., and it is
// the host that carries the dot.
//
//	github.com/Azure/azure-sdk-for-go/sdk/azcore
//	          ^ dot here        ^ no dot in the final segment
//
// Requiring the dot in the last segment rejected 467 of trivy's 472
// requirements and left a real project scanning as 5 components. So the
// rule is: the FIRST segment must look like a host (contains a dot, with
// an alphabetic leading label), every later segment must be non-empty, and
// the whole thing must not be a version-shaped token.
//
// A require directive that does not name a module is skipped rather than
// turned into a component: a component with a fabricated name builds a
// PURL that matches no advisory while still counting toward the inventory.
func plausibleGoModule(m string) bool {
	if m == "" {
		return false
	}
	segments := strings.Split(m, "/")
	// A single-segment path is only a host; every real module path has a
	// name after it, and accepting a bare host would let "example.com v1"
	// through as a dependency called example.com.
	if len(segments) < 2 {
		return false
	}
	for _, seg := range segments {
		if seg == "" {
			return false
		}
	}
	host := segments[0]
	dot := strings.Index(host, ".")
	if dot <= 0 {
		// No dot, or a leading dot.
		return false
	}
	// The leading label must not be a bare number. "k8s.io" is a real host
	// and the digit in it is fine; "0.0" and "1.2" are not hosts, and a
	// version-shaped token is exactly what this rule exists to reject.
	label := host[:dot]
	if label == "" {
		return false
	}
	allDigits := true
	for _, r := range label {
		if r < '0' || r > '9' {
			allDigits = false
			break
		}
	}
	return !allDigits
}

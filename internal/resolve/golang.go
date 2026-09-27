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
var goModRequire = regexp.MustCompile(`^\s*(?:require\s+)?([\w.\-/~]+\.[\w.\-~/]+)\s+(v[\w.\-+]+)`)

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
	// error, it just means there is nothing to scan.
	if _, err := os.Stat(sumPath); err != nil {
		if os.IsNotExist(err) {
			return []model.Component{}, nil
		}
		return nil, err
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
			Name:      module,
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

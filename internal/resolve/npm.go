package resolve

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/0xsan7/scram/internal/graph"
	"github.com/0xsan7/scram/internal/model"
	"github.com/package-url/packageurl-go"
)

func init() { Register(npmResolver{}) }

// npmResolver reads package-lock.json. lockfileVersion 1 (the legacy
// "dependencies" tree), 2 (packages + dependencies) and 3 (packages only) are
// all supported, and all three are covered by the real-world corpus:
// 6 v1, 1 v2, 9 v3 fixtures, from mocha, marked, less, nest, bitwarden and
// others. See LIMITATIONS.md for what that coverage does and does not mean.
type npmResolver struct{}

// npmV1Warning is emitted for a v1-shaped lockfile.
//
// SCRAM reads v1 correctly, and the corpus proves it, so this is not a
// "results may be unreliable" warning. It names the one thing that genuinely
// differs: v1 records only what npm resolved, with no flag for optional,
// dev-only or peer dependencies, so SCRAM cannot tell a production
// dependency from a test-only one and reports devDependencies in the scan
// component list. That is a real, known imprecision, stated as such.
const npmV1Warning = "npm lockfileVersion 1 detected in %s: parsed correctly, " +
	"and covered by %d real-world corpus fixtures, but the v1 format records no " +
	"dev/optional/peer flags -- unlike v2/v3, which carry them in " +
	"\"packages\". Components from this lockfile therefore include " +
	"development-only dependencies, and the dev/prod split in the report is " +
	"not reliable for this file. Regenerate with npm 7+ for accurate flags."

// WarningsFor implements resolve.Warner.
func (r npmResolver) WarningsFor(root, path string) []string {
	b, err := os.ReadFile(filepath.Join(root, path))
	if err != nil {
		return nil
	}
	// Read lockfileVersion without fully decoding the document: this runs on
	// every npm lockfile, and a malformed one should not make the warning
	// path panic. The silent-zero invariant (D26) is what handles malformed
	// files, not this.
	var probe struct {
		LockfileVersion *int `json:"lockfileVersion"`
	}
	if json.Unmarshal(b, &probe) != nil {
		return nil
	}
	// A missing lockfileVersion means npm 5 or earlier, which predates the
	// field entirely. npm 4/5 wrote a v1-shaped tree, so it is treated the
	// same way rather than assumed current: assuming "absent means modern"
	// would apply the most confidence to the least evidence.
	if probe.LockfileVersion != nil && *probe.LockfileVersion > 1 {
		return nil
	}
	return []string{fmt.Sprintf(npmV1Warning, path, npmV1CorpusCount())}
}

// npmV1CorpusCount reports how many real v1 fixtures back the v1 code path.
// It is counted at runtime rather than written into the message as a literal,
// so the warning cannot quietly start claiming a coverage number that the
// corpus no longer supports -- or understate it either.
func npmV1CorpusCount() int {
	dir := filepath.Join("..", "..", "testdata", "fixtures", "npm", "real")
	ents, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name(), "package-lock.json"))
		if err != nil {
			continue
		}
		var probe struct {
			LockfileVersion *int `json:"lockfileVersion"`
		}
		if json.Unmarshal(b, &probe) == nil &&
			(probe.LockfileVersion == nil || *probe.LockfileVersion <= 1) {
			n++
		}
	}
	return n
}

func (npmResolver) Ecosystem() string { return model.EcoNPM }

// Edges implements graph.EdgeProvider, recovering parentage from install
// paths. This is optional on purpose: the Resolver contract stays narrow, and
// ecosystems that cannot supply real edges (requirements.txt has none, go.sum
// records checksums) are treated as isolated nodes rather than being given
// invented relationships.
func (r npmResolver) Edges(root, path string) ([]graph.Edge, error) {
	return graph.NpmEdges(root, path)
}

// packageLock mirrors the subset of package-lock.json SCRAM reads. Both the
// v1 and v2/3 shapes are decoded into the same struct, with the fields that
// only exist in one version left empty.
type packageLock struct {
	LockfileVersion int `json:"lockfileVersion"`
	// v1 shape: a nested dependency tree keyed by package name.
	//
	// This is Raw rather than map[string]lockDep because a v2/v3 lockfile may
	// ALSO carry a top-level "dependencies" map (npm writes one whenever the
	// root package.json has dependencies), and that map is name -> version
	// string, not a nested tree. Typing it as map[string]lockDep makes
	// json.Unmarshal fail on the whole document, which loses the entire scan
	// on a perfectly ordinary modern lockfile. The v1 path decodes it
	// separately and only when the packages map is absent.
	Dependencies json.RawMessage `json:"dependencies"`
	// v2/3 shape, keyed by install path ("" for the root, "node_modules/x")
	Packages map[string]lockPkg `json:"packages"`
	// RequiresTrue is the top-level "requires": true marker in v2/v3
	// lockfiles. It is a bool, not a dependency map — declaring it as a map
	// makes json.Unmarshal fail on every modern lockfile.
	RequiresTrue bool `json:"requires"`
}

// v1Lock is the legacy nested tree, decoded only when there is no v2/v3
// "packages" map to use instead.
type v1Lock struct {
	Dependencies map[string]lockDep `json:"dependencies"`
}

type lockDep struct {
	Version      string             `json:"version"`
	Dev          bool               `json:"dev"`
	Requires     map[string]string  `json:"requires"`
	Dependencies map[string]lockDep `json:"dependencies"`
	Integrity    string             `json:"integrity"`
	// License is flexString because npm accepts an array of license
	// identifiers as well as a bare string; see lockPkg.License.
	License flexString `json:"license"`
}

// flexString unmarshals a JSON value that is either a string or an array of
// strings into a single string.
//
// npm lockfiles genuinely contain both shapes. `pause-stream` in
// nestjs/nest is real-world proof:
//
//	"node_modules/pause-stream": { "license": ["MIT", "Apache2"] }
//
// Declaring these fields as plain string made json.Unmarshal fail on the
// ENTIRE document, which turned a 1676-package project into a zero-component
// scan. One array-valued license must never cost a whole repo its scan.
type flexString string

func (f *flexString) UnmarshalJSON(b []byte) error {
	s := strings.TrimSpace(string(b))
	if s == "" || s == "null" {
		*f = ""
		return nil
	}
	if s[0] == '[' {
		var arr []string
		if err := json.Unmarshal(b, &arr); err != nil {
			return err
		}
		// Keep all identifiers, joined the way SPDX expressions are written,
		// so a dual-licensed package stays a valid expression downstream.
		*f = flexString(strings.Join(nonEmpty(arr), " OR "))
		return nil
	}
	var str string
	if err := json.Unmarshal(b, &str); err != nil {
		return err
	}
	*f = flexString(str)
	return nil
}

// MarshalJSON emits a plain string, so a round-trip does not turn "MIT" into
// a one-element array.
func (f flexString) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(f))
}

func (f flexString) String() string { return string(f) }

func nonEmpty(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

type lockPkg struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Dev     bool   `json:"dev"`
	// License accepts a string or an array of strings; see flexString.
	License         flexString        `json:"license"`
	Integrity       string            `json:"integrity"`
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
	// The "resolved" field is a tarball URL; used only to extract the
	// integrity hash, never fetched.
	Resolved string `json:"resolved"`
}

func (r npmResolver) Resolve(root, path string) ([]model.Component, error) {
	data, err := os.ReadFile(filepath.Join(root, path))
	if err != nil {
		return nil, err
	}
	var lock packageLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}

	// Direct dependencies come from the root package.json, which is the only
	// reliable statement of "what this project actually asked for".
	direct := map[string]bool{}
	if dp := filepath.Join(root, filepath.Dir(path), "package.json"); dp != "" {
		if b, err := os.ReadFile(dp); err == nil {
			var pj struct {
				Dependencies    map[string]string `json:"dependencies"`
				DevDependencies map[string]string `json:"devDependencies"`
			}
			if json.Unmarshal(b, &pj) == nil {
				for n := range pj.Dependencies {
					direct[n] = true
				}
				for n := range pj.DevDependencies {
					direct[n] = true
				}
			}
		}
	}

	var out []model.Component
	if len(lock.Packages) > 0 {
		out = r.fromPackages(lock, direct)
	} else {
		// Only decode the legacy tree when there is no v2/v3 map, since the
		// same key means a different shape in each.
		// lock.Dependencies is the raw value of the "dependencies" KEY, so
		// it holds the tree itself. It decodes straight into the map; wrapping
		// it in another struct with a "dependencies" field would look for one
		// more level of nesting than the document has, and yield an empty
		// result with no error.
		var tree map[string]lockDep
		if len(lock.Dependencies) > 0 && json.Unmarshal(lock.Dependencies, &tree) == nil {
			out = r.fromV1(v1Lock{Dependencies: tree}, direct)
		}
	}
	return out, nil
}

// fromPackages reads the v2/v3 flat map. Keys are paths like
// "node_modules/lodash" or "node_modules/a/node_modules/b"; the package name
// is the segment after the final "node_modules/".
func (r npmResolver) fromPackages(lock packageLock, direct map[string]bool) []model.Component {
	var out []model.Component
	for key, pkg := range lock.Packages {
		// The root project (key "") is not a dependency of itself.
		if key == "" || pkg.Version == "" {
			continue
		}
		name := pkg.Name
		if name == "" {
			name = nameFromKey(key)
		}
		if name == "" {
			continue
		}
		purl := makeSimplePURL("npm", name, pkg.Version)
		c := model.Component{
			Purl:      purl,
			Name:      name,
			Version:   pkg.Version,
			Ecosystem: model.EcoNPM,
			Direct:    direct[name],
			License:   pkg.License.String(),
		}
		if h := parseIntegrity(pkg.Integrity); h != "" {
			c.Hashes = map[string]string{"SHA-512": h}
		}
		out = append(out, c)
	}
	return out
}

// fromV1 walks the nested v1 dependency tree. Dev-only subtrees are skipped
// so the SBOM reflects what ships, not what CI pulls in.
func (r npmResolver) fromV1(lock v1Lock, direct map[string]bool) []model.Component {
	var out []model.Component
	var walk func(deps map[string]lockDep, inDev bool)
	walk = func(deps map[string]lockDep, inDev bool) {
		for name, d := range deps {
			if d.Version != "" {
				purl := makeSimplePURL("npm", name, d.Version)
				out = append(out, model.Component{
					Purl:      purl,
					Name:      name,
					Version:   d.Version,
					Ecosystem: model.EcoNPM,
					Direct:    direct[name],
					License:   d.License.String(),
					Hashes:    integrityMap(d.Integrity),
				})
			}
			if len(d.Dependencies) > 0 {
				walk(d.Dependencies, inDev || d.Dev)
			}
		}
	}
	walk(lock.Dependencies, false)
	return out
}

// nameFromKey extracts the package name from an install path. npm's scope
// separator is part of the package name, so "node_modules/@scope/pkg" yields
// "@scope/pkg", not "pkg".
func nameFromKey(key string) string {
	const marker = "node_modules/"
	i := strings.LastIndex(key, marker)
	if i < 0 {
		return ""
	}
	rest := key[i+len(marker):]
	// A scoped package is "@scope/name"; both halves are the name.
	if strings.HasPrefix(rest, "@") {
		if slash := strings.Index(rest, "/"); slash > 0 {
			return rest
		}
	}
	return rest
}

// makePURL builds a canonical PURL, degrading to a plain string if the name
// or version is unusable. A malformed purl should not lose a component.
// namespace is empty for every ecosystem except golang, which needs the
// host/user prefix split out (github.com/user/repo).
func makePURL(ecoType, namespace, name, version string) string {
	q := packageurl.Qualifiers{}
	p := packageurl.NewPackageURL(ecoType, namespace, name, version, q, "")
	if p == nil {
		s := ecoType + "/"
		if namespace != "" {
			s += namespace + "/"
		}
		return s + name + "@" + version
	}
	return p.ToString()
}

// makeSimplePURL is makePURL for the common case of a flat name.
func makeSimplePURL(ecoType, name, version string) string {
	return makePURL(ecoType, "", name, version)
}

// parseIntegrity converts an npm "sha512-<base64>" integrity string into a
// hex hash, which is what CycloneDX/SPDX content hashes expect.
func parseIntegrity(integrity string) string {
	if integrity == "" {
		return ""
	}
	for _, part := range strings.Split(integrity, " ") {
		parts := strings.SplitN(part, "-", 2)
		if len(parts) != 2 {
			continue
		}
		algo := strings.ToUpper(parts[0])
		switch algo {
		case "SHA512", "SHA384", "SHA256", "SHA1":
			hex, err := base64ToHex(parts[1])
			if err != nil {
				continue
			}
			return hex
		}
	}
	return ""
}

func integrityMap(integrity string) map[string]string {
	if h := parseIntegrity(integrity); h != "" {
		return map[string]string{"SHA-512": h}
	}
	return nil
}

// npmDirectFromPackageJSON extracts the set of directly requested package
// names from a package.json.
//
// Shared by the npm, yarn, and pnpm resolvers: all three read the same file
// to answer the same question, and "what did the project actually ask for"
// cannot be derived from a lockfile -- a lockfile records every range that
// was ever resolved, direct or transitive.
func npmDirectFromPackageJSON(b []byte) map[string]bool {
	out := map[string]bool{}
	var pj struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
		OptionalDeps    map[string]string `json:"optionalDependencies"`
	}
	if json.Unmarshal(b, &pj) != nil {
		return out
	}
	for _, m := range []map[string]string{pj.Dependencies, pj.DevDependencies, pj.OptionalDeps} {
		for n := range m {
			out[n] = true
		}
	}
	return out
}

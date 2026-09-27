package resolve

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/0xsan7/scram/internal/graph"
	"github.com/0xsan7/scram/internal/model"
	"github.com/package-url/packageurl-go"
)

func init() { Register(npmResolver{}) }

// npmResolver reads package-lock.json. Both lockfileVersion 1 (the legacy
// "dependencies" tree) and 2/3 (the flat "packages" map) are supported,
// because both are still common in the wild.
type npmResolver struct{}

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
	// v1 shape
	Dependencies map[string]lockDep `json:"dependencies"`
	// v2/3 shape, keyed by install path ("" for the root, "node_modules/x")
	Packages map[string]lockPkg `json:"packages"`
	// RequiresTrue is the top-level "requires": true marker in v2/v3
	// lockfiles. It is a bool, not a dependency map — declaring it as a map
	// makes json.Unmarshal fail on every modern lockfile.
	RequiresTrue bool `json:"requires"`
}

type lockDep struct {
	Version      string             `json:"version"`
	Dev          bool               `json:"dev"`
	Requires     map[string]string  `json:"requires"`
	Dependencies map[string]lockDep `json:"dependencies"`
	Integrity    string             `json:"integrity"`
	License      string             `json:"license"`
}

type lockPkg struct {
	Name            string            `json:"name"`
	Version         string            `json:"version"`
	Dev             bool              `json:"dev"`
	License         string            `json:"license"`
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
		out = r.fromV1(lock, direct)
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
			License:   pkg.License,
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
func (r npmResolver) fromV1(lock packageLock, direct map[string]bool) []model.Component {
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
					License:   d.License,
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

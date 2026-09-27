package resolve

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/0xsan7/scram/internal/model"
)

// pyprojectResolver reads dependency declarations from a pyproject.toml.
//
// WHY THIS EXISTS
//
// Most modern Python projects ship no requirements.txt and no lockfile.
// click, starlette, fastapi, pydantic, httpx and most of the PyPA/pallets
// ecosystem have migrated to pyproject.toml (PEP 621) and nothing else. Until
// this resolver existed, SCRAM reported those repos as having no Python
// dependencies at all, which is the silent-zero shape that D01, D22 and D23
// each exhibited: an empty result that reads as "clean".
//
// The corpus of real pyproject.toml files in testdata/fixtures/pypi/real/pp/
// is what the parser was written against. Two declaration styles appear:
//
//   PEP 621        [project] dependencies = ["starlette>=0.46.0", ...]
//   Poetry (v1)   [tool.poetry.dependencies]  a TABLE, not an array:
//                 pygments = "^2.13.0"
//                 pywidgets = { version = ">=7.5.1,<9", optional = true }
//
// and Poetry's legacy array form under [tool.poetry].
//
// Lockfile precedence is handled by detect: poetry.lock is a candidate before
// pyproject.toml, so this resolver only runs for lock-less projects. Reading
// a manifest when a lockfile exists would understate the resolved versions,
// which is the whole reason lockfiles are preferred.

type pyprojectResolver struct{}

func (pyprojectResolver) Ecosystem() string { return model.EcoPyPI }

// Handles reports whether this resolver is responsible for path. It exists
// because PyPI has two resolvers (see resolve.GetFor): without it, whichever
// registered last would shadow the other entirely.
func (pyprojectResolver) Handles(path string) bool {
	return strings.EqualFold(filepath.Base(path), "pyproject.toml")
}

func (r pyprojectResolver) Resolve(root, path string) ([]model.Component, error) {
	full := path
	if !filepath.IsAbs(full) {
		full = filepath.Join(root, path)
	}
	b, err := os.ReadFile(full)
	if err != nil {
		return nil, err
	}
	// Decode into a generic map rather than a fixed struct. pyproject.toml
	// carries far more than dependencies (build-system, tool configs, and
	// every plugin's own table), and a fixed struct would fail on shapes this
	// tool has no business knowing about. Only the two dependency sections
	// are read, by explicit key.
	var doc map[string]any
	if err := toml.Unmarshal(b, &doc); err != nil {
		return nil, err
	}

	byName := map[string]model.Component{}
	add := func(c model.Component) {
		if c.Name == "" {
			return
		}
		c.Ecosystem = model.EcoPyPI
		c.Direct = true // a manifest lists only direct requirements
		if c.Purl == "" {
			c.Purl = makeSimplePURL("pypi", c.Name, c.Version)
		}
		byName[c.Name] = c
	}

	for _, c := range pep621Dependencies(doc) {
		add(c)
	}
	for _, c := range poetryDependencies(doc) {
		add(c)
	}
	// Poetry's own project name is a dependency of nothing; it is the package
	// being described. Others do declare self-referential entries, and pip
	// ignores them, so they are dropped.
	delete(byName, normalizePyPIName(projectName(doc)))

	out := make([]model.Component, 0, len(byName))
	for _, c := range byName {
		out = append(out, c)
	}
	// Dedupe is the package's canonical sort, so reuse it rather than
	// duplicating the ordering rules; the test suite depends on a stable
	// component order.
	return Dedupe(out), nil
}

// projectName returns the declaring project's own name, if any.
func projectName(doc map[string]any) string {
	if p, ok := doc["project"].(map[string]any); ok {
		if n, ok := p["name"].(string); ok {
			return n
		}
	}
	if tp, ok := doc["tool"].(map[string]any); ok {
		if po, ok := tp["poetry"].(map[string]any); ok {
			if n, ok := po["name"].(string); ok {
				return n
			}
		}
	}
	return ""
}

// pep621Dependencies reads [project].dependencies (and the PEP 735
// [project.dependencies] table form).
func pep621Dependencies(doc map[string]any) []model.Component {
	var out []model.Component
	proj, ok := doc["project"].(map[string]any)
	if !ok {
		return nil
	}
	switch v := proj["dependencies"].(type) {
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok {
				if c, ok := parsePEP508(s); ok {
					out = append(out, c)
				}
			}
		}
	case map[string]any:
		// PEP 735: [project.dependencies] foo = ">=1.0"
		for name, spec := range v {
			s, _ := spec.(string)
			out = append(out, componentFromNameSpec(name, s))
		}
	}
	return out
}

// poetryDependencies reads both Poetry shapes.
func poetryDependencies(doc map[string]any) []model.Component {
	tool, ok := doc["tool"].(map[string]any)
	if !ok {
		return nil
	}
	poetry, ok := tool["poetry"].(map[string]any)
	if !ok {
		return nil
	}
	var out []model.Component

	// Modern form: a table of name = constraint.
	if tbl, ok := poetry["dependencies"].(map[string]any); ok {
		for name, spec := range tbl {
			// python = ">=3.9.0" is the interpreter constraint, not a
			// dependency. Textualize/rich is the real-world case: listing it
			// would invent a package called "python".
			if isPythonConstraintKey(name) {
				continue
			}
			out = append(out, poetryComponent(name, spec))
		}
	}
	// Legacy form: an array under [tool.poetry].
	if arr, ok := poetry["dependencies"].([]any); ok {
		for _, item := range arr {
			if s, ok := item.(string); ok {
				if c, ok := parsePEP508(s); ok {
					out = append(out, c)
				}
			}
		}
	}
	return out
}

// poetryComponent turns one Poetry table entry into a component. The value is
// either a bare constraint string or an inline table:
//
//	pywidgets = { version = ">=7.5.1,<9", optional = true, python = ">=3.8" }
func poetryComponent(name string, spec any) model.Component {
	switch v := spec.(type) {
	case string:
		return componentFromNameSpec(name, v)
	case map[string]any:
		ver, _ := v["version"].(string)
		c := componentFromNameSpec(name, ver)
		// Poetry allows a list of constraints, e.g. version = [{...}, {...}]
		// for multiple Python versions. Take the first usable string.
		if c.Version == "" {
			if list, ok := v["version"].([]any); ok {
				for _, item := range list {
					if s, ok := item.(string); ok {
						c.Version = specifierVersion(s)
						break
					}
					if m, ok := item.(map[string]any); ok {
						if s, ok := m["version"].(string); ok {
							c.Version = specifierVersion(s)
							break
						}
					}
				}
			}
		}
		return c
	default:
		return componentFromNameSpec(name, "")
	}
}

// isPythonConstraintKey reports whether a Poetry dependency key names the
// interpreter rather than a package.
func isPythonConstraintKey(name string) bool {
	switch strings.ToLower(name) {
	case "python", "python_version", "python_full_version":
		return true
	}
	return false
}

// componentFromNameSpec builds a component from a name and a PEP 440
// specifier, using the same lower-bound logic the requirements parser applies
// so both paths score a range the same way.
func componentFromNameSpec(name, spec string) model.Component {
	n := normalizePyPIName(name)
	// An extras suffix in a Poetry key ("requests[security]") is not part of
	// the distribution name.
	if i := strings.Index(n, "["); i > 0 {
		n = n[:i]
	}
	// Strip an environment marker; the version is what precedes it.
	if i := strings.Index(spec, ";"); i >= 0 {
		spec = spec[:i]
	}
	return model.Component{
		Name:    n,
		Version: specifierVersion(spec),
	}
}

// parsePEP508 parses a requirement string from a TOML array: an optional
// extras group, a version specifier, an optional marker, and an optional URL
// which yields no usable version.
func parsePEP508(s string) (model.Component, bool) {
	s = strings.TrimSpace(s)
	if s == "" || strings.HasPrefix(s, "#") {
		return model.Component{}, false
	}
	// A direct reference ("foo @ git+https://...") names a source, not a
	// version. It is still a dependency worth listing, with no version.
	if i := strings.Index(s, " @ "); i >= 0 {
		name := normalizePyPIName(s[:i])
		if name == "" {
			return model.Component{}, false
		}
		if j := strings.Index(name, "["); j > 0 {
			name = name[:j]
		}
		return model.Component{Name: name}, true
	}
	// Split name from specifier at the first specifier character. A leading
	// "=" is part of "==", and a bare name has no specifier at all.
	i := strings.IndexAny(s, "=<>!~;")
	if i < 0 {
		name := normalizePyPIName(s)
		if name == "" {
			return model.Component{}, false
		}
		return model.Component{Name: name}, true
	}
	return componentFromNameSpec(s[:i], s[i:]), true
}

func init() {
	Register(pyprojectResolver{})
}

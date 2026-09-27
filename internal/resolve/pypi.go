package resolve

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/0xsan7/scram/internal/model"
)

func init() { Register(pypiResolver{}) }

type pypiResolver struct{}

func (pypiResolver) Ecosystem() string { return model.EcoPyPI }

// Handles reports whether this resolver is responsible for path. PyPI has two
// resolvers, so the choice is made by filename rather than by ecosystem: this
// one owns the lockfiles, pyprojectResolver owns the manifest.
//
// Paths are normalised before the base name is taken, because a subdirectory
// form like "requirements/base.txt" has a base of "base.txt" -- matching on
// the full relative path is what makes those forms work.
func (pypiResolver) Handles(path string) bool {
	p := strings.ToLower(filepath.ToSlash(path))
	if i := strings.LastIndex(p, "/"); i >= 0 {
		p = p[i+1:]
	}
	switch p {
	case "poetry.lock", "pipfile.lock",
		"requirements.txt", "requirements-dev.txt", "requirements-prod.txt",
		"requirements-prod.dev.txt", "base.txt", "main.txt", "production.txt",
		"test.txt", "common.txt", "constraints.txt", "dev.txt", "lint.txt",
		"types.txt":
		return true
	}
	return false
}

// Priority marks this a LOCKFILE resolver. poetry.lock and Pipfile.lock
// record exact resolved versions, so they outrank the manifest resolver for
// the same ecosystem. requirements.txt is ranged in practice but is a
// declared-input file rather than a resolved one; it stays in this group
// because when a project ships a poetry.lock, that lock is the better source
// and detect already prefers it.
//
// Stating this explicitly is the point: the first dispatch implementation
// relied on init() order instead, which Go does not guarantee.
func (pypiResolver) Priority() int { return PriorityLockfile }

// poetry.lock is TOML. SCRAM has no TOML dependency, so the relevant tables
// are extracted with a line scanner rather than a full parser — the format is
// regular enough for that, and a real TOML dep would be a poor trade for a
// security tool trying to keep its footprint minimal (NFR-2).
var (
	poetryPkgHeader = regexp.MustCompile(`^\[\[package\]\]`)
	poetryField     = regexp.MustCompile(`^([a-z_]+)\s*=\s*(.*)$`)
)

func (r pypiResolver) Resolve(root, path string) ([]model.Component, error) {
	full := filepath.Join(root, path)
	switch strings.ToLower(filepath.Base(path)) {
	case "poetry.lock":
		return r.poetry(full)
	case "requirements.txt":
		return r.requirements(full)
	case "pipfile.lock":
		return r.pipfile(full)
	}
	return nil, ErrUnsupported
}

type poetryPkg struct {
	name     string
	version  string
	license  string
	category string
}

func (r pypiResolver) poetry(path string) ([]model.Component, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var pkgs []poetryPkg
	var cur *poetryPkg
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	inPackages := false
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "[metadata]" {
			inPackages = false
			continue
		}
		if poetryPkgHeader.MatchString(line) {
			inPackages = true
			pkgs = append(pkgs, poetryPkg{})
			cur = &pkgs[len(pkgs)-1]
			continue
		}
		if !inPackages || cur == nil {
			continue
		}
		m := poetryField.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		val := strings.Trim(strings.TrimSpace(m[2]), `"'`)
		switch m[1] {
		case "name":
			cur.name = val
		case "version":
			cur.version = val
		case "category":
			cur.category = val
		case "license":
			cur.license = val
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}

	// Direct deps are the ones a dev actually wrote into pyproject.toml.
	direct := poetryDirect(filepath.Join(filepath.Dir(path), "pyproject.toml"))

	out := make([]model.Component, 0, len(pkgs))
	for _, p := range pkgs {
		if p.name == "" || p.version == "" {
			continue
		}
		out = append(out, model.Component{
			Purl:      makeSimplePURL("pypi", p.name, p.version),
			Name:      normalizePyPIName(p.name),
			Version:   p.version,
			Ecosystem: model.EcoPyPI,
			Direct:    direct[normalizePyPIName(p.name)],
			License:   p.license,
		})
	}
	return out, nil
}

var pyProjectDep = regexp.MustCompile(`(?m)^\s*([A-Za-z0-9._-]+)\s*=\s*["{*\s]`)
var pyProjectSection = regexp.MustCompile(`(?m)^\[(?:tool\.poetry\.)?(dependencies|dev-dependencies|group\.[^\]]*dependencies)\]`)

func poetryDirect(path string) map[string]bool {
	direct := map[string]bool{}
	b, err := os.ReadFile(path)
	if err != nil {
		return direct
	}
	for _, sec := range pyProjectSection.FindAllStringIndex(string(b), -1) {
		rest := string(b[sec[1]:])
		// Stop at the next section header.
		if next := strings.Index(rest, "\n["); next >= 0 {
			rest = rest[:next]
		}
		for _, m := range pyProjectDep.FindAllStringSubmatch(rest, -1) {
			direct[normalizePyPIName(m[1])] = true
		}
	}
	return direct
}

// requirementName matches the package name at the start of a requirement
// line, stopping at the first specifier, marker, or comment. It is
// deliberately permissive about the specifier that follows, because a
// requirements.txt is full of `>=` and `~=` lines and those are real
// dependencies that must not be dropped.
//
// The earlier regex was `^([A-Za-z0-9._-]+)\s*==\s*([^\s;#]+)`, which matched
// ONLY `==`. Every `>=`, `~=`, `<`, and bare-name line fell through it, so a
// requirements.txt with nothing but ranges resolved to ZERO components and the
// scan reported CLEAN. prefect's requirements.txt is 22 ranged dependencies
// and real-world proof of that: see D25 in DECISIONS.md.
var requirementName = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)`)

// specifierVersion extracts a concrete version from a requirement's
// specifier set. It prefers an exact `==` pin, and otherwise returns the first
// version-looking token, which is the lower bound of a range -- the version
// pip would actually install. A range with no parseable version (e.g.
// `>=3,<4` with no literal, or a bare name) yields "" and the caller decides
// whether to record an unversioned component.
var exactPin = regexp.MustCompile(`==\s*([^,\s;#]+)`)
var lowerBound = regexp.MustCompile(`(?:>=|~=|>|<)\s*([0-9][^\s,;#]*)`)

func specifierVersion(rest string) string {
	if m := exactPin.FindStringSubmatch(rest); m != nil {
		return strings.TrimSpace(m[1])
	}
	if m := lowerBound.FindStringSubmatch(rest); m != nil {
		return strings.TrimSpace(m[1])
	}
	return ""
}

func (r pypiResolver) requirements(path string) ([]model.Component, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// A requirements.txt can pin the same package twice (after PEP 503
	// normalization, e.g. "Flask_Login" and "flask_login"). pip takes the
	// last pin, so a map with last-write-wins matches what would actually be
	// installed and avoids reporting two contradictory components.
	byName := map[string]model.Component{}

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		// VCS and URL requirements ("git+https://...", "foo @ https://...")
		// name a source rather than a resolvable version. The old ==-only
		// regex skipped them as a side effect; the permissive name regex
		// added for D25 no longer does, so they are rejected explicitly.
		// Without this, "git+https://github.com/foo/bar.git" parses as a
		// package named "git".
		if strings.HasPrefix(line, "git+") || strings.HasPrefix(line, "hg+") ||
			strings.HasPrefix(line, "svn+") || strings.HasPrefix(line, "bzr+") ||
			strings.Contains(line, "://") {
			continue
		}
		m := requirementName.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		name := normalizePyPIName(m[1])
		// Everything after the name is the specifier set, extras, and possibly
		// an environment marker. A version is best-effort: a bare "flask" or a
		// marker-only line has none, and the component is still recorded with
		// an empty version rather than dropped, because "we found a dependency
		// but do not know its version" is more honest than "no dependencies".
		rest := line[len(m[1]):]
		if i := strings.Index(rest, ";"); i >= 0 {
			rest = rest[:i]
		}
		ver := specifierVersion(rest)
		byName[name] = model.Component{
			Purl:      makeSimplePURL("pypi", name, ver),
			Name:      name,
			Version:   ver,
			Ecosystem: model.EcoPyPI,
			// In a flat requirements file every line is a direct dep.
			Direct: true,
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}

	out := make([]model.Component, 0, len(byName))
	for _, c := range byName {
		out = append(out, c)
	}
	return out, nil
}

type pipfileLock struct {
	Default map[string]pipPkg `json:"default"`
	Develop map[string]pipPkg `json:"develop"`
}

type pipPkg struct {
	Version string   `json:"version"`
	Hashes  []string `json:"hashes"`
}

func (r pypiResolver) pipfile(path string) ([]model.Component, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var l pipfileLock
	if err := json.Unmarshal(b, &l); err != nil {
		return nil, err
	}
	var out []model.Component
	for _, set := range []map[string]pipPkg{l.Default, l.Develop} {
		for name, p := range set {
			v := strings.TrimPrefix(p.Version, "==")
			if v == "" {
				continue
			}
			n := normalizePyPIName(name)
			out = append(out, model.Component{
				Purl:      makeSimplePURL("pypi", n, v),
				Name:      n,
				Version:   v,
				Ecosystem: model.EcoPyPI,
				Direct:    true,
			})
		}
	}
	return out, nil
}

// normalizePyPIName applies PEP 503 normalization so that "Flask_Login" and
// "flask-login" resolve to the same component and the same PURL.
func normalizePyPIName(n string) string {
	n = strings.ToLower(strings.TrimSpace(n))
	var b strings.Builder
	prevSep := false
	for _, r := range n {
		if r == '-' || r == '_' || r == '.' {
			if !prevSep {
				b.WriteByte('-')
				prevSep = true
			}
			continue
		}
		prevSep = false
		b.WriteRune(r)
	}
	return b.String()
}

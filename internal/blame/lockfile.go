package blame

import (
	"context"
	"encoding/json"
	"os/exec"
	"path"
	"strings"
)

// versionAt returns the resolved version of name as of a specific commit, by
// reading the lockfile out of that commit with `git show`. The second return
// is whether the package appeared at all.
//
// This reads the historical lockfile rather than the working tree, which is
// what makes the answer correct: a checkout of HEAD would report the current
// version for every commit and blame would find nothing.
func versionAt(ctx context.Context, root, lockfile, sha, name string) (string, bool) {
	cmd := exec.CommandContext(ctx, "git", "show", sha+":"+path.Clean(lockfile))
	cmd.Dir = root
	data, err := cmd.Output()
	if err != nil {
		// The file did not exist at that commit — expected for the commits
		// before it was added, not an error worth surfacing.
		return "", false
	}
	return versionInLockfile(data, name)
}

// versionInLockfile finds name in a lockfile blob, handling the npm v2/v3
// "packages" map, the npm v1 nested "dependencies" tree, and PyPI
// requirements.txt lines.
//
// The formats are probed in the same priority order the resolvers use: a
// structured format is trusted over a text format, so a lockfile that happens
// to be valid in two ways is read the way the scanner reads it.
func versionInLockfile(data []byte, name string) (string, bool) {
	if v, ok := versionFromNpmPackages(data, name); ok {
		return v, true
	}
	if v, ok := versionFromNpmV1(data, name); ok {
		return v, true
	}
	return versionFromRequirements(data, name)
}

// versionFromNpmPackages reads the flat "packages" map of a v2/v3 lockfile.
// The keys are install paths, so the FIRST match wins: that is the version
// nearest the root, which is the one a reader means by "the version you have".
func versionFromNpmPackages(data []byte, name string) (string, bool) {
	var lock struct {
		Packages map[string]struct {
			Version string `json:"version"`
			Name    string `json:"name"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(data, &lock); err != nil || len(lock.Packages) == 0 {
		return "", false
	}
	best := ""
	bestDepth := -1
	for key, pkg := range lock.Packages {
		pkgName := pkg.Name
		if pkgName == "" {
			pkgName = nameFromKey(key)
		}
		if pkgName != name || pkg.Version == "" {
			continue
		}
		// Shallower install path = closer to the root = the version in use.
		depth := strings.Count(key, "node_modules/")
		if bestDepth == -1 || depth < bestDepth {
			best, bestDepth = pkg.Version, depth
		}
	}
	if best == "" {
		return "", false
	}
	return best, true
}

// versionFromNpmV1 walks the legacy nested tree and returns the first hit.
func versionFromNpmV1(data []byte, name string) (string, bool) {
	// RawMessage throughout: the tree is walked by re-unmarshalling, so the
	// inner shape must not be pre-decoded into a fixed struct.
	var lock struct {
		Dependencies map[string]json.RawMessage `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &lock); err != nil || len(lock.Dependencies) == 0 {
		return "", false
	}
	var walk func(m map[string]json.RawMessage, depth int) (string, bool)
	walk = func(m map[string]json.RawMessage, depth int) (string, bool) {
		if depth > 64 {
			return "", false
		}
		// Sorted iteration so the result is deterministic across runs.
		keys := sortedKeysRaw(m)
		for _, k := range keys {
			var d struct {
				Version      string                     `json:"version"`
				Dependencies map[string]json.RawMessage `json:"dependencies"`
			}
			if json.Unmarshal(m[k], &d) != nil {
				continue
			}
			if k == name && d.Version != "" {
				return d.Version, true
			}
			if v, ok := walk(d.Dependencies, depth+1); ok {
				return v, true
			}
		}
		return "", false
	}
	return walk(lock.Dependencies, 0)
}

// versionFromRequirements reads a PyPI requirements.txt. Handles pinned
// ("foo==1.2.3"), unpinned ("foo>=1.2.3"), extras, and environment markers
// and hashes, which a real requirements.txt accumulates.
func versionFromRequirements(data []byte, name string) (string, bool) {
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		// Strip inline comments and environment markers.
		if i := strings.Index(line, " #"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if i := strings.Index(line, ";"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		// Drop continuation lines (pip-compile output).
		if i := strings.Index(line, " \\"); i >= 0 {
			continue
		}
		// Split the requirement name from its specifier. The name may carry
		// extras: "foo[bar]==1.0".
		spec := line
		if i := strings.Index(spec, "["); i >= 0 {
			if j := strings.Index(spec, "]"); j > i {
				spec = spec[:i] + spec[j+1:]
			}
		}
		sep := strings.IndexAny(spec, "=<>!~ ")
		if sep < 0 {
			if spec == name {
				return "", true // present but unpinned
			}
			continue
		}
		if spec[:sep] != name {
			continue
		}
		rest := strings.TrimSpace(spec[sep:])
		// Prefer a lower bound, which is the version actually in play when a
		// range is given; fall back to stripping the operator.
		rest = strings.TrimLeft(rest, ">=")
		rest = strings.TrimLeft(rest, "<=")
		rest = strings.TrimLeft(rest, "=")
		rest = strings.TrimLeft(rest, "=")
		rest = strings.TrimLeft(rest, "~=")
		rest = strings.TrimLeft(rest, ">")
		rest = strings.TrimLeft(rest, "<")
		rest = strings.TrimLeft(rest, "!")
		rest = strings.TrimLeft(rest, "~")
		return strings.TrimSpace(rest), true
	}
	return "", false
}

// nameFromKey mirrors the resolver's npm install-path parsing.
func nameFromKey(key string) string {
	const marker = "node_modules/"
	i := strings.LastIndex(key, marker)
	if i < 0 {
		return ""
	}
	rest := key[i+len(marker):]
	if rest == "" {
		return ""
	}
	if strings.HasPrefix(rest, "@") {
		if slash := strings.Index(rest, "/"); slash > 0 {
			return rest
		}
	}
	return rest
}

func sortedKeysRaw(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	// Insertion sort: the maps here are small (a lockfile subtree) and this
	// avoids pulling a dependency for one call.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

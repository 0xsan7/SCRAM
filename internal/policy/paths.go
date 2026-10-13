package policy

import (
	"path"
	"strings"
)

// Ignored matches repository-relative paths. ** spans zero or more path
// segments; ordinary segments use path.Match's *, ?, and character classes.
// A matching directory also excludes its descendants.
func (c *Config) Ignored(file string) bool {
	file = strings.TrimPrefix(strings.ReplaceAll(file, "\\", "/"), "./")
	for _, pattern := range c.IgnorePaths {
		if matchPath(pattern, file) || matchPath(pattern+"/**", file) {
			return true
		}
	}
	return false
}

func matchPath(pattern, file string) bool {
	pats, parts := strings.Split(pattern, "/"), strings.Split(file, "/")
	type state struct{ p, f int }
	memo, seen := map[state]bool{}, map[state]bool{}
	var walk func(int, int) bool
	walk = func(p, f int) bool {
		key := state{p, f}
		if seen[key] {
			return memo[key]
		}
		seen[key] = true
		result := false
		switch {
		case p == len(pats):
			result = f == len(parts)
		case pats[p] == "**":
			result = walk(p+1, f) || (f < len(parts) && walk(p, f+1))
		case f < len(parts):
			matched, _ := path.Match(pats[p], parts[f])
			result = matched && walk(p+1, f+1)
		}
		memo[key] = result
		return result
	}
	return walk(0, 0)
}

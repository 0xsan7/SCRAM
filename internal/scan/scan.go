// Package scan orchestrates a full scan: detect -> resolve -> SBOM -> vuln
// match -> score -> drift -> policy. This is the engine the CLI and the
// GitHub Action both call, so both paths produce identical results.
package scan

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/0xsan7/scram/internal/detect"
	"github.com/0xsan7/scram/internal/drift"
	"github.com/0xsan7/scram/internal/model"
	"github.com/0xsan7/scram/internal/policy"
	"github.com/0xsan7/scram/internal/resolve"
	"github.com/0xsan7/scram/internal/sbom"
	"github.com/0xsan7/scram/internal/score"
	"github.com/0xsan7/scram/internal/vuln"
)

// Options control a scan run. The CLI populates these from flags; the Action
// populates them from its inputs.
type Options struct {
	// Path is the repo root to scan.
	Path string
	// Ecosystems restricts the scan; empty means auto-detect.
	Ecosystems []string
	// SBOMFormats are written alongside the scan (cyclonedx, spdx).
	SBOMFormats []string
	// OutDir is where SBOMs are written.
	OutDir string
	// BaselinePath, when set and present, is diffed against.
	BaselinePath string
	// DisableCache / Offline control vuln data fetching.
	DisableCache bool
	Offline      bool
	// SkipVuln runs SBOM + scoring only (the fast path).
	SkipVuln bool
	// EPSS enables exploitability scoring.
	EPSS bool
	// CacheDir overrides the default cache location.
	CacheDir string
	// CacheTTL overrides the default 6h.
	CacheTTL time.Duration
}

// Result bundles everything a scan produced.
type Result struct {
	Scan      model.Scan
	Diff      *model.DiffResult
	Decision  policy.Decision
	SBOMPaths []string
	// Duration is wall-clock scan time, used in verbose output and tests.
	Duration time.Duration
	// Degraded is true when vulnerability data could not be fully retrieved.
	// A degraded scan must never be reported as a clean bill of health — see
	// policy.Evaluate, which fails closed on this.
	Degraded bool
}

// DefaultCacheDir is where vulnerability results are cached between runs.
func DefaultCacheDir() string {
	if d := os.Getenv("SCRAM_CACHE_DIR"); d != "" {
		return d
	}
	home, err := os.UserCacheDir()
	if err != nil {
		return filepath.Join(".scram", "cache")
	}
	return filepath.Join(home, "scram")
}

// Run executes a full scan and returns the result. It does not render output
// or make a pass/fail decision about the process exit code — the caller does,
// so the same engine serves local runs, CI, and tests.
func Run(ctx context.Context, opts Options) (*Result, error) {
	start := time.Now()

	root, err := filepath.Abs(opts.Path)
	if err != nil {
		return nil, err
	}
	cfg, err := policy.Load(root)
	if err != nil {
		return nil, err
	}
	// CLI/config overrides on top of the loaded policy.
	if len(opts.Ecosystems) > 0 {
		cfg.Ecosystems = opts.Ecosystems
	}
	if opts.EPSS {
		cfg.EPSS = true
	}
	if opts.Offline {
		cfg.Offline = true
	}

	scan := model.Scan{
		SchemaVersion: model.SchemaVersion,
		Repo:          filepath.Base(root),
		Components:    []model.Component{},
		Warnings:      []string{},
	}
	if commit := headCommit(root); commit != "" {
		scan.Commit = commit
	}

	// 1. Detect.
	projects, err := detect.Detect(root)
	if err != nil {
		return nil, fmt.Errorf("detecting ecosystems: %w", err)
	}
	if len(projects) == 0 {
		scan.Warnings = append(scan.Warnings,
			"no supported lockfiles found (looked for package-lock.json, poetry.lock, requirements.txt, go.sum)")
	}

	// 2. Resolve. Only projects matching the requested ecosystems are kept.
	allowed := map[string]bool{}
	for _, e := range cfg.Ecosystems {
		allowed[e] = true
	}
	var all []model.Component
	for _, p := range projects {
		if len(allowed) > 0 && !allowed[p.Ecosystem] {
			continue
		}
		r, err := resolve.Get(p.Ecosystem)
		if err != nil {
			scan.Warnings = append(scan.Warnings,
				fmt.Sprintf("no resolver for %s (%s)", p.Ecosystem, p.File))
			continue
		}
		comps, err := r.Resolve(root, p.File)
		if err != nil {
			// One unreadable lockfile shouldn't sink the whole scan; warn and
			// continue with the ecosystems that did parse.
			scan.Warnings = append(scan.Warnings,
				fmt.Sprintf("resolving %s failed: %v", p.File, err))
			continue
		}
		all = append(all, comps...)
	}
	scan.Components = resolve.Dedupe(all)

	// 3. Vulnerability matching (skipped by the SBOM fast path).
	var resultDegraded bool
	if !opts.SkipVuln {
		// attachVulns reports whether vulnerability data was incomplete, so
		// the caller can fail closed rather than reporting a clean result it
		// never actually verified (NFR-3 paired with NFR-6: degrade, but
		// never claim "clean" on data you didn't get).
		degraded, err := attachVulns(ctx, cfg, opts, &scan)
		if err != nil {
			return nil, err
		}
		resultDegraded = degraded
	}

	// 4. Score.
	engine := score.New()
	scan.Summary = engine.Score(scan.Components)
	// 5. SBOM files (after scoring, so the SBOM can carry vuln data).
	paths, err := writeSBOMs(opts, scan)
	if err != nil {
		scan.Warnings = append(scan.Warnings, fmt.Sprintf("writing SBOM: %v", err))
	}

	result := &Result{Scan: scan, SBOMPaths: paths, Degraded: resultDegraded}

	// 6. Drift, if a baseline is available.
	var base model.Scan
	if opts.BaselinePath != "" {
		base, err = drift.Load(opts.BaselinePath)
		if err != nil {
			return nil, fmt.Errorf("loading baseline %s: %w", opts.BaselinePath, err)
		}
		d := drift.Diff(base, scan)
		result.Diff = &d
	}

	// 7. Policy decision.
	result.Decision = policy.Evaluate(cfg, scan, result.Diff, result.Degraded)

	result.Duration = time.Since(start)
	return result, nil
}

// attachVulns queries OSV (and optionally EPSS) and attaches results to the
// scan. It returns true when vulnerability data was incomplete.
//
// The degraded flag is what stops a network outage from reading as "this repo
// is clean": the scan still produces a usable SBOM and report (NFR-3), but
// the policy engine refuses to pass a result it can't vouch for.
func attachVulns(ctx context.Context, cfg *policy.Config, opts Options, scan *model.Scan) (bool, error) {
	if cfg.Offline {
		// NFR-6: offline must fail loudly rather than silently skipping
		// vulnerability checks and reporting a clean bill of health.
		scan.Warnings = append(scan.Warnings,
			"offline mode: vulnerability data comes from cache only; uncached components are unscanned")
	}

	cacheDir := opts.CacheDir
	if cacheDir == "" {
		cacheDir = DefaultCacheDir()
	}
	var cache vuln.Cache = vuln.NewMemoryCache()
	if !opts.DisableCache && !cfg.Offline {
		ttl := opts.CacheTTL
		if ttl == 0 {
			ttl = cfg.CacheTTL()
		}
		fc, err := vuln.NewFileCache(cacheDir, ttl)
		if err == nil {
			cache = fc
		} else {
			scan.Warnings = append(scan.Warnings,
				fmt.Sprintf("cache unavailable at %s, continuing uncached: %v", cacheDir, err))
		}
	}

	// A warning from the vuln client means a source was unreachable or
	// rate-limited; that is by definition an incomplete picture.
	degraded := false
	client := vuln.NewClient(cache)
	client.Offline = cfg.Offline
	client.UseEPSS = cfg.EPSS
	client.Warn = func(msg string) {
		degraded = true
		scan.Warnings = append(scan.Warnings, msg)
	}

	if err := client.QueryOSV(ctx, scan.Components); err != nil {
		return true, err
	}
	return degraded, nil
}

// writeSBOMs serializes the scan into the requested SBOM formats.
func writeSBOMs(opts Options, scan model.Scan) ([]string, error) {
	if len(opts.SBOMFormats) == 0 {
		return nil, nil
	}
	outDir := opts.OutDir
	if outDir == "" {
		outDir = "scram-output"
	}
	var paths []string
	for _, f := range opts.SBOMFormats {
		var format sbom.Format
		switch f {
		case "cyclonedx":
			format = sbom.FormatCycloneDX
		case "spdx":
			format = sbom.FormatSPDX
		default:
			continue
		}
		p, err := sbom.Write(outDir, scan.Repo, format, scan.Components)
		if err != nil {
			return paths, err
		}
		paths = append(paths, p)
	}
	return paths, nil
}

// headCommit returns the current git commit SHA, or "" if not a git repo.
// Used only to stamp the baseline; never fails the scan.
func headCommit(root string) string {
	data, err := os.ReadFile(filepath.Join(root, ".git", "HEAD"))
	if err != nil {
		return ""
	}
	head := trimSpace(string(data))
	if !hasPrefix(head, "ref: ") {
		return head
	}
	// Resolve the ref to a SHA.
	refPath := filepath.Join(root, ".git", head[5:])
	if b, err := os.ReadFile(refPath); err == nil {
		return trimSpace(string(b))
	}
	// Packed refs.
	if b, err := os.ReadFile(filepath.Join(root, ".git", "packed-refs")); err == nil {
		for _, line := range splitLines(string(b)) {
			if hasPrefix(line, "#") || line == "" {
				continue
			}
			parts := splitN(line, " ", 2)
			if len(parts) == 2 && parts[1] == head[5:] {
				return parts[0]
			}
		}
	}
	return ""
}

// Small local helpers to keep this file's import list focused.
func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\n' || s[start] == '\r' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\n' || s[end-1] == '\r' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}

func hasPrefix(s, p string) bool {
	return len(s) >= len(p) && s[:len(p)] == p
}

func splitLines(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == '\n' {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

func splitN(s, sep string, n int) []string {
	var out []string
	rest := s
	for i := 0; i < n-1; i++ {
		idx := indexOf(rest, sep)
		if idx < 0 {
			break
		}
		out = append(out, rest[:idx])
		rest = rest[idx+len(sep):]
	}
	out = append(out, rest)
	return out
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

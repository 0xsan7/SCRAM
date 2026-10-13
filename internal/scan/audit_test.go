package scan

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/0xsan7/scram/internal/scorecard"
	"github.com/0xsan7/scram/internal/vuln"
)

func TestAuditConfiguredCacheTTLReachesClient(t *testing.T) {
	root := npmRepo(t, "4.17.11")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/querybatch" {
			_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"CVE-TTL"}]}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"id":"CVE-TTL","summary":"fixture","severity":[{"type":"CVSS_V3","score":"7.5"}]}`))
	}))
	defer server.Close()
	old := vuln.OSVBaseURL
	vuln.OSVBaseURL = server.URL
	defer func() { vuln.OSVBaseURL = old }()
	dir := t.TempDir()
	if _, err := Run(context.Background(), Options{Path: root, CacheDir: dir, CacheTTL: time.Second}); err != nil {
		t.Fatal(err)
	}
	paths, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil || len(paths) != 1 {
		t.Fatalf("cache paths=%v err=%v", paths, err)
	}
	data, err := os.ReadFile(paths[0])
	if err != nil {
		t.Fatal(err)
	}
	var entry struct {
		Stored  time.Time `json:"stored_at"`
		Expires time.Time `json:"expires_at"`
	}
	if err := json.Unmarshal(data, &entry); err != nil {
		t.Fatal(err)
	}
	if got := entry.Expires.Sub(entry.Stored); got != time.Second {
		t.Fatalf("TTL=%v want 1s", got)
	}
}

func TestAuditPolicyOfflineSkipsScorecard(t *testing.T) {
	root := npmRepo(t, "4.17.21")
	if err := os.WriteFile(filepath.Join(root, ".scram.yml"), []byte("offline: true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests++; w.WriteHeader(404) }))
	defer server.Close()
	client := scorecard.New()
	client.BaseURL = server.URL
	if _, err := Run(context.Background(), Options{Path: root, SkipVuln: true, ScorecardRepo: "owner/repo", ScorecardClient: client}); err != nil {
		t.Fatal(err)
	}
	if requests != 0 {
		t.Fatalf("offline config made %d Scorecard requests", requests)
	}
}

func TestAuditHeadCommitInLinkedWorktree(t *testing.T) {
	root := t.TempDir()
	git := func(args ...string) string {
		t.Helper()
		c := exec.Command("git", args...)
		c.Dir = root
		out, err := c.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
		return string(out)
	}
	git("init")
	git("-c", "user.name=Audit", "-c", "user.email=audit@example.invalid", "commit", "--allow-empty", "-m", "fixture")
	wt := filepath.Join(t.TempDir(), "worktree")
	git("worktree", "add", "--detach", wt, "HEAD")
	defer git("worktree", "remove", "--force", wt)
	if got, want := headCommit(wt), headCommit(root); got == "" || got != want {
		t.Fatalf("worktree commit=%q normal commit=%q", got, want)
	}
}

func TestAuditHeadCommitRejectsArbitraryFileContents(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, head := range []string{"not a commit SHA", "ref: ../secret.txt"} {
		if err := os.WriteFile(filepath.Join(root, ".git", "HEAD"), []byte(head), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "secret.txt"), []byte("do not export unrelated file contents"), 0600); err != nil {
			t.Fatal(err)
		}
		if got := headCommit(root); got != "" {
			t.Fatalf("malformed Git metadata leaked arbitrary contents: %q", got)
		}
	}
}

func TestAuditIgnorePathsExcludesProjectsBeforeParsing(t *testing.T) {
	root := npmRepo(t, "4.17.21")
	nested := filepath.Join(root, "apps", "legacy")
	if err := os.MkdirAll(nested, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nested, "package-lock.json"), []byte("{malformed"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".scram.yml"), []byte("ignore_paths: ['apps/**/package-lock.json']\n"), 0600); err != nil {
		t.Fatal(err)
	}
	result, err := Run(context.Background(), Options{Path: root, SkipVuln: true})
	if err != nil {
		t.Fatal(err)
	}
	if result.Degraded || len(result.Scan.Warnings) > 0 {
		t.Fatalf("ignored project was still parsed: %v", result.Scan.Warnings)
	}
}

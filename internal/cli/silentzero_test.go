package cli

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0xsan7/scram/internal/model"
)

// The silent-zero guard has three layers: resolve refuses to return an empty
// list for a file that declares dependencies, scan propagates that as an error,
// and these tests cover the layer the user actually experiences -- the exit
// code of a command that read nothing.
//
// D01, D22 and D23 all ended in a green build. This file is what stops that.

func writeCLIFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// runCLI executes the root command with args.
//
// The subcommands print with fmt.Printf, which writes to os.Stdout directly
// rather than through the cobra writer, so capturing means swapping the
// process's stdout for a pipe rather than calling SetOut.
func runCLI(t *testing.T, args ...string) (string, error) {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()

	root := rootCmd()
	root.SetArgs(args)
	execErr := root.ExecuteContext(context.Background())

	_ = w.Close()
	os.Stdout = old
	out := <-done
	_ = r.Close()
	return out, execErr
}

func TestCLIExitsNonZeroWhenNothingResolvedAndALockfileFailed(t *testing.T) {
	root := t.TempDir()
	// Detected, found, and unparseable.
	writeCLIFile(t, filepath.Join(root, "package-lock.json"), `{ this is not json`)

	out, err := runCLI(t, "sbom", "generate", root, "--out", filepath.Join(root, "out"))
	if err == nil {
		t.Fatalf("command succeeded having read nothing; a 0-component SBOM from a "+
			"repo with a lockfile is a false negative. Output was:\n%s", out)
	}
	// The message must name the file and say why, so an operator can act.
	if !strings.Contains(err.Error(), "package-lock.json") {
		t.Errorf("error should name the offending file, got: %v", err)
	}
	if !strings.Contains(err.Error(), "false negative") {
		t.Errorf("error should explain the consequence, got: %v", err)
	}
	// A silent-zero is an operational failure, not a policy verdict, so it
	// gets exit 2 and stays distinguishable from "found something" (exit 1).
	if code := ExitCodeFor(err); code != 2 {
		t.Errorf("ExitCodeFor = %d, want 2 (operational failure)", code)
	}
}

func TestCLIExitsZeroForAGenuinelyDependencyFreeProject(t *testing.T) {
	root := t.TempDir()
	// A real project with a real, empty lockfile: ceph's shape.
	writeCLIFile(t, filepath.Join(root, "package-lock.json"),
		`{"name":"ceph","lockfileVersion":3,"requires":true,"packages":{}}`)

	out, err := runCLI(t, "sbom", "generate", root, "--out", filepath.Join(root, "out"))
	if err != nil {
		t.Fatalf("an empty lockfile is a true observation, not a failure: %v\n%s", err, out)
	}
	if !strings.Contains(out, "0 components") {
		t.Errorf("expected an honest 0-component report, got:\n%s", out)
	}
}

func TestCLIExitsZeroWhenComponentsWereResolved(t *testing.T) {
	root := t.TempDir()
	writeCLIFile(t, filepath.Join(root, "requirements.txt"),
		"click >= 1.0\nflask >= 2.0\n")

	out, err := runCLI(t, "sbom", "generate", root, "--out", filepath.Join(root, "out"))
	if err != nil {
		t.Fatalf("a resolvable project must not fail: %v\n%s", err, out)
	}
	if strings.Contains(out, "0 components") {
		t.Errorf("ranged requirements should have resolved, got:\n%s", out)
	}
}

// TestWarnIfNothingResolvedUnit covers the decision table directly, including
// the case that is easiest to get wrong: a scan with warnings that are NOT
// parse failures must not be escalated, or an unrelated advisory would fail
// every scan.
func TestWarnIfNothingResolvedUnit(t *testing.T) {
	empty := model.Scan{}
	empty.Summary.TotalComponents = 0
	empty.Summary.VulnTotal = 0

	// No components, no warnings: a project with genuinely no dependencies.
	if err := warnIfNothingResolved(empty, "."); err != nil {
		t.Errorf("a dependency-free project must not be treated as a failure: %v", err)
	}

	// No components, an unrelated warning: still not a parse failure.
	other := empty
	other.Warnings = []string{"EPSS enrichment failed, exploitability scored as 0"}
	if err := warnIfNothingResolved(other, "."); err != nil {
		t.Errorf("an unrelated warning must not escalate: %v", err)
	}

	// No components, a real parse failure: must fail.
	broken := empty
	broken.Warnings = []string{"resolving package-lock.json failed: invalid character"}
	if err := warnIfNothingResolved(broken, "."); err == nil {
		t.Error("a parse failure with nothing resolved must fail the command")
	}

	// Components resolved despite a warning: fine.
	ok := empty
	ok.Summary.TotalComponents = 12
	ok.Warnings = []string{"resolving other/package-lock.json failed: invalid character"}
	if err := warnIfNothingResolved(ok, "."); err != nil {
		t.Errorf("a partial failure alongside real results must not fail: %v", err)
	}
}

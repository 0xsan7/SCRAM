package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// The check exists because a shell version of it failed on Windows CI
// twice for reasons that had nothing to do with formatting. These tests
// pin the two properties that make it usable there: it must find
// unformatted files, and it must not report the deliberately malformed
// files under testdata/.

func buildChecker(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "gofmtcheck")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building the checker: %v\n%s", err, out)
	}
	return bin
}

func TestCheckerPassesOnTheRealTree(t *testing.T) {
	bin := buildChecker(t)
	// The repository root, so this walks ./cmd and ./internal the way CI
	// does. If it is red here, the tree is unformatted.
	cmd := exec.Command(bin)
	cmd.Dir = repoRoot(t)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("checker failed on the real tree: %v\n%s", err, out)
	}
	if !bytes.Contains(out, []byte("all files formatted")) {
		t.Errorf("output = %q, want a confirmation", out)
	}
}

func TestCheckerReportsAnUnformattedFile(t *testing.T) {
	bin := buildChecker(t)
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.go")
	if err := os.WriteFile(bad, []byte("package x\nfunc  F( ) {\n}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, dir)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("checker passed an unformatted file; output:\n%s", out)
	}
	if !bytes.Contains(out, []byte("bad.go")) {
		t.Errorf("output = %q, want it to name bad.go", out)
	}
}

func TestCheckerPassesOnAFormattedFile(t *testing.T) {
	bin := buildChecker(t)
	dir := t.TempDir()
	good := filepath.Join(dir, "good.go")
	if err := os.WriteFile(good, []byte("package x\n\nfunc F() {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, dir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("checker failed a formatted file: %v\n%s", err, out)
	}
}

// testdata/ holds fuzz crashers promoted from fuzzing and real-world
// lockfile fixtures. Some of those are malformed on purpose: the point of
// promoting a crasher is that it is an input the parser must survive.
// Reporting those as unformatted would make this check permanently red,
// and a permanently red check is a check nobody reads.
func TestCheckerSkipsTestdata(t *testing.T) {
	bin := buildChecker(t)
	dir := t.TempDir()
	td := filepath.Join(dir, "testdata")
	if err := os.MkdirAll(td, 0o755); err != nil {
		t.Fatal(err)
	}
	crash := filepath.Join(td, "crasher.go")
	if err := os.WriteFile(crash, []byte("package x\nfunc  F(  ) {\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, dir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("checker inspected testdata/: %v\n%s", err, out)
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	// The test runs in cmd/gofmtcheck.
	return filepath.Clean(filepath.Join(dir, "..", ".."))
}

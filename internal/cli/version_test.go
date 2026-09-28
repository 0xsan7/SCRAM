package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The linker silently ignores a -X flag whose symbol path does not
// resolve. That is the property this test exists for: `.goreleaser.yml`
// stamped the commit as `main.commit` and the build date as `main.date`,
// neither of which is a symbol in this module, so both flags were
// dropped without a warning and `scram --version` printed a version
// string with no way to identify the exact build behind it.
//
// The check builds a real binary with the same flags the release uses and
// reads the values back out of it. It is the only kind of test that can
// catch this, because a unit test asserting `Commit` equals its default
// passes whether or not the flag works.

const (
	flagVersion = "-X github.com/0xsan7/scram/internal/cli.Version=v9.9.9-test"
	flagCommit  = "-X github.com/0xsan7/scram/internal/cli.Commit=deadbeefcafe"
	flagDate    = "-X github.com/0xsan7/scram/internal/cli.Date=2001-02-03T04:05:06Z"
)

func TestLinkerFlagsActuallyStampTheBinary(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary; skipped in -short")
	}

	dir := t.TempDir()
	bin := dir + "/scram"

	// -buildid= is what the release uses for reproducible builds; without
	// it two builds of the same tree differ and this test would be
	// comparing noise.
	cmd := exec.Command("go", "build",
		"-ldflags", "-s -w "+flagVersion+" "+flagCommit+" "+flagDate+" -buildid=",
		"-o", bin, "github.com/0xsan7/scram/cmd/scram",
	)
	cmd.Dir = repoRoot(t)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building with the release ldflags: %v\n%s", err, out)
	}

	out, err := exec.Command(bin, "--version").CombinedOutput()
	if err != nil {
		t.Fatalf("running --version: %v\n%s", err, out)
	}
	got := string(out)

	for _, want := range []string{"v9.9.9-test", "deadbeefcafe", "2001-02-03T04:05:06Z"} {
		if !strings.Contains(got, want) {
			t.Errorf("--version output does not contain %q\n\ngot:\n%s", want, got)
		}
	}
}

// The negative case. If someone changes .goreleaser.yml back to
// `main.commit`, this test does not change -- but the test above does,
// and its failure message is the point.
func TestVersionOutputIsNotJustTheVersionString(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary; skipped in -short")
	}
	dir := t.TempDir()
	bin := dir + "/scram"
	cmd := exec.Command("go", "build", "-o", bin, "github.com/0xsan7/scram/cmd/scram")
	cmd.Dir = repoRoot(t)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building: %v\n%s", err, out)
	}
	out, err := exec.Command(bin, "--version").CombinedOutput()
	if err != nil {
		t.Fatalf("running --version: %v\n%s", err, out)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) < 3 {
		t.Errorf("--version printed %d line(s), want at least 3 "+
			"(version, commit, date). A build with no commit stamped "+
			"should say so, not print nothing:\n%s", len(lines), out)
	}
	// An unstamped build must say "unknown" rather than leaving the
	// field blank, so a reader can tell "not stamped" from "stamped with
	// an empty value".
	if !strings.Contains(string(out), "unknown") {
		t.Errorf("an unstamped build should report 'unknown' for commit "+
			"and date, got:\n%s", out)
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	// The test runs in internal/cli; the module root is two up.
	return filepath.Clean(filepath.Join(wd, "..", ".."))
}

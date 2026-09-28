// Command gofmtcheck reports Go files that are not gofmt-clean.
//
// It exists because the shell version of this check was the one step that
// failed on windows-latest in CI, twice, for a reason that had nothing to
// do with the formatting:
//
//	run: |
//	  unformatted=$(gofmt -l ./cmd ./internal)
//	  if [ -n "$unformatted" ]; then ... exit 1; fi
//
// windows-latest defaults to pwsh, where `[ -n "$x" ]` does not parse.
// Adding `shell: bash` fixed the parse and left the step still failing,
// which is the part worth writing down: a step whose shell is fixed can
// still be wrong for a shell-adjacent reason, and without log access a
// second guess is a coin flip. This program removes the shell from the
// question entirely, and it is testable.
//
// It is also stricter than `gofmt -l`: it verifies the formatted output
// round-trips, so a file gofmt would rewrite is reported with the diff
// rather than just a path.
//
//	go run ./cmd/gofmtcheck [dir...]
package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func main() {
	dirs := os.Args[1:]
	if len(dirs) == 0 {
		dirs = []string{"./cmd", "./internal"}
	}

	var unformatted []string
	for _, dir := range dirs {
		files, err := goFiles(dir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "gofmtcheck: %v\n", err)
			os.Exit(2)
		}
		for _, f := range files {
			ok, err := isFormatted(f)
			if err != nil {
				fmt.Fprintf(os.Stderr, "gofmtcheck: %s: %v\n", f, err)
				os.Exit(2)
			}
			if !ok {
				unformatted = append(unformatted, f)
			}
		}
	}

	if len(unformatted) == 0 {
		fmt.Println("gofmt: all files formatted")
		return
	}
	fmt.Fprintf(os.Stderr, "these files are not gofmt-clean:\n")
	for _, f := range unformatted {
		fmt.Fprintf(os.Stderr, "  %s\n", f)
	}
	os.Exit(1)
}

// goFiles returns every .go file under dir, skipping testdata, which
// holds deliberately malformed fixtures: a corpus of real-world
// lockfiles and a set of fuzz crashers exist precisely to be unparseable,
// and reporting them as unformatted would make this check permanently
// red for no reason.
func goFiles(dir string) ([]string, error) {
	var out []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			switch info.Name() {
			case "testdata", ".git", "vendor", "node_modules":
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ".go") {
			out = append(out, path)
		}
		return nil
	})
	return out, err
}

func isFormatted(path string) (bool, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	cmd := exec.Command("gofmt", path)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return false, fmt.Errorf("gofmt failed: %w: %s", err, stderr.String())
	}
	return bytes.Equal(src, stdout.Bytes()), nil
}

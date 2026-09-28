// Command yaml2json converts a YAML file to JSON on stdout.
//
// It exists for one caller: scripts/check_action_metadata.py, which needs
// to read action.yml and would otherwise need its own YAML parser. That
// is not a small thing to do correctly -- the first version of the
// checker carried a hand-rolled indentation parser that turned
// `runs.steps` into a mapping instead of a sequence, and consequently
// reported thirteen problems in an action.yml that was entirely correct.
//
// gopkg.in/yaml.v3 is already a dependency of this repository, so this
// adds no new module to go.mod and no new supply-chain surface.
//
//	go build -o bin/yaml2json ./cmd/yaml2json
//	bin/yaml2json action.yml
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: yaml2json <file.yml>")
		os.Exit(2)
	}
	src, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "reading %s: %v\n", os.Args[1], err)
		os.Exit(1)
	}
	var doc any
	if uerr := yaml.Unmarshal(src, &doc); uerr != nil {
		// Errors go to stderr and nothing goes to stdout, so a caller
		// that pipes this into a JSON parser gets a parse error rather
		// than a truncated document that looks valid.
		fmt.Fprintf(os.Stderr, "parsing %s: %v\n", os.Args[1], uerr)
		os.Exit(1)
	}
	// yaml.v3 decodes mappings into map[string]any, which encoding/json
	// handles. It decodes into map[any]any only for non-string keys,
	// which cannot appear in a valid workflow file.
	out, err := json.Marshal(doc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "encoding %s: %v\n", os.Args[1], err)
		os.Exit(1)
	}
	fmt.Println(string(out))
}

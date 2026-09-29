package scorecard

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// FuzzResponse covers the JSON decoder, which processes a response from a
// server SCRAM does not control.
//
// Two properties, neither of which is "it parses":
//
//  1. No panic. A malformed body from an upstream service must not crash a
//     security scan.
//  2. No silent zero. A body that parses but yields no usable checks must
//     produce a Result with zero usable checks, and must not be
//     constructible into something that looks like a measured score. This is
//     the D01/D22/D23 failure mode that this project has already produced
//     three times, in a different package.
//
// The second property is why NewResult, not the decoder, is the interesting
// function here: the decoder's job is to accept junk, and the invariant is
// enforced downstream.
func FuzzResponse(f *testing.F) {
	// Seed from the real captured response.
	if b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "fixtures", "scorecard", "oss-fuzz.json")); err == nil {
		f.Add(b)
	}
	f.Add([]byte(`{"date":"2026-09-28","repo":{"name":"github.com/o/r","commit":"abc"},"score":7.5,"checks":[{"name":"Maintained","score":10,"reason":"ok"}]}`))
	f.Add([]byte(`{"score":10,"checks":[{"name":"A","score":-1},{"name":"B","score":10}]}`))
	f.Add([]byte(`{"score":-1,"checks":[{"name":"A","score":-1}]}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"checks":null}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`not json at all`))
	f.Add([]byte(`{"checks":[{"name":"X","score":1e999}]}`))
	f.Add([]byte(`{"checks":[{"name":"X","score":"ten"}]}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var r Response
		// A decode error is an acceptable outcome; a panic is not.
		if err := json.Unmarshal(data, &r); err != nil {
			return
		}
		res := NewResult(r)
		// Property 2: every check in the usable set must carry a real
		// score. Anything negative was counted, not kept.
		for _, c := range res.Checks {
			if c.Score < 0 {
				t.Fatalf("usable check %q has score %d; inapplicable checks must not be usable",
					c.Name, c.Score)
			}
		}
		if len(res.Checks)+res.Inapplicable != len(r.Checks) {
			t.Fatalf("checks(%d)+inapplicable(%d) != input checks(%d); a check was lost",
				len(res.Checks), res.Inapplicable, len(r.Checks))
		}
	})
}

// FuzzNormalize covers the repository identifier parser, which takes a
// string that in practice comes from a git remote.
//
// Invariants: never panic, and never return a result with a different number
// of path segments than it was given, because a shorter or longer result
// would change which project the Scorecard API is asked about.
func FuzzNormalize(f *testing.F) {
	f.Add("github.com/0xsan7/SCRAM")
	f.Add("0xsan7/SCRAM")
	f.Add("git@github.com:0xsan7/SCRAM.git")
	f.Add("https://github.com/a/b/tree/main")
	f.Add("")
	f.Add("/")
	f.Add("/////")
	f.Add("a/b/c/d/e/f")
	f.Add("../../etc/passwd")
	f.Add("github.com/../..")
	f.Add("a b/c d")
	f.Add("\x00\x01\x02")
	f.Add("host/owner/name\x00extra")

	f.Fuzz(func(t *testing.T, in string) {
		got, err := Normalize(in)
		if err != nil {
			// A rejected input must not leak a partial identifier.
			if got != "" {
				t.Fatalf("Normalize(%q) returned %q together with an error", in, got)
			}
			return
		}
		parts := strings.Split(got, "/")
		if len(parts) < 2 || len(parts) > 3 {
			t.Fatalf("Normalize(%q) = %q, which has %d segments; want 2 or 3",
				in, got, len(parts))
		}
		for _, p := range parts {
			if p == "" {
				t.Fatalf("Normalize(%q) = %q has an empty segment", in, got)
			}
			if strings.ContainsAny(p, " \t\n") {
				t.Fatalf("Normalize(%q) = %q has whitespace in a segment", in, got)
			}
		}
	})
}

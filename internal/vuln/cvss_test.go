package vuln

import "testing"

// TestCVSSBaseFromVector checks the base score against vectors whose
// published scores are independently known, so a regression in the
// implementation is caught rather than re-baselined.
//
// The first three are real advisories with well-known scores:
//   - CVE-2021-44228 (Log4Shell)  -> 10.0
//   - CVE-2014-0160  (Heartbleed) -> 7.5
//   - GHSA-29mw-wpgm-hmr9 (lodash)-> 5.3, the vector OSV actually returns
//
// The rest cover the branches that are easy to get wrong: the scope-changed
// formula, the AC:H penalty, and the scope-changed PR weights.
func TestCVSSBaseFromVector(t *testing.T) {
	cases := []struct {
		name string
		vec  string
		want float64
	}{
		{
			name: "Log4Shell, worst case",
			vec:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
			want: 10.0,
		},
		{
			name: "Heartbleed",
			vec:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
			want: 7.5,
		},
		{
			name: "lodash ReDoS, as returned by OSV",
			vec:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
			want: 5.3,
		},
		{
			name: "network, low complexity, full CIA impact",
			vec:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			want: 9.8,
		},
		{
			// The scope-changed path uses a different impact equation and
			// different PR weights; getting this wrong is easy.
			name: "local, high complexity, privileges required, scope changed",
			vec:  "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:C/C:L/I:L/A:N",
			want: 3.4,
		},
		{
			name: "high attack complexity penalty",
			vec:  "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H",
			want: 7.4,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := cvssBaseFromVector(c.vec); got != c.want {
				t.Errorf("%s\n  got %.1f, want %.1f", c.vec, got, c.want)
			}
		})
	}
}

// TestCVSSBaseFromVectorIncomplete makes sure a malformed or partial vector
// scores 0 rather than a plausible-looking wrong number. A vulnerability with
// an unparseable vector must not be silently treated as low risk.
func TestCVSSBaseFromVectorIncomplete(t *testing.T) {
	bad := []string{
		"",
		"garbage",
		"CVSS:3.1/AV:N", // truncated
		"CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // invalid AV value
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",     // missing A
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", // zero impact
	}
	for _, v := range bad {
		if got := cvssBaseFromVector(v); got != 0 {
			t.Errorf("%q: got %.1f, want 0", v, got)
		}
	}
}

func TestParseCVSSVector(t *testing.T) {
	t.Run("bare number", func(t *testing.T) {
		// Some feeds publish a score with no vector.
		got, vec := parseCVSSVector("7.5")
		if got != 7.5 || vec != "" {
			t.Errorf("got %.1f %q, want 7.5 \"\"", got, vec)
		}
	})

	t.Run("v3 vector", func(t *testing.T) {
		score, vec := parseCVSSVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
		if score != 9.8 {
			t.Errorf("got %.1f, want 9.8", score)
		}
		if vec == "" {
			t.Error("expected the vector string to be returned alongside the score")
		}
	})

	t.Run("v2 vector is not scored as v3", func(t *testing.T) {
		// A v2 vector looks similar but has no "CVSS:3" prefix. Scoring it
		// with v3 weights would produce a confident wrong number.
		if got, _ := parseCVSSVector("AV:N/AC:L/Au:N/C:P/I:P/A:P"); got != 0 {
			t.Errorf("got %.1f, want 0", got)
		}
	})

	t.Run("v4 vector is not scored as v3", func(t *testing.T) {
		// OSV often carries CVSS_V4 alongside CVSS_V3. maxCVSS filters by
		// type, but parseCVSSVector must not misread one either.
		if got, _ := parseCVSSVector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:L"); got != 0 {
			t.Errorf("got %.1f, want 0", got)
		}
	})
}

// TestMaxCVSS verifies the selection rule: highest CVSS v3 across a
// vulnerability's severity list, ignoring v2 and v4 entries.
func TestMaxCVSS(t *testing.T) {
	sevs := []osvSeverity{
		{Type: "CVSS_V2", Score: "AV:N/AC:L/Au:N/C:P/I:P/A:P"},
		{Type: "CVSS_V4", Score: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"},
		{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"}, // 5.3
	}
	score, vec := maxCVSS(sevs)
	if score != 5.3 {
		t.Errorf("got %.1f, want 5.3 (v3 only)", score)
	}
	if vec == "" {
		t.Error("expected the matching vector to be returned")
	}

	// With no v3 entry at all, the score is 0 and must not fall back to v2.
	if s, _ := maxCVSS(sevs[:1]); s != 0 {
		t.Errorf("v2-only: got %.1f, want 0", s)
	}
	if s, _ := maxCVSS(nil); s != 0 {
		t.Errorf("empty: got %.1f, want 0", s)
	}
}

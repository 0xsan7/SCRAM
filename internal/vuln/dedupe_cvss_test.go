package vuln

import (
	"testing"

	"github.com/0xsan7/scram/internal/model"
)

// The CVE-2021-23337 case, from live OSV data rather than a constructed one.
//
// Two GHSA records alias to the same CVE and carry DIFFERENT CVSS vectors:
//
//	GHSA-35jh-r3h4-6jhm  CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H  -> 7.2
//	GHSA-r5fr-rjxr-66jc  CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H  -> 8.1
//
// Both are real, and they are the same underlying issue. OSV's own record
// for CVE-2021-23337 carries the 7.2 vector, matching GHSA-35jh: GitHub
// rescored the issue when its scope model changed, so the older record has
// the higher number.
//
// Before this test, Dedupe merged the group and reported 8.1 -- a severity
// inherited from a sibling record that describes the same bug, not from the
// advisory that was matched. A CVE-2021-23337 finding at 8.1 is not wrong
// in isolation, but it is not what OSV says about GHSA-35jh, and a reader
// comparing against the GitHub advisory sees a discrepancy with no way to
// tell which number is the mistake.
const (
	cve202123337Vector = "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" // 7.2
	cve202123337High   = 7.2
)

func TestDedupeDoesNotInflateCVSSFromASiblingRecord(t *testing.T) {
	vulns := []model.Vuln{
		{
			ID:         "GHSA-35jh-r3h4-6jhm",
			CVSSv3:     7.2,
			CVSSVector: cve202123337Vector,
			Aliases:    []string{"CVE-2021-23337", "GHSA-r5fr-rjxr-66jc"},
			Summary:    "Command Injection in lodash",
		},
		{
			// The same issue, higher score, different vector.
			ID:         "GHSA-r5fr-rjxr-66jc",
			CVSSv3:     8.1,
			CVSSVector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
			Aliases:    []string{"CVE-2021-23337", "GHSA-35jh-r3h4-6jhm"},
		},
	}

	got := Dedupe(vulns)
	if len(got) != 1 {
		t.Fatalf("Dedupe produced %d records, want 1 merged record", len(got))
	}

	// The surviving record must not claim a severity it did not carry.
	if got[0].CVSSv3 > cve202123337High {
		t.Errorf("CVSSv3 = %v, want at most %v: a merged group must not take the "+
			"highest score from a sibling record, because that number describes a "+
			"different scoring of the same issue rather than the matched advisory",
			got[0].CVSSv3, cve202123337High)
	}

	// Whatever score is kept, the vector must be the one that produces it.
	// A score and a vector that disagree is worse than either being absent.
	if got[0].CVSSVector == "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" &&
		got[0].CVSSv3 != 8.1 {
		t.Errorf("vector and score disagree: vector is the 8.1 AC:H/PR:N one but "+
			"CVSSv3 = %v", got[0].CVSSv3)
	}
}

// Every field a record ends up with must come from the same source record.
// A score from one advisory, a vector from another, and a summary from a
// third produces a finding no one can verify against any of them.
func TestDedupeKeepsScoreAndVectorFromTheSameRecord(t *testing.T) {
	vulns := []model.Vuln{
		{ID: "GHSA-a", CVSSv3: 9.8, CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", Aliases: []string{"CVE-1111-1111"}},
		{ID: "GHSA-b", CVSSv3: 5.3, CVSSVector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L", Aliases: []string{"CVE-1111-1111"}},
	}
	got := Dedupe(vulns)
	if len(got) != 1 {
		t.Fatalf("got %d records, want 1", len(got))
	}
	byVector := map[string]float64{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
		"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L": 5.3,
	}
	want, ok := byVector[got[0].CVSSVector]
	if !ok {
		t.Fatalf("CVSSVector = %q, which came from neither input record", got[0].CVSSVector)
	}
	if got[0].CVSSv3 != want {
		t.Errorf("CVSSv3 = %v but CVSSVector %q scores %v: the pair must come "+
			"from the same record", got[0].CVSSv3, got[0].CVSSVector, want)
	}
}

// EPSS is a property of the vulnerability, not of the record that describes
// it, so taking the maximum is correct -- but only among records that
// actually have a value. A 0 must never win over a real score.
func TestDedupeEPSSDoesNotTreatZeroAsBetter(t *testing.T) {
	vulns := []model.Vuln{
		{ID: "GHSA-a", CVSSv3: 5.3, EPSS: 0.21333, Aliases: []string{"CVE-2222-2222"}},
		{ID: "GHSA-b", CVSSv3: 7.2, EPSS: 0, Aliases: []string{"CVE-2222-2222"}},
	}
	got := Dedupe(vulns)
	if len(got) != 1 {
		t.Fatalf("got %d records, want 1", len(got))
	}
	if got[0].EPSS != 0.21333 {
		t.Errorf("EPSS = %v, want 0.21333: an absent or zero score from one "+
			"record must not overwrite a real one from another", got[0].EPSS)
	}
}

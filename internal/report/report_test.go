package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/0xsan7/scram/internal/model"
	"github.com/0xsan7/scram/internal/score"
)

func sampleScan() model.Scan {
	comps := []model.Component{
		{
			Purl: "pkg:npm/lodash@4.17.11", Name: "lodash", Version: "4.17.11",
			Ecosystem: model.EcoNPM, Direct: true, License: "MIT",
			Vulnerabilities: []model.Vuln{
				{ID: "CVE-NEW", CVSSv3: 9.1, EPSS: 0.05, Source: "osv",
					Summary: "Prototype pollution", URL: "https://osv.dev/vulnerability/CVE-NEW"},
				{ID: "CVE-OLD", CVSSv3: 3.1, Source: "osv", Summary: "Minor issue"},
			},
		},
		{Purl: "pkg:npm/clean@1.0.0", Name: "clean", Version: "1.0.0", Ecosystem: model.EcoNPM},
	}
	s := model.Scan{
		SchemaVersion: model.SchemaVersion,
		Repo:          "my-app",
		Commit:        "abc123",
		Components:    comps,
	}
	s.Summary = score.New().Score(comps)
	return s
}

func sampleDiff() *model.DiffResult {
	return &model.DiffResult{
		SchemaVersion: model.SchemaVersion,
		Base:          "my-app@old",
		Head:          "my-app@abc123",
		Summary: model.Summary{
			NewVulnIDs:  []string{"CVE-NEW"},
			NewHigh:     1,
			NewCritical: 1,
		},
		Drifts: []model.Drift{
			{
				Purl: "pkg:npm/lodash@4.17.11", Name: "lodash",
				Change:          model.ChangeVersionChanged,
				PreviousVersion: "4.17.21", NewVersion: "4.17.11",
				NewVulnerabilities: []string{"CVE-NEW"},
				ScoreDelta:         9, ScoreBefore: 27, ScoreAfter: 36,
				Bucket: model.BucketMedium,
			},
		},
	}
}

// TestJSONStdoutIsParseable is the contract that makes `scram scan
// --format json | jq` work. The report writer must emit exactly one JSON
// document and nothing else.
func TestJSONIsValidAndComplete(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, sampleScan(), sampleDiff(), FormatJSON); err != nil {
		t.Fatal(err)
	}

	var doc JSONDocument
	dec := json.NewDecoder(&buf)
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("output does not parse as JSON: %v", err)
	}
	// Nothing may follow the document, or every pipe into jq breaks.
	if dec.More() {
		t.Error("extra content after the JSON document")
	}

	if doc.SchemaVersion != model.SchemaVersion {
		t.Errorf("schema version: got %q, want %q", doc.SchemaVersion, model.SchemaVersion)
	}
	if doc.Scan.Repo != "my-app" {
		t.Errorf("repo: got %q", doc.Scan.Repo)
	}
	if len(doc.Scan.Components) != 2 {
		t.Errorf("components: got %d, want 2", len(doc.Scan.Components))
	}
	if doc.Drift == nil {
		t.Fatal("drift should be present when a diff is supplied")
	}
	if len(doc.Drift.Summary.NewVulnIDs) != 1 {
		t.Errorf("new vuln ids: got %v", doc.Drift.Summary.NewVulnIDs)
	}
}

func TestJSONWithoutDrift(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, sampleScan(), nil, FormatJSON); err != nil {
		t.Fatal(err)
	}
	var doc JSONDocument
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("output does not parse: %v", err)
	}
	if doc.Drift != nil {
		t.Error("drift should be omitted, not null, when no baseline was used")
	}
}

func TestSARIFStructure(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, sampleScan(), sampleDiff(), FormatSARIF); err != nil {
		t.Fatal(err)
	}
	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("SARIF does not parse: %v", err)
	}
	if log.Version != sarifVersion {
		t.Errorf("version: got %q, want %q", log.Version, sarifVersion)
	}
	if !strings.Contains(log.Schema, "sarif-schema-2.1.0.json") {
		t.Errorf("schema: got %q, want the 2.1.0 schema", log.Schema)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("runs: got %d, want 1", len(log.Runs))
	}
	run := log.Runs[0]
	if run.Tool.Driver.Name != "scram" {
		t.Errorf("tool name: got %q", run.Tool.Driver.Name)
	}
	// One result per finding.
	if len(run.Results) != 2 {
		t.Errorf("results: got %d, want 2 (one per vulnerability)", len(run.Results))
	}
	// One rule per distinct vulnerability id.
	if len(run.Tool.Driver.Rules) != 2 {
		t.Errorf("rules: got %d, want 2", len(run.Tool.Driver.Rules))
	}
	// Every result must have a location, or GitHub drops it.
	for _, r := range run.Results {
		if len(r.Locations) == 0 {
			t.Errorf("result %s has no location", r.RuleID)
			continue
		}
		if r.Locations[0].PhysicalLocation.ArtifactLocation.URI == "" {
			t.Errorf("result %s has an empty artifact URI", r.RuleID)
		}
	}
	// Rules must be sorted for a stable, diffable file.
	for i := 1; i < len(run.Tool.Driver.Rules); i++ {
		if run.Tool.Driver.Rules[i-1].ID > run.Tool.Driver.Rules[i].ID {
			t.Error("rules are not sorted by id")
		}
	}
}

func TestSARIFLevelsFromSeverity(t *testing.T) {
	// GitHub renders error/warning/note differently; a 9.1 must be an error.
	cases := []struct {
		bucket string
		level  string
	}{
		{model.BucketCritical, "error"},
		{model.BucketHigh, "error"},
		{model.BucketMedium, "warning"},
		{model.BucketLow, "note"},
		{model.BucketClean, "note"},
	}
	for _, c := range cases {
		if got := sarifLevel(c.bucket); got != c.level {
			t.Errorf("sarifLevel(%q) = %q, want %q", c.bucket, got, c.level)
		}
	}
}

func TestSARIFMarksNewFindings(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, sampleScan(), sampleDiff(), FormatSARIF); err != nil {
		t.Fatal(err)
	}
	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, r := range log.Runs[0].Results {
		if v, ok := r.Properties["scram:newInThisDiff"].(bool); ok && v {
			found[r.RuleID] = true
		}
	}
	if !found["CVE-NEW"] {
		t.Error("CVE-NEW should be flagged as new in this diff")
	}
	if found["CVE-OLD"] {
		t.Error("CVE-OLD is pre-existing and should not be flagged as new")
	}
}

// TestSARIFFingerprintsAreStable matters because GitHub uses them to track a
// finding across commits. A fingerprint that changes every run makes every
// finding look brand new on every push.
func TestSARIFFingerprintsAreStable(t *testing.T) {
	render := func() []byte {
		var buf bytes.Buffer
		if err := Write(&buf, sampleScan(), sampleDiff(), FormatSARIF); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}
	a, b := render(), render()
	var la, lb sarifLog
	if err := json.Unmarshal(a, &la); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &lb); err != nil {
		t.Fatal(err)
	}
	for i := range la.Runs[0].Results {
		x := la.Runs[0].Results[i].PartialFingerprints
		y := lb.Runs[0].Results[i].PartialFingerprints
		if x["scramComponentPurl/v1"] != y["scramComponentPurl/v1"] {
			t.Error("component fingerprint changed between identical runs")
		}
		if x["scramVulnId/v1"] != y["scramVulnId/v1"] {
			t.Error("vuln fingerprint changed between identical runs")
		}
	}
}

// TestSARIFDegradedScanIsNotSuccessful guards against a partial scan being
// uploaded as if it were complete.
func TestSARIFDegradedScanIsNotSuccessful(t *testing.T) {
	s := sampleScan()
	s.Warnings = []string{"OSV query failed: connection refused"}
	var buf bytes.Buffer
	if err := Write(&buf, s, nil, FormatSARIF); err != nil {
		t.Fatal(err)
	}
	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	inv := log.Runs[0].Invocations
	if len(inv) == 0 {
		t.Fatal("no invocation recorded")
	}
	if inv[0].ExecutionSuccessful {
		t.Error("a degraded scan must not report executionSuccessful: true")
	}
	if len(inv[0].ToolExecutionNotifications) == 0 {
		t.Error("the warning should be carried into the SARIF file")
	}
}

func TestSecuritySeverityFormat(t *testing.T) {
	cases := map[float64]string{
		0:    "0.0",
		9.8:  "9.8",
		7.5:  "7.5",
		10.0: "10.0",
		5.0:  "5.0",
	}
	for in, want := range cases {
		if got := securitySeverity(in); got != want {
			t.Errorf("securitySeverity(%.1f) = %q, want %q", in, got, want)
		}
	}
}

func TestTableOutput(t *testing.T) {
	NoColor = true
	defer func() { NoColor = false }()

	var buf bytes.Buffer
	if err := Write(&buf, sampleScan(), sampleDiff(), FormatTable); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"my-app",                 // repo
		"pkg:npm/lodash@4.17.11", // the flagged component
		"CVE-NEW",                // the finding
		"9.1",                    // its CVSS
		"Drift since baseline",   // the drift section
		"version-changed",        // the change type
	} {
		if !strings.Contains(out, want) {
			t.Errorf("table output missing %q:\n%s", want, out)
		}
	}
	// No ANSI escapes when colors are off.
	if strings.Contains(out, "\033[") {
		t.Error("table output contains ANSI escapes with NoColor set")
	}
}

func TestTableEmptyResult(t *testing.T) {
	NoColor = true
	defer func() { NoColor = false }()

	comps := []model.Component{
		{Purl: "pkg:npm/clean@1.0.0", Name: "clean", Version: "1.0.0", Ecosystem: model.EcoNPM},
	}
	s := model.Scan{SchemaVersion: model.SchemaVersion, Repo: "app", Components: comps}
	s.Summary = score.New().Score(comps)

	var buf bytes.Buffer
	if err := Write(&buf, s, nil, FormatTable); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "No known vulnerabilities") {
		t.Errorf("expected an explicit no-findings message:\n%s", buf.String())
	}
}

func TestUnknownFormatIsAnError(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, sampleScan(), nil, Format("xml")); err == nil {
		t.Error("expected an error for an unknown format")
	}
}

func TestExplainOutput(t *testing.T) {
	c := model.Component{
		Purl: "pkg:npm/x@1.0.0", Name: "x", Version: "1.0.0",
		Vulnerabilities: []model.Vuln{{ID: "CVE-1", CVSSv3: 7.5}},
	}
	c.Score = &model.Score{Total: 30, Severity: 30}
	c.Bucket = model.BucketLow
	var buf bytes.Buffer
	if err := Explain(&buf, c, score.MaintenanceProvenance{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "pkg:npm/x@1.0.0") {
		t.Error("explain output missing the purl")
	}
	if !strings.Contains(buf.String(), "CVE-1") {
		t.Error("explain output missing the finding")
	}
}

// TestTheReportStatesItsOwnDenominator is the JSON half of the /65 rescale.
//
// repo_score is a PRESENTED score out of 65, and in JSON it is a bare
// integer. A consumer written against schema 1.0.0 parses it successfully and
// renders "25/100", which is wrong by 35%, with nothing in the document to
// contradict it. The document therefore carries the denominator itself, so the
// scale is a fact in the data rather than something the reader has to know.
func TestTheReportStatesItsOwnDenominator(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, sampleScan(), sampleDiff(), FormatJSON); err != nil {
		t.Fatal(err)
	}
	var doc JSONDocument
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}

	got := doc.Scan.Summary.RepoScoreMax
	if got != model.PresentedMax {
		t.Errorf("summary.repo_score_max = %d, want %d. Without it a consumer "+
			"cannot tell what repo_score is out of, and a 1.0.0 consumer will "+
			"assume 100 and be wrong by 35%%.", got, model.PresentedMax)
	}
	if got != 0 && doc.Scan.Summary.RepoScore > got {
		t.Errorf("repo_score %d exceeds its own stated maximum %d",
			doc.Scan.Summary.RepoScore, got)
	}
	// A MAJOR bump, because the field NAMES did not change -- which is
	// exactly what makes an old consumer wrong without erroring.
	if doc.SchemaVersion == "1.0.0" {
		t.Error("schema_version is still 1.0.0, but repo_score changed meaning " +
			"silently. That is a breaking change and needs a major bump.")
	}
	t.Logf("repo_score=%d of repo_score_max=%d, schema %s",
		doc.Scan.Summary.RepoScore, got, doc.SchemaVersion)
}

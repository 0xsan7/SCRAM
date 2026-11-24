package resolve

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNpmV1WarningDescribesActualFlags(t *testing.T) {
	dir := filepath.Join("..", "..", "testdata", "fixtures", "npm", "real", "less-less@3.13.0")
	data, err := os.ReadFile(filepath.Join(dir, "package-lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	var lock struct {
		Dependencies map[string]struct {
			Dev bool `json:"dev"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		t.Fatal(err)
	}
	hasDev := false
	for _, dependency := range lock.Dependencies {
		hasDev = hasDev || dependency.Dev
	}
	if !hasDev {
		t.Fatal("test fixture must demonstrate real npm v1 development flags")
	}
	warnings := WarningsFor(npmResolver{}, dir, "package-lock.json")
	if len(warnings) != 1 {
		t.Fatalf("want one warning, got %v", warnings)
	}
	for _, falseClaim := range []string{"records no", "for accurate flags", "covered by"} {
		if strings.Contains(warnings[0], falseClaim) {
			t.Errorf("warning makes an unsupported claim %q: %s", falseClaim, warnings[0])
		}
	}
	if !strings.Contains(warnings[0], "does not expose") {
		t.Errorf("warning must identify SCRAM's missing classification: %s", warnings[0])
	}
}

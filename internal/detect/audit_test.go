package detect

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAuditNestedProjectKeepsFullRelativePath(t *testing.T) {
	root := t.TempDir()
	mk(t, root, "apps/web/package-lock.json", "services/web/package-lock.json")
	projects, err := Detect(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(projects) != 2 {
		t.Fatalf("projects=%+v", projects)
	}
	for _, p := range projects {
		if _, err := os.Stat(filepath.Join(root, p.File)); err != nil {
			t.Errorf("detected nonexistent path %q: %v", p.File, err)
		}
	}
	if projects[0].File == projects[1].File {
		t.Fatalf("different subprojects collapsed to %q", projects[0].File)
	}
}

func TestAuditDetectorRejectsAFileAsRoot(t *testing.T) {
	root := t.TempDir()
	mk(t, root, "package-lock.json")
	if _, err := Detect(filepath.Join(root, "package-lock.json")); err == nil {
		t.Fatal("file was accepted as a repository directory")
	}
}

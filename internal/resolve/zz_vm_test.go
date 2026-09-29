package resolve

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVersionMatrix(t *testing.T) {
	dir := "/Users/santiagojerald/.hermes/cache/scratch/lockresearch/raw"
	files, _ := filepath.Glob(dir + "/*")
	for _, f := range files {
		if !strings.HasSuffix(f, ".lock") {
			continue
		}
		comps, err := pnpmResolver{}.Resolve(filepath.Dir(f), filepath.Base(f))
		ver := "?"
		b, _ := os.ReadFile(f)
		for _, l := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(strings.TrimSpace(l), "lockfileVersion:") {
				ver = strings.TrimSpace(l)
				break
			}
		}
		fmt.Printf("  %-34s %-24s comps=%-6d err=%v\n", filepath.Base(f), ver, len(comps), err)
	}
}

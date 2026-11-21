package resolve

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"maps"
	"strings"
	"testing"
)

func TestLockfileIntegrityKeepsAlgorithm(t *testing.T) {
	sum := sha256.Sum256([]byte("package contents"))
	sri := "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
	want := hex.EncodeToString(sum[:])
	for _, tc := range []struct {
		name string
		r    Resolver
		lock string
	}{
		{"package-lock.json", npmResolver{}, `{"lockfileVersion":1,"dependencies":{"item":{"version":"1.0.0","integrity":"%s"}}}`},
		{"package-lock.json", npmResolver{}, `{"lockfileVersion":3,"packages":{"node_modules/item":{"version":"1.0.0","integrity":"%s"}}}`},
		{"yarn.lock", yarnResolver{}, "item@^1.0.0:\n  version \"1.0.0\"\n  integrity %s\n"},
		{"pnpm-lock.yaml", pnpmResolver{}, "lockfileVersion: '9.0'\npackages:\n  item@1.0.0:\n    resolution: {integrity: %s}\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := writeFixture(t, map[string]string{tc.name: fmt.Sprintf(tc.lock, sri)})
			components, err := tc.r.Resolve(root, tc.name)
			if err != nil || len(components) != 1 {
				t.Fatalf("components=%v err=%v", components, err)
			}
			if got := components[0].Hashes; len(got) != 1 || got["SHA-256"] != want {
				t.Fatalf("hashes=%v, want SHA-256 %s", got, want)
			}
		})
	}
}

func TestGoSumPreservesModuleHash(t *testing.T) {
	const digest = "h1:iURUrlRGxPUNPdy5z7M4E+77sj2Kpf79I2/F/q4rR7U="
	root := writeFixture(t, map[string]string{"go.sum": "github.com/pkg/errors v0.9.1 " + digest + "\n"})
	cs, err := (goResolver{}).Resolve(root, "go.sum")
	if err != nil || len(cs) != 1 {
		t.Fatalf("components=%v err=%v", cs, err)
	}
	if got := cs[0].Hashes["SHA-256"]; got != digest {
		t.Fatalf("got %q, want original %q", got, digest)
	}
}

func TestIntegritySkipsMalformedTokensAndKeepsDistinctAlgorithms(t *testing.T) {
	want := map[string]string{}
	input := "sha1-YWJj unknown-YWJj"
	for algorithm, size := range map[string]int{"1": 20, "256": 32, "384": 48, "512": 64} {
		raw := bytes.Repeat([]byte{0xab}, size)
		want["SHA-"+algorithm] = hex.EncodeToString(raw)
		input += "\tsha" + algorithm + "-" + base64.StdEncoding.EncodeToString(raw)
	}
	if got := integrityMap(input); !maps.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestGoSumRejectsUnprefixedHashAsPackageChecksum(t *testing.T) {
	root := writeFixture(t, map[string]string{"go.sum": "example.org/item v1.0.0 " + strings.Repeat("a", 64) + "\n"})
	cs, err := (goResolver{}).Resolve(root, "go.sum")
	if err != nil || len(cs) != 1 {
		t.Fatalf("components=%v err=%v", cs, err)
	}
	if len(cs[0].Hashes) != 0 {
		t.Fatalf("unexpected package checksum %v", cs[0].Hashes)
	}
}

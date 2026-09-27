package vuln

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMemoryCacheRoundTrip(t *testing.T) {
	c := NewMemoryCache()
	if _, ok := c.Get("missing"); ok {
		t.Error("a miss should report false")
	}
	c.Set("k", []byte("v"), time.Hour)
	got, ok := c.Get("k")
	if !ok || string(got) != "v" {
		t.Errorf("got (%q, %v), want (\"v\", true)", got, ok)
	}
}

func TestMemoryCacheExpiry(t *testing.T) {
	c := NewMemoryCache()
	c.Set("k", []byte("v"), -time.Hour) // already expired
	if _, ok := c.Get("k"); ok {
		t.Error("an expired entry must not be returned")
	}
}

func TestFileCacheRoundTrip(t *testing.T) {
	dir := t.TempDir()
	c, err := NewFileCache(dir, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := c.Get("absent"); ok {
		t.Error("a miss should report false")
	}
	c.Set("key1", []byte(`{"x":1}`), time.Hour)
	got, ok := c.Get("key1")
	if !ok {
		t.Fatal("expected a hit")
	}
	if string(got) != `{"x":1}` {
		t.Errorf("payload: got %q", got)
	}
	// The entry must be a file on disk so the cache survives across runs.
	if _, err := os.Stat(filepath.Join(dir, "key1.json")); err != nil {
		t.Errorf("expected an on-disk entry: %v", err)
	}
}

func TestFileCacheExpiry(t *testing.T) {
	dir := t.TempDir()
	c, err := NewFileCache(dir, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	c.Set("stale", []byte("v"), -time.Minute)
	if _, ok := c.Get("stale"); ok {
		t.Error("an expired entry must not be returned")
	}
	// An expired entry is deleted rather than left to accumulate.
	if _, err := os.Stat(filepath.Join(dir, "stale.json")); !os.IsNotExist(err) {
		t.Error("an expired entry should be removed from disk")
	}
}

// TestFileCacheDiscardsCorruptEntry covers a truncated write or a partial
// file: the cost is one wasted query, the alternative is a permanently
// broken scan.
func TestFileCacheDiscardsCorruptEntry(t *testing.T) {
	dir := t.TempDir()
	c, err := NewFileCache(dir, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "corrupt.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.Get("corrupt"); ok {
		t.Error("a corrupt entry must not be returned as a hit")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("a corrupt entry should be deleted")
	}
}

func TestFileCacheLeavesNoTempFiles(t *testing.T) {
	// Writes go to a temp file and are renamed into place, so a crashed run
	// cannot leave a half-written entry that reads as corrupt.
	dir := t.TempDir()
	c, err := NewFileCache(dir, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	c.Set("k", []byte("v"), time.Hour)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Errorf("left a temp file behind: %s", e.Name())
		}
	}
}

func TestCacheKeyIsStableAndDistinct(t *testing.T) {
	a := CacheKey("pkg:npm/lodash@4.17.11", "npm", "4.17.11")
	b := CacheKey("pkg:npm/lodash@4.17.11", "npm", "4.17.11")
	if a != b {
		t.Error("the same input must produce the same key, or the cache never hits")
	}
	if a == CacheKey("pkg:npm/lodash@4.17.21", "npm", "4.17.21") {
		t.Error("different versions must produce different keys")
	}
	if a == CacheKey("pkg:pypi/lodash@4.17.11", "pypi", "4.17.11") {
		t.Error("different ecosystems must produce different keys")
	}
}

func TestDefaultCacheTTLIsSixHours(t *testing.T) {
	// FR-204 specifies a 6h default: long enough to avoid re-querying within
	// a workday, short enough that a new advisory shows up the same day.
	if DefaultCacheTTL != 6*time.Hour {
		t.Errorf("got %v, want 6h", DefaultCacheTTL)
	}
}

func TestNewFileCacheDefaultsTTL(t *testing.T) {
	c, err := NewFileCache(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if c.TTL != DefaultCacheTTL {
		t.Errorf("got %v, want the %v default", c.TTL, DefaultCacheTTL)
	}
}

// TestFlexFloat64Unmarshal covers the EPSS API returning numbers as JSON
// strings. Decoding them into float64 directly failed on every response,
// which silently zeroed out all exploitability scores.
func TestFlexFloat64Unmarshal(t *testing.T) {
	cases := []struct {
		in   string
		want float64
	}{
		{`"0.073360000"`, 0.07336},
		{`0.5`, 0.5},
		{`"1"`, 1.0},
		{`""`, 0},
		{`null`, 0},
		{`"0"`, 0},
	}
	for _, c := range cases {
		var got flexFloat64
		if err := got.UnmarshalJSON([]byte(c.in)); err != nil {
			t.Errorf("UnmarshalJSON(%s): %v", c.in, err)
			continue
		}
		if float64(got) != c.want {
			t.Errorf("UnmarshalJSON(%s) = %v, want %v", c.in, float64(got), c.want)
		}
	}
	var bad flexFloat64
	if err := bad.UnmarshalJSON([]byte(`"not a number"`)); err == nil {
		t.Error("expected an error for a non-numeric string")
	}
}

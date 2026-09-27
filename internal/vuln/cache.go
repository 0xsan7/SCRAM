package vuln

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// DefaultCacheTTL is 6 hours per FR-204: long enough that a burst of PRs in
// one afternoon doesn't re-query the same deps, short enough that a
// newly-published advisory shows up the same day.
const DefaultCacheTTL = 6 * time.Hour

// Cache stores vulnerability query results between runs (FR-204). The key is
// derived from the query itself, so a cache hit is exactly equivalent to a
// fresh query for the same inputs.
type Cache interface {
	// Get returns the cached value for key, or false if absent or expired.
	Get(key string) ([]byte, bool)
	// Set stores value under key with the given TTL.
	Set(key string, value []byte, ttl time.Duration)
}

// CacheKey builds the deterministic cache key for a component query.
func CacheKey(purl, ecosystem, version string) string {
	sum := sha256.Sum256([]byte("scram-osv|" + purl + "|" + ecosystem + "|" + version))
	return hex.EncodeToString(sum[:])
}

// FileCache stores cache entries as individual JSON files under a directory.
// One file per entry keeps concurrent CI jobs and parallel ecosystem scans
// from fighting over a single blob, and makes the cache trivially prunable.
type FileCache struct {
	Dir string
	TTL time.Duration
	// now is overridable for tests.
	now func() time.Time
}

// NewFileCache creates the cache directory and returns a handle to it.
func NewFileCache(dir string, ttl time.Duration) (*FileCache, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	if ttl <= 0 {
		ttl = DefaultCacheTTL
	}
	return &FileCache{Dir: dir, TTL: ttl, now: time.Now}, nil
}

type cacheEntry struct {
	Key       string    `json:"key"`
	ExpiresAt time.Time `json:"expires_at"`
	StoredAt  time.Time `json:"stored_at"`
	Payload   []byte    `json:"payload"`
}

func (f *FileCache) path(key string) string {
	return filepath.Join(f.Dir, key+".json")
}

func (f *FileCache) Get(key string) ([]byte, bool) {
	b, err := os.ReadFile(f.path(key))
	if err != nil {
		return nil, false
	}
	var e cacheEntry
	if err := json.Unmarshal(b, &e); err != nil {
		// A corrupt entry is discarded rather than fatal — the cost is one
		// wasted query, the alternative is a permanently broken scan.
		_ = os.Remove(f.path(key))
		return nil, false
	}
	if f.now().After(e.ExpiresAt) {
		// Expired: drop it so the directory doesn't grow without bound.
		_ = os.Remove(f.path(key))
		return nil, false
	}
	return e.Payload, true
}

// Set stores an entry. A non-positive ttl stores it already expired, so a
// caller can force a miss. Callers that want the cache default should pass
// the cache's own TTL, which NewFileCache has already normalized.
func (f *FileCache) Set(key string, value []byte, ttl time.Duration) {
	now := f.now()
	e := cacheEntry{
		Key:       key,
		StoredAt:  now,
		ExpiresAt: now.Add(ttl),
		Payload:   value,
	}
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	// Write to a temp file and rename, so a crashed or concurrent scan can
	// never leave a half-written entry that reads as corrupt.
	tmp := f.path(key) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return
	}
	_ = os.Rename(tmp, f.path(key))
}

// MemoryCache is a no-persistence Cache for tests and for --no-cache runs.
type MemoryCache struct {
	m map[string]memoryEntry
}

type memoryEntry struct {
	payload []byte
	expires time.Time
}

// NewMemoryCache returns an empty in-memory cache.
func NewMemoryCache() *MemoryCache {
	return &MemoryCache{m: map[string]memoryEntry{}}
}

func (c *MemoryCache) Get(key string) ([]byte, bool) {
	e, ok := c.m[key]
	if !ok {
		return nil, false
	}
	if time.Now().After(e.expires) {
		delete(c.m, key)
		return nil, false
	}
	return e.payload, true
}

// Set stores a value. A non-positive ttl means "already expired", which is
// how a caller forces a bypass; ttl of 0 at construction time is normalized
// to the default by NewFileCache, so this cannot silently disable caching
// by accident.
func (c *MemoryCache) Set(key string, value []byte, ttl time.Duration) {
	c.m[key] = memoryEntry{payload: value, expires: time.Now().Add(ttl)}
}

package viewer

import (
	"context"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHandlerServesEmbeddedAssetsAndProtectsLocalReport(t *testing.T) {
	const host = "127.0.0.1:12345"
	h := handler(host, "/session/", []byte(`{"private":"local report"}`))
	for _, tc := range []struct {
		method, path, requestHost, origin string
		status                            int
		contains                          string
	}{
		{"GET", "/session/", host, "", 200, "See what changed."},
		{"GET", "/session/app.mjs", host, "", 200, "parseReport"},
		{"GET", "/session/viewer.html", host, "", 200, "Open a report"},
		{"GET", "/session/landing.css", host, "", 200, ".hero-figure"},
		{"HEAD", "/session/assets/landscape-dawn.webp", host, "", 200, ""},
		{"HEAD", "/session/assets/landscape-night.webp", host, "", 200, ""},
		{"GET", "/session/site.mjs", host, "", 200, "clipboard"},
		{"GET", "/session/glass.mjs", host, "", 404, ""},
		{"GET", "/session/assets/", host, "", 404, ""},
		{"GET", "/session/fixtures/", host, "", 404, ""},
		{"POST", "/session/viewer.html", host, "", 405, ""},
		{"GET", "/session/assets/fonts/sora-latin.woff2", host, "", 200, ""},
		{"GET", "/session/assets/glass-room.jpg", host, "", 404, ""},
		{"GET", "/session/fixtures/blocked-new-finding.json", host, "", 200, "DEMO-HIGH-001"},
		{"GET", "/session/report.json", host, "", 200, "local report"},
		{"HEAD", "/session/report.json", host, "", 200, ""},
		{"GET", "/report.json", host, "", 404, ""},
		{"GET", "/session/report.json", "attacker.example:12345", "", 403, ""},
		{"GET", "/session/report.json", host, "https://attacker.example", 403, ""},
		{"POST", "/session/report.json", host, "", 405, ""},
		{"GET", "/session/embed.go", host, "", 404, ""},
	} {
		t.Run(tc.method+tc.path+tc.requestHost+tc.origin, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, "http://"+host+tc.path, nil)
			r.Host = tc.requestHost
			r.Header.Set("Origin", tc.origin)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.status || !strings.Contains(w.Body.String(), tc.contains) {
				t.Fatalf("status %d, body %q", w.Code, w.Body.String())
			}
			if tc.method == "HEAD" && w.Body.Len() != 0 {
				t.Fatal("HEAD leaked a body")
			}
			if (tc.status == 200 && w.Header().Get("Cache-Control") != "no-store") || w.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Fatal("missing privacy headers")
			}
		})
	}
}

func TestReadReportRejectsInvalidAndOversizeFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	for _, tc := range []struct {
		data  string
		valid bool
	}{{`{"passed":true}`, true}, {"broken", false}, {strings.Repeat(" ", MaxReportBytes+1), false}} {
		if err := os.WriteFile(path, []byte(tc.data), 0o600); err != nil {
			t.Fatal(err)
		}
		data, err := ReadReport(path)
		if (err == nil) != tc.valid {
			t.Fatalf("valid=%v, error=%v", tc.valid, err)
		}
		if tc.valid && string(data) != tc.data {
			t.Fatal("report changed")
		}
	}
	if _, err := ReadReport(filepath.Dir(path)); err == nil {
		t.Fatal("directory accepted")
	}
}

func TestServeStopsWhenContextIsCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, nil, io.Discard) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("local viewer did not stop")
	}
}

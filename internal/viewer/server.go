// Package viewer serves an embedded, read-only report viewer on loopback.
package viewer

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	viewerexamples "github.com/0xsan7/scram/examples/report-viewer"
	viewerassets "github.com/0xsan7/scram/web"
)

const MaxReportBytes = 5 * 1024 * 1024

// ReadReport limits input before allocating the full file. Semantic validation
// remains in the browser's shared parser, also used for file-picker imports.
func ReadReport(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open report: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("report must be a regular JSON file")
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxReportBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxReportBytes {
		return nil, errors.New("report exceeds the viewer's 5 MiB limit")
	}
	if !json.Valid(data) {
		return nil, errors.New("report is not valid JSON")
	}
	return data, nil
}

func handler(host, prefix string, report []byte) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/fixtures/", http.FileServer(http.FS(viewerexamples.Files)))
	mux.HandleFunc("/report.json", func(w http.ResponseWriter, r *http.Request) {
		if report == nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		if r.Method != http.MethodHead {
			_, _ = w.Write(report)
		}
	})
	mux.Handle("/", http.FileServer(http.FS(viewerassets.Files)))
	files := http.StripPrefix(strings.TrimSuffix(prefix, "/"), mux)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
		if r.Host != host || (r.Header.Get("Origin") != "" && r.Header.Get("Origin") != "http://"+host) {
			http.Error(w, "This viewer only accepts its own local address.", http.StatusForbidden)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "Read-only viewer", http.StatusMethodNotAllowed)
			return
		}
		if !strings.HasPrefix(r.URL.Path, prefix) ||
			(r.URL.Path != prefix && strings.HasSuffix(r.URL.Path, "/")) {
			http.NotFound(w, r)
			return
		}
		files.ServeHTTP(w, r)
	})
}

// Serve binds only to IPv4 loopback. A random path keeps the report out of
// predictable localhost endpoints; it exposes no filesystem browsing or upload.
func Serve(ctx context.Context, report []byte, output io.Writer) error {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	prefix := "/" + hex.EncodeToString(nonce[:]) + "/"
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("start local viewer: %w", err)
	}
	defer listener.Close()
	address := listener.Addr().String()
	url := "http://" + address + prefix
	if report != nil {
		url += "viewer.html?local=1"
	}
	server := &http.Server{Handler: handler(address, prefix, report), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_ = server.Shutdown(shutdown)
		case <-done:
		}
	}()
	fmt.Fprintf(output, "Open SCRAM in your browser:\n%s\n\nLocal, read-only viewer. Press Ctrl+C to stop.\n", url)
	err = server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

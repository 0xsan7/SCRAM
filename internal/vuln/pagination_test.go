package vuln

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/0xsan7/scram/internal/model"
)

func TestOSVPaginatesOnlyPendingQueries(t *testing.T) {
	comps := []model.Component{
		{Name: "one", Version: "1", Ecosystem: model.EcoNPM},
		{Name: "two", Version: "2", Ecosystem: model.EcoNPM},
		{Name: "three", Version: "3", Ecosystem: model.EcoNPM},
	}
	calls := 0
	client := paginationClient(t, func(w http.ResponseWriter, r *http.Request, queries []osvQuery) {
		calls++
		switch calls {
		case 1:
			fmt.Fprint(w, `{"results":[{"vulns":[{"id":"TEST-FIRST"}],"next_page_token":"one-more"},{},{"next_page_token":"three-more"}]}`)
		case 2:
			if len(queries) != 2 || queries[0].Package.Name != "one" || queries[0].PageToken != "one-more" ||
				queries[1].Package.Name != "three" || queries[1].PageToken != "three-more" || queries[1].Version != "3" {
				t.Errorf("continuations lost their component association: %+v", queries)
			}
			fmt.Fprint(w, `{"results":[{"vulns":[{"id":"TEST-SECOND"}]},{"vulns":[{"id":"TEST-THIRD"}]}]}`)
		default:
			t.Errorf("extra batch: %+v", queries)
			http.Error(w, "unexpected", http.StatusBadRequest)
		}
	})
	client.Warn = func(warning string) { t.Error(warning) }
	got, err := client.QueryOSV(context.Background(), comps)
	if err != nil || got != (model.OSVCoverage{Checked: 3}) || calls != 2 {
		t.Fatalf("coverage=%+v calls=%d err=%v", got, calls, err)
	}
	if first, second, third := comps[0].Vulnerabilities, comps[1].Vulnerabilities, comps[2].Vulnerabilities; len(first) != 2 ||
		first[0].ID != "TEST-FIRST" || first[1].ID != "TEST-SECOND" || len(second) != 0 || len(third) != 1 || third[0].ID != "TEST-THIRD" {
		t.Fatalf("wrong findings: %+v %+v %+v", first, second, third)
	}
}

func TestOSVRetainsSuccessfulAndPartialBatches(t *testing.T) {
	comps := make([]model.Component, 2*OSVBatch+2)
	for i := range comps {
		comps[i] = model.Component{Name: fmt.Sprint(i), Version: "1", Ecosystem: model.EcoNPM}
	}
	comps[len(comps)-1].Version = ""
	warnings := 0
	client := paginationClient(t, func(w http.ResponseWriter, r *http.Request, queries []osvQuery) {
		results := make([]osvResult, len(queries))
		switch queries[0].Package.Name {
		case "0":
			if queries[0].PageToken != "" {
				http.Error(w, "continuation unavailable", http.StatusServiceUnavailable)
				return
			}
			results[0] = osvResult{NextPageToken: "more", Vulns: []osvVuln{{ID: "TEST-PARTIAL"}}}
		case fmt.Sprint(OSVBatch):
			http.Error(w, "batch unavailable", http.StatusServiceUnavailable)
			return
		case fmt.Sprint(2 * OSVBatch):
			results[0].Vulns = []osvVuln{{ID: "TEST-LATER"}}
		default:
			t.Errorf("unexpected query %+v", queries[0])
		}
		if err := json.NewEncoder(w).Encode(map[string]any{"results": results}); err != nil {
			t.Error(err)
		}
	})
	client.Warn = func(string) { warnings++ }
	got, err := client.QueryOSV(context.Background(), comps)
	if err != nil || got != (model.OSVCoverage{Checked: OSVBatch, Partial: 1, Unchecked: OSVBatch + 1}) || warnings != 3 {
		t.Fatalf("coverage=%+v warnings=%d err=%v", got, warnings, err)
	}
	if first, last := comps[0].Vulnerabilities, comps[2*OSVBatch].Vulnerabilities; len(first) != 1 ||
		first[0].ID != "TEST-PARTIAL" || len(last) != 1 || last[0].ID != "TEST-LATER" {
		t.Fatalf("findings lost: first=%+v later=%+v", first, last)
	}
}

func TestOSVBoundsContinuationAndHonorsCancellation(t *testing.T) {
	for _, scenario := range []struct {
		name string
		want int
	}{
		{"repeated", 2}, {"unique", maxOSVPages}, {"canceled", 1},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := make(chan int, maxOSVPages+1)
			client := paginationClient(t, func(w http.ResponseWriter, r *http.Request, queries []osvQuery) {
				calls <- 1
				token := "same"
				if scenario.name == "unique" {
					token = fmt.Sprint(len(calls))
				}
				if scenario.name == "canceled" {
					cancel()
				}
				fmt.Fprintf(w, `{"results":[{"next_page_token":%q}]}`, token)
			})
			var warning string
			client.Warn = func(msg string) { warning = msg }
			got, err := client.QueryOSV(ctx, []model.Component{{Name: "one", Version: "1", Ecosystem: model.EcoNPM}})
			if len(calls) != scenario.want {
				t.Fatalf("batch calls=%d want %d", len(calls), scenario.want)
			}
			if scenario.name == "canceled" {
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("expected cancellation, got %v", err)
				}
			} else if err != nil || got.Partial != 1 || warning == "" {
				t.Fatalf("coverage=%+v warning=%q err=%v", got, warning, err)
			}
		})
	}
}

func paginationClient(t *testing.T, batch func(http.ResponseWriter, *http.Request, []osvQuery)) *Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id, ok := strings.CutPrefix(r.URL.Path, "/v1/vulns/"); ok {
			fmt.Fprintf(w, `{"id":%q,"summary":"test record"}`, id)
			return
		}
		var req osvBatchRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Queries) == 0 {
			t.Errorf("bad batch: %+v (%v)", req, err)
			http.Error(w, "bad batch", http.StatusBadRequest)
			return
		}
		batch(w, r, req.Queries)
	}))
	old := OSVBaseURL
	OSVBaseURL = server.URL
	t.Cleanup(func() { server.Close(); OSVBaseURL = old })
	return NewClient(nil)
}

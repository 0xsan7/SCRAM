package resolve

import (
	"fmt"
	"testing"

	"github.com/0xsan7/scram/internal/model"
)

// TestPurlInvariantBites is the meta-test: an invariant that accepts
// everything checks nothing. Each case below is a PURL that disagrees with
// the fields it claims to be built from, and every one must be rejected.
func TestPurlInvariantBites(t *testing.T) {
	bad := []struct {
		label string
		c     model.Component
	}{
		{"version mismatch", model.Component{
			Purl: "pkg:golang/github.com/pkg/errors@v0.9.1",
			Name: "github.com/pkg/errors", Version: "v9.9.9"}},
		{"a namespace segment dropped", model.Component{
			Purl: "pkg:golang/github.com/errors@v0.9.1",
			Name: "github.com/pkg/errors", Version: "v0.9.1"}},
		{"a namespace segment reordered", model.Component{
			Purl: "pkg:golang/errors/pkg@v0.9.1",
			Name: "github.com/pkg/errors", Version: "v0.9.1"}},
		{"empty purl", model.Component{Purl: "", Name: "x", Version: "1"}},
		{"empty name", model.Component{Purl: "pkg:npm/lodash@1.0.0", Name: "", Version: "1.0.0"}},
		{"empty version", model.Component{Purl: "pkg:npm/lodash@1.0.0", Name: "lodash", Version: ""}},
		{"name absent from purl", model.Component{
			Purl: "pkg:npm/other@1.0.0", Name: "lodash", Version: "1.0.0"}},
	}
	for _, c := range bad {
		if purlAgreesWithFields(c.c) {
			t.Errorf("ACCEPTED a corrupt component (%s): purl=%q name=%q version=%q",
				c.label, c.c.Purl, c.c.Name, c.c.Version)
		}
	}
	good := []struct {
		label string
		c     model.Component
	}{
		{"npm flat", model.Component{Purl: "pkg:npm/lodash@4.17.21", Name: "lodash", Version: "4.17.21"}},
		{"npm scoped", model.Component{Purl: "pkg:npm/%40babel/core@7.11.1", Name: "@babel/core", Version: "7.11.1"}},
		{"go namespaced", model.Component{Purl: "pkg:golang/github.com/pkg/errors@v0.9.1", Name: "github.com/pkg/errors", Version: "v0.9.1"}},
		{"go v2 suffix", model.Component{Purl: "pkg:golang/github.com/aws/aws-sdk-go-v2/service/s3@v1.0.0", Name: "github.com/aws/aws-sdk-go-v2/service/s3", Version: "v1.0.0"}},
		{"gopkg.in", model.Component{Purl: "pkg:golang/gopkg.in/yaml.v3@v3.0.1", Name: "gopkg.in/yaml.v3", Version: "v3.0.1"}},
		{"pypi", model.Component{Purl: "pkg:pypi/requests@2.31.0", Name: "requests", Version: "2.31.0"}},
		{"cargo", model.Component{Purl: "pkg:cargo/serde@1.0.0", Name: "serde", Version: "1.0.0"}},
	}
	for _, c := range good {
		if !purlAgreesWithFields(c.c) {
			t.Errorf("REJECTED a valid component (%s): purl=%q name=%q version=%q",
				c.label, c.c.Purl, c.c.Name, c.c.Version)
		}
	}
	fmt.Printf("  %d corrupt rejected, %d valid accepted\n", len(bad), len(good))
}

package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/orcasecurity-research/bgh/internal/model"
	"github.com/orcasecurity-research/bgh/internal/scan"
)

func TestTerminalNotSearchedIsNeverClean(t *testing.T) {
	o := &scan.Outcome{
		Ref: model.RepoRef{Owner: "o", Name: "r"}, Verdict: scan.NotSearched,
		Detail: "publishes no GitHub releases", Started: time.Now(),
	}
	var b bytes.Buffer
	Terminal(&b, o, "o-r.md", Style{})
	out := b.String()
	if !strings.Contains(out, "NOT SEARCHED") || strings.Contains(out, "NO GAP") ||
		!strings.Contains(out, "not a clean result") || !strings.Contains(out, "o-r.md") {
		t.Errorf("%s", out)
	}
	md := Markdown(o, "test")
	if !strings.Contains(md, "Verdict: NOT SEARCHED") || strings.Contains(md, "## No gap") {
		t.Errorf("%s", md)
	}
}

func TestDefaultPathAndStyle(t *testing.T) {
	o := &scan.Outcome{Ref: model.RepoRef{Owner: "acme", Name: "tool"}}
	if DefaultPath(o) != "acme-tool.md" {
		t.Error(DefaultPath(o))
	}
	if (Style{}).Red("x") != "x" || !strings.Contains((Style{Color: true}).Red("x"), "\033[") {
		t.Error("style")
	}
}

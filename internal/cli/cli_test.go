package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestParseArgs(t *testing.T) {
	var buf bytes.Buffer
	o, _, done := parseArgs([]string{"owner/repo", "--ai=codex", "-o", "x.md", "-q"}, &buf)
	if done || o.target != "owner/repo" || !o.ai.set || o.ai.name != "codex" || o.output != "x.md" || !o.quiet {
		t.Fatalf("%+v done=%v %s", o, done, buf.String())
	}
	o, _, done = parseArgs([]string{"--ai", "https://github.com/o/r"}, &buf)
	if done || !o.ai.set || o.ai.name != "" || o.target != "https://github.com/o/r" {
		t.Fatalf("bare --ai must not swallow the repo: %+v", o)
	}
	o, _, _ = parseArgs([]string{"o/r"}, &buf)
	if o.ai.set {
		t.Error("ai off by default")
	}
	for _, bad := range [][]string{{}, {"a/b", "c/d"}, {"--ai=gemini", "a/b"}, {"--nope", "a/b"}} {
		if _, code, done := parseArgs(bad, &buf); !done || code != ExitNotSearched {
			t.Errorf("%v should be rejected", bad)
		}
	}
}

func TestRunRejectsBadRepo(t *testing.T) {
	var out, errb bytes.Buffer
	if code := Run([]string{"nonsense"}, &out, &errb); code != ExitNotSearched || !strings.Contains(errb.String(), "owner/name") {
		t.Errorf("%d %s", code, errb.String())
	}
}

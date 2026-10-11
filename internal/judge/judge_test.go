package judge

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseVerdict(t *testing.T) {
	v := ParseVerdict(`Sure! {"reachable": true, "defect": false, "confidence": "high", "path": ["a.go:3"], "attacker_input": "x", "mechanism": "m"} done`)
	if v.Unjudged() || !v.IsReachable() || v.IsDefect() || v.Confidence != "high" || len(v.Path) != 1 {
		t.Errorf("%+v", v)
	}
	if v := ParseVerdict("no idea"); !v.Unjudged() || v.Error == "" {
		t.Errorf("garbage must be unjudged: %+v", v)
	}
	if v := ParseVerdict(""); !v.Unjudged() {
		t.Error("empty must be unjudged")
	}
	v = ParseVerdict(`{"reachable": false, "defect": true, "mechanism": "has } brace"}`)
	if !v.IsDefect() || v.IsReachable() || v.Band() != 4 {
		t.Errorf("%+v", v)
	}
}

func TestClaudeEnvelope(t *testing.T) {
	txt, err := claudeText(`{"type":"result","is_error":false,"result":"{\"reachable\":true}"}`)
	if err != nil || txt != `{"reachable":true}` {
		t.Errorf("%q %v", txt, err)
	}
	if _, err := claudeText(`{"is_error":true,"result":"Usage limit reached"}`); err == nil {
		t.Error("expected error")
	} else {
		var q *QuotaError
		if !errors.As(err, &q) {
			t.Errorf("want quota error, got %v", err)
		}
	}
}

func TestSymbolName(t *testing.T) {
	cases := map[string]string{
		"func (l *Limiter) Validate(req *Request) error {": "Validate",
		"def download_file(request, name):":                "download_file",
		"impl RoutedItem {":                                "RoutedItem",
		"":                                                 "",
	}
	for in, want := range cases {
		if got := SymbolName(in); got != want {
			t.Errorf("SymbolName(%q) = %q, want %q", in, got, want)
		}
	}
}

type fakeProvider struct {
	answer string
	err    error
	prompt string
}

func (f *fakeProvider) Name() string { return "fake" }
func (f *fakeProvider) Ask(_ context.Context, p string) (string, error) {
	f.prompt = p
	return f.answer, f.err
}

func TestJudge(t *testing.T) {
	f := &fakeProvider{answer: `{"reachable":true,"defect":true}`}
	v, err := Judge(context.Background(), f, Input{Slug: "o/r", Tag: "v1", Subject: "s", Symbol: "f", Diff: "d"}, "file", nil)
	if err != nil || !v.IsDefect() {
		t.Fatalf("%+v %v", v, err)
	}
	if !strings.Contains(f.prompt, "untrusted data") || !strings.Contains(f.prompt, "No call site") {
		t.Error("prompt missing guardrails")
	}
	f.err = errors.New("boom")
	if v, err := Judge(context.Background(), f, Input{}, "", nil); err != nil || !v.Unjudged() {
		t.Errorf("failure must be unjudged, not an error: %+v %v", v, err)
	}
	f.err = &QuotaError{Detail: "x"}
	if _, err := Judge(context.Background(), f, Input{}, "", nil); err == nil {
		t.Error("quota must surface")
	}
}

func TestDetect(t *testing.T) {
	old := LookPath
	defer func() { LookPath = old }()
	LookPath = func(n string) (string, error) {
		if n == "codex" {
			return "/bin/codex", nil
		}
		return "", errors.New("no")
	}
	p, err := Detect("")
	if err != nil || p.Name() != Codex {
		t.Errorf("auto: %v %v", p, err)
	}
	if _, err := Detect("claude"); err == nil {
		t.Error("forcing a missing CLI must fail")
	}
	LookPath = func(string) (string, error) { return "", errors.New("no") }
	if _, err := Detect(""); !errors.Is(err, ErrNoProvider) {
		t.Errorf("want ErrNoProvider, got %v", err)
	}
}

func TestExecProviders(t *testing.T) {
	dir := t.TempDir()
	claude := filepath.Join(dir, "claude")
	os.WriteFile(claude, []byte("#!/bin/sh\ncat >/dev/null\necho '{\"result\":\"{\\\"reachable\\\":true,\\\"defect\\\":true}\"}'\n"), 0o755)
	out, err := (&ClaudeProvider{Bin: claude}).Ask(context.Background(), "hi")
	if err != nil || !ParseVerdict(out).IsDefect() {
		t.Errorf("claude: %q %v", out, err)
	}
	codex := filepath.Join(dir, "codex")
	// Fake codex: find the -o argument and write the answer there.
	os.WriteFile(codex, []byte("#!/bin/sh\ncat >/dev/null\nwhile [ $# -gt 0 ]; do if [ \"$1\" = -o ]; then echo '{\"reachable\":false,\"defect\":true}' > \"$2\"; fi; shift; done\n"), 0o755)
	out, err = (&CodexProvider{Bin: codex}).Ask(context.Background(), "hi")
	if err != nil || !ParseVerdict(out).IsDefect() {
		t.Errorf("codex: %q %v", out, err)
	}
}

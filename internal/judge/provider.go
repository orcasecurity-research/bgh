package judge

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// ErrNoProvider explains that no AI CLI could be found.
var ErrNoProvider = fmt.Errorf("--ai needs the `claude` or `codex` CLI on your PATH (neither was found)")

// Names of the supported providers.
const (
	Claude = "claude"
	Codex  = "codex"
)

// LookPath is exec.LookPath; replaced in tests.
var LookPath = exec.LookPath

// Detect picks a provider. want is "" or "auto" for whichever is on PATH
// (claude first), or "claude" / "codex" to force one.
func Detect(want string) (Provider, error) {
	switch strings.ToLower(want) {
	case "", "auto", "true":
		for _, name := range []string{Claude, Codex} {
			if bin, err := LookPath(name); err == nil {
				return newProvider(name, bin), nil
			}
		}
		return nil, ErrNoProvider
	case Claude, Codex:
		bin, err := LookPath(want)
		if err != nil {
			return nil, fmt.Errorf("--ai=%s: the `%s` CLI was not found on your PATH", want, want)
		}
		return newProvider(strings.ToLower(want), bin), nil
	}
	return nil, fmt.Errorf("unknown AI provider %q (use claude or codex)", want)
}

func newProvider(name, bin string) Provider {
	if name == Codex {
		return &CodexProvider{Bin: bin}
	}
	return &ClaudeProvider{Bin: bin}
}

// run executes a CLI with the prompt on stdin, in an empty scratch directory so
// that a model tricked by the untrusted code it reads has nothing to find.
//
// "{dir}" in args is replaced by that directory. If readFile is not empty, its
// contents (relative to the directory) are returned in file, read before the
// directory is removed.
func run(ctx context.Context, bin string, args []string, prompt, readFile string) (stdout, file string, err error) {
	ctx, cancel := context.WithTimeout(ctx, CallTimout)
	defer cancel()
	dir, err := os.MkdirTemp("", "bgh-ai-")
	if err != nil {
		return "", "", err
	}
	defer os.RemoveAll(dir)
	args = append([]string(nil), args...)
	for i, a := range args {
		args[i] = strings.ReplaceAll(a, "{dir}", dir)
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = dir
	cmd.Stdin = strings.NewReader(prompt)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err = cmd.Run()
	if readFile != "" {
		if data, rerr := os.ReadFile(filepath.Join(dir, readFile)); rerr == nil {
			file = string(data)
		}
	}
	return out.String(), file, finish(ctx, err, filepath.Base(bin), errb.String(), out.String())
}

func finish(ctx context.Context, err error, name, stderr, stdout string) error {
	if err == nil {
		return nil
	}
	if ctx.Err() == context.DeadlineExceeded {
		return fmt.Errorf("%s timed out after %s", name, CallTimout.Round(time.Second))
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	detail := strings.TrimSpace(stderr)
	if detail == "" {
		detail = strings.TrimSpace(stdout)
	}
	if len(detail) > 200 {
		detail = detail[:200]
	}
	if quotaRe.MatchString(stderr) || quotaRe.MatchString(stdout) {
		return &QuotaError{Detail: detail}
	}
	return fmt.Errorf("%s: %v: %s", name, err, detail)
}

// ClaudeProvider runs `claude -p ... --output-format json`.
//
// Tools are disabled: the prompt embeds code from a public repository, which
// is untrusted, and a judgement needs no tools. No model is chosen here; the
// CLI's default applies.
type ClaudeProvider struct{ Bin string }

func (p *ClaudeProvider) Name() string { return Claude }

func (p *ClaudeProvider) Ask(ctx context.Context, prompt string) (string, error) {
	out, _, err := run(ctx, p.Bin,
		[]string{"-p", "--output-format", "json", "--tools", "", "--no-session-persistence"}, prompt, "")
	if err != nil {
		return "", err
	}
	return claudeText(out)
}

// claudeText unwraps the envelope `claude --output-format json` puts around the
// model's reply. Reading the envelope as the verdict finds no `reachable` key
// and calls every judgement unjudged.
func claudeText(stdout string) (string, error) {
	var env struct {
		Result  *string `json:"result"`
		IsError bool    `json:"is_error"`
	}
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		return stdout, nil
	}
	if env.IsError {
		msg := ""
		if env.Result != nil {
			msg = *env.Result
		}
		if quotaRe.MatchString(msg) {
			return "", &QuotaError{Detail: clip(msg, 200)}
		}
		return "", fmt.Errorf("claude reported an error: %s", clip(msg, 200))
	}
	if env.Result != nil {
		return *env.Result, nil
	}
	return stdout, nil
}

// CodexProvider runs `codex exec` non-interactively, read-only sandboxed.
type CodexProvider struct{ Bin string }

func (p *CodexProvider) Name() string { return Codex }

func (p *CodexProvider) Ask(ctx context.Context, prompt string) (string, error) {
	stdout, file, err := run(ctx, p.Bin,
		[]string{"exec", "--skip-git-repo-check", "--sandbox", "read-only", "--ephemeral", "--color", "never",
			"-C", "{dir}", "-o", "{dir}/answer.txt", "-"},
		prompt, "answer.txt")
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(file) != "" {
		return file, nil
	}
	return stdout, nil
}

// Package cli is bgh's command line: parse arguments, resolve credentials,
// run one scan, print the summary, write the report, pick the exit code.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"syscall"

	"github.com/orcasecurity-research/bgh/internal/detect"
	"github.com/orcasecurity-research/bgh/internal/ghapi"
	"github.com/orcasecurity-research/bgh/internal/judge"
	"github.com/orcasecurity-research/bgh/internal/model"
	"github.com/orcasecurity-research/bgh/internal/report"
	"github.com/orcasecurity-research/bgh/internal/scan"
)

// Exit codes.
const (
	ExitNoGap       = 0
	ExitGap         = 1
	ExitNotSearched = 2 // not searched, or an error
)

// Version is set by -ldflags, otherwise read from the module build info.
var Version = ""

func version() string {
	if Version != "" {
		return Version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return "dev"
}

const usage = `bgh - Backport Gap Hunter

Does the tag behind a repository's "Latest release" lack a security fix that is
already on the default branch, with the pre-fix code still present in that tag?

Usage:
  bgh [flags] <owner/repo | https://github.com/owner/repo>

Flags:
  --ai[=claude|codex]  add the keyword tier, judged by an AI CLI on your PATH
                       (auto-detects claude, then codex; --ai=NAME forces one)
  -o, --output PATH    write the markdown report here (default ./<owner>-<repo>.md)
  -q, --quiet          no progress messages
  --version            print the version
  -h, --help           show this help

Verdicts and exit codes:
  GAP           exit 1   a fix is missing from the Latest release
  NO GAP        exit 0   nothing found missing
  NOT SEARCHED  exit 2   the scan was refused or failed; nothing was compared

Credentials: GH_TOKEN, then GITHUB_TOKEN, then your gh login (gh auth login).
`

// aiFlag is a boolean flag that also accepts a value: --ai, --ai=claude.
type aiFlag struct {
	set  bool
	name string
}

func (a *aiFlag) String() string   { return a.name }
func (a *aiFlag) IsBoolFlag() bool { return true }
func (a *aiFlag) Set(v string) error {
	switch strings.ToLower(v) {
	case "false", "0":
		a.set, a.name = false, ""
	case "true", "1", "":
		a.set, a.name = true, ""
	case judge.Claude, judge.Codex:
		a.set, a.name = true, strings.ToLower(v)
	default:
		return fmt.Errorf("unknown AI provider %q (use claude or codex)", v)
	}
	return nil
}

type options struct {
	ai     aiFlag
	output string
	quiet  bool
	target string
}

// parseArgs lets flags appear before or after the repository argument.
func parseArgs(args []string, stderr io.Writer) (*options, int, bool) {
	o := &options{}
	fs := flag.NewFlagSet("bgh", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Var(&o.ai, "ai", "")
	fs.StringVar(&o.output, "o", "", "")
	fs.StringVar(&o.output, "output", "", "")
	fs.BoolVar(&o.quiet, "q", false, "")
	fs.BoolVar(&o.quiet, "quiet", false, "")
	showVersion := fs.Bool("version", false, "")
	help := fs.Bool("h", false, "")
	fs.BoolVar(help, "help", false, "")

	var positional []string
	rest := args
	for {
		if err := fs.Parse(rest); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				fmt.Fprint(stderr, usage)
				return nil, ExitNoGap, true
			}
			fmt.Fprintf(stderr, "bgh: %v\n\n%s", err, usage)
			return nil, ExitNotSearched, true
		}
		if fs.NArg() == 0 {
			break
		}
		positional = append(positional, fs.Arg(0))
		rest = fs.Args()[1:]
	}
	if *help {
		fmt.Fprint(stderr, usage)
		return nil, ExitNoGap, true
	}
	if *showVersion {
		fmt.Fprintln(stderr, "bgh", version())
		return nil, ExitNoGap, true
	}
	if len(positional) != 1 {
		fmt.Fprintf(stderr, "bgh: expected exactly one repository (owner/repo or a github.com URL)\n\n%s", usage)
		return nil, ExitNotSearched, true
	}
	o.target = positional[0]
	return o, 0, false
}

// Run is the whole program. It returns the process exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	opts, code, done := parseArgs(args, stderr)
	if done {
		return code
	}
	ref, err := model.ParseRepo(opts.target)
	if err != nil {
		fmt.Fprintf(stderr, "bgh: %v\n", err)
		return ExitNotSearched
	}

	var provider judge.Provider
	if opts.ai.set {
		provider, err = judge.Detect(opts.ai.name)
		if err != nil {
			fmt.Fprintf(stderr, "bgh: %v\n", err)
			return ExitNotSearched
		}
	}

	token, err := ghapi.ResolveToken()
	if err != nil {
		fmt.Fprintf(stderr, "bgh: %v\n", err)
		return ExitNotSearched
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	st := report.Style{Color: isTerminal(stdout) && os.Getenv("NO_COLOR") == ""}
	progress := func(msg string) {
		if !opts.quiet {
			fmt.Fprintln(stderr, st.Dim("  "+msg))
		}
	}
	client := ghapi.New(token)
	client.Log = progress

	cfg := scan.Config{
		Config:   detect.Config{Client: client, Token: token, Progress: progress},
		Provider: provider,
	}
	out, err := scan.Run(ctx, cfg, ref)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			fmt.Fprintln(stderr, "bgh: interrupted")
			return 130
		}
		fmt.Fprintf(stderr, "bgh: %s: %s\n", scan.NotSearched, err)
		fmt.Fprintln(stderr, "bgh: this is not a clean result - nothing was compared.")
		return ExitNotSearched
	}

	path := opts.output
	if path == "" {
		path = report.DefaultPath(out)
	}
	wrote := path
	if err := report.Write(path, out, version()); err != nil {
		fmt.Fprintf(stderr, "bgh: could not write the report: %v\n", err)
		wrote = ""
	}
	report.Terminal(stdout, out, wrote, st)

	switch out.Verdict {
	case scan.Gap:
		return ExitGap
	case scan.NoGap:
		return ExitNoGap
	}
	return ExitNotSearched
}

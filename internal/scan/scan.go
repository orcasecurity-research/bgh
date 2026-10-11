// Package scan composes the detection pipeline and the optional AI tier into
// one verdict for one repository.
//
// Three answers only. NOT SEARCHED is deliberately not NO GAP: a repository
// whose detector cannot be derived was never compared, and reading it as clean
// is the one failure mode that misleads.
package scan

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/orcasecurity-research/bgh/internal/detect"
	"github.com/orcasecurity-research/bgh/internal/gitrepo"
	"github.com/orcasecurity-research/bgh/internal/judge"
	"github.com/orcasecurity-research/bgh/internal/model"
)

// The three verdicts.
const (
	Gap         = "GAP"
	NoGap       = "NO GAP"
	NotSearched = "NOT SEARCHED"
)

// MaxJudged caps the AI calls one scan may spend. Candidates beyond it are
// reported as unjudged rather than silently dropped.
const MaxJudged = 40

// judgeWorkers is how many AI CLI calls run at once.
const judgeWorkers = 3

// Finding is one gap to show the user.
type Finding struct {
	Cand *detect.Candidate
	// Verdict is the AI judgement; nil for vendor-signalled findings, which are
	// never judged.
	Verdict   *judge.Verdict
	CallSites []judge.CallSite
}

// Outcome is the final answer for a repository.
type Outcome struct {
	Ref     model.RepoRef
	Verdict string
	Detail  string
	Result  *detect.Result
	// Findings are the gaps shown: vendor-signalled ones, plus keyword-tier
	// ones the judge rated as a real defect.
	Findings []Finding
	// HiddenNotDefect counts keyword-tier exposures the judge rated not a defect.
	HiddenNotDefect int
	// Unjudged counts keyword-tier exposures the judge gave no answer on.
	Unjudged int
	Provider string
	// QuotaStopped is true when the AI provider's quota ended judging early.
	QuotaStopped bool
	Started      time.Time
	Finished     time.Time
}

// Config extends the detection config with the AI provider.
type Config struct {
	detect.Config
	// Provider is non-nil in --ai mode.
	Provider judge.Provider
}

// Run scans one repository end to end. An error means the scan could not be
// completed; the caller reports it as NOT SEARCHED.
func Run(ctx context.Context, cfg Config, ref model.RepoRef) (*Outcome, error) {
	cfg.AI = cfg.Provider != nil
	out := &Outcome{Ref: ref, Started: time.Now()}
	if cfg.Provider != nil {
		out.Provider = cfg.Provider.Name()
	}
	res, err := detect.Run(ctx, cfg.Config, ref)
	if err != nil {
		return nil, err
	}
	out.Result = res
	defer func() { out.Finished = time.Now() }()

	if res.Refused != "" {
		out.Verdict, out.Detail = NotSearched, res.RefusedShort
		return out, nil
	}

	var keyword []*detect.Candidate
	for _, c := range res.Exposures() {
		if c.VendorSignalled() {
			out.Findings = append(out.Findings, Finding{Cand: c})
		} else {
			keyword = append(keyword, c)
		}
	}
	if len(keyword) > 0 && cfg.Provider != nil {
		if err := judgeKeyword(ctx, cfg, ref, res, keyword, out); err != nil {
			return nil, err
		}
	}

	sort.SliceStable(out.Findings, func(i, j int) bool {
		a, b := out.Findings[i], out.Findings[j]
		if (a.Verdict == nil) != (b.Verdict == nil) {
			return a.Verdict == nil // vendor signal first
		}
		if a.Verdict != nil && a.Verdict.Band() != b.Verdict.Band() {
			return a.Verdict.Band() > b.Verdict.Band()
		}
		return a.Cand.Date().After(b.Cand.Date())
	})

	switch {
	case len(out.Findings) > 0:
		out.Verdict = Gap
		out.Detail = fmt.Sprintf("%d gap(s) at %s", len(out.Findings), res.Release.Tag)
	case out.Unjudged > 0:
		// Hidden because nobody answered, not because the answer was no.
		out.Verdict = NotSearched
		out.Detail = fmt.Sprintf("the AI judge gave no answer on %d keyword-tier candidate(s)", out.Unjudged)
	default:
		out.Verdict = NoGap
		out.Detail = fmt.Sprintf("%d candidates examined against %s", res.Stats.Silent, res.Release.Tag)
	}
	return out, nil
}

// judgeKeyword rates each keyword-tier exposure by reading the shipped code.
// Only those rated a real defect become findings; the rest are counted, never
// silently lost.
func judgeKeyword(ctx context.Context, cfg Config, ref model.RepoRef, res *detect.Result,
	keyword []*detect.Candidate, out *Outcome) error {
	if len(keyword) > MaxJudged {
		out.Unjudged += len(keyword) - MaxJudged
		keyword = keyword[:MaxJudged]
	}
	tag := res.Release.Tag
	if cfg.Progress != nil {
		cfg.Progress(fmt.Sprintf("judging %d keyword-tier candidate(s) with %s", len(keyword), cfg.Provider.Name()))
	}

	dir, err := os.MkdirTemp(cfg.WorkDir, "bgh-tag-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	url := ref.CloneURL()
	if cfg.CloneURL != nil {
		url = cfg.CloneURL(ref)
	}
	co, err := judge.NewCheckout(ctx, url, tag, filepath.Join(dir, "co"), gitrepo.AuthEnv(cfg.Token))
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// A repository that cannot be checked out leaves its findings unjudged,
		// which is reported, never read as "not a defect".
		out.Unjudged += len(keyword)
		return nil
	}

	type result struct {
		v     judge.Verdict
		sites []judge.CallSite
	}
	results := make([]*result, len(keyword))
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		next    int
		stopped bool
	)
	for w := 0; w < judgeWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				mu.Lock()
				if stopped || next >= len(keyword) || ctx.Err() != nil {
					mu.Unlock()
					return
				}
				i := next
				next++
				mu.Unlock()

				c := keyword[i]
				in := inputFor(ref, tag, c)
				sites := co.WalkCallers(ctx, in.Symbol)
				shipped := ""
				if c.Release != nil && c.Release.Path != "" {
					shipped = readShipped(co, c.Release.Path)
				}
				v, err := judge.Judge(ctx, cfg.Provider, in, shipped, sites)
				var q *judge.QuotaError
				mu.Lock()
				if errors.As(err, &q) {
					stopped = true
				} else {
					results[i] = &result{v, sites}
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return err
	}
	for i, c := range keyword {
		r := results[i]
		switch {
		case r == nil:
			out.Unjudged++
			out.QuotaStopped = out.QuotaStopped || stopped
		case r.v.Unjudged():
			out.Unjudged++
		case r.v.IsDefect():
			v := r.v
			out.Findings = append(out.Findings, Finding{Cand: c, Verdict: &v, CallSites: r.sites})
		default:
			out.HiddenNotDefect++
		}
	}
	return nil
}

func inputFor(ref model.RepoRef, tag string, c *detect.Candidate) judge.Input {
	in := judge.Input{Slug: ref.Slug(), Tag: tag, Subject: c.Commit.Subject(), Diff: c.Patch}
	if c.Signature != nil {
		in.Symbol = c.Signature.Symbol
		in.Path = c.Signature.Path
	}
	if in.Symbol == "" {
		in.Symbol = in.Path
	}
	if c.Release != nil && c.Release.Path != "" {
		in.Path = c.Release.Path
	}
	return in
}

func readShipped(co *judge.Checkout, path string) string {
	data, err := os.ReadFile(filepath.Join(co.Root, path))
	if err != nil {
		return ""
	}
	return string(data)
}

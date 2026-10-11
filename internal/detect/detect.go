// Package detect is the core of bgh: one repository in, a set of confirmed
// exposures out.
//
// Pipeline:
//
//  1. gather facts over the API: metadata, GitHub's Latest release, published
//     advisories, the default branch's recent commits
//  2. derive the vendor's security-commit fingerprint (package fingerprint)
//  3. blobless clone of the default branch and the Latest tag
//  4. enumerate candidate fix commits on the default branch with the signals
//  5. subtract commits that map to a published advisory, leaving the silent set
//  6. extract a testable signature from each survivor's diff
//  7. test that signature against the tag behind Latest by READING FILES,
//     never by searching commit history
//
// A finding is reported only when every step resolved positively. Anything
// ambiguous is reported as ambiguous, or not at all.
package detect

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/orcasecurity-research/bgh/internal/fingerprint"
	"github.com/orcasecurity-research/bgh/internal/ghapi"
	"github.com/orcasecurity-research/bgh/internal/gitrepo"
	"github.com/orcasecurity-research/bgh/internal/keywords"
	"github.com/orcasecurity-research/bgh/internal/model"
	"github.com/orcasecurity-research/bgh/internal/signature"
)

// Per-candidate outcomes at the release tag.
const (
	StatusGap          = "GAP"          // fix missing, pre-fix code still present
	StatusBackported   = "BACKPORTED"   // the tag carries the fix
	StatusUnresolved   = "UNRESOLVED"   // could not locate the code with confidence - never a finding
	StatusInconclusive = "INCONCLUSIVE" // located it, evidence does not settle the question
)

// Defaults.
const (
	ScreenWindowDays  = 180 // commit corpus for detector derivation
	MaxCommitPages    = 40  // 100 commits per page
	DeepWindowDays    = 180 // how far back to look for fix commits
	MaxCandidates     = 400 // candidate commits examined per scan
	ShallowMarginDays = 180 // history fetched beyond the judged window
)

// Config is everything a scan needs besides the repository.
type Config struct {
	Client *ghapi.Client
	// Token is passed to git in memory only.
	Token string
	// AI adds the keyword tier. Without it, only vendor signals enumerate.
	AI            bool
	WindowDays    int
	MaxCandidates int
	Workers       int
	// CloneURL overrides where git fetches from (tests).
	CloneURL func(model.RepoRef) string
	// WorkDir is where the clone lives; "" uses the system temp dir. The clone
	// is always removed.
	WorkDir  string
	Progress func(string)
}

func (c *Config) progress(format string, a ...any) {
	if c.Progress != nil {
		c.Progress(fmt.Sprintf(format, a...))
	}
}

func (c *Config) defaults() {
	if c.WindowDays <= 0 {
		c.WindowDays = DeepWindowDays
	}
	if c.MaxCandidates <= 0 {
		c.MaxCandidates = MaxCandidates
	}
	if c.Workers <= 0 {
		c.Workers = 6
	}
}

// ReleaseFinding is what the tag behind GitHub's Latest release does with one
// fix. A tag IS something that shipped, which is the whole reason it is the
// anchor: unlike a branch it cannot be "carries the bug but nothing released".
type ReleaseFinding struct {
	Ref        string
	Status     string
	Path       string
	HowLocated string
	Presence   *signature.Presence
	Published  time.Time
	DaysPublic int // days the fix has been public; -1 unknown
	Note       string
	// VulnEvidence is which pre-fix shape the fix-absent decision rested on:
	// "removed", "context" or "none". A gap resting on context lines rests on a
	// weaker discriminator than one resting on lines the fix actually deleted.
	VulnEvidence string
	// ShippedSinceFix is whether the vendor published a release after the fix
	// landed: a missed backport versus a fix not yet shipped. It gates
	// nothing; in both cases the downloadable version lacks the fix.
	ShippedSinceFix *bool
}

// Confirmed is true for a gap.
func (r *ReleaseFinding) Confirmed() bool { return r != nil && r.Status == StatusGap }

// Candidate is a commit on the default branch that might be an unshipped fix.
type Candidate struct {
	Commit         model.Commit
	MatchedSignals []string
	Signature      *signature.FixSignature
	// Evidence is graded from the same patch the signature is built from. nil
	// means the patch could not be fetched, which is no basis for a claim.
	Evidence *signature.DiffEvidence
	Advisory *model.Advisory
	Dropped  string
	Release  *ReleaseFinding
	Patch    string

	forkUnverified bool
}

// VendorSignalled: a vendor-specific signal says the vendor themselves marked
// this as security work.
func (c *Candidate) VendorSignalled() bool {
	for _, s := range c.MatchedSignals {
		if fingerprint.IsVendorKind(s) {
			return true
		}
	}
	return false
}

// Signals lists the distinct matched signal kinds in order.
func (c *Candidate) Signals() []string {
	var out []string
	seen := map[string]bool{}
	for _, s := range c.MatchedSignals {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// Date is the commit's date.
func (c *Candidate) Date() time.Time { return c.Commit.Date() }

// Exposed: does this candidate earn the word GAP?
//
// Two conditions, and neither is about whether the change looks like security
// work:
//
//	exposed       the tag behind Latest lacks the fix and still carries the
//	              pre-fix code. One ref, asked once.
//	not loosening a change that removes salient lines leaves the unpatched
//	              release strictly MORE restrictive, so reporting its absence
//	              as an exposure is backwards.
func (c *Candidate) Exposed() bool {
	if !c.Release.Confirmed() {
		return false
	}
	if c.Evidence == nil {
		// An empty patch is not a neutral diff, it is no diff: the API answers
		// "" both when the commit could not be fetched and for a merge commit.
		return false
	}
	return c.Evidence.Direction != signature.Loosening
}

// Result is a finished scan of one repository.
type Result struct {
	Ref         model.RepoRef
	Facts       *fingerprint.Facts
	Fingerprint *fingerprint.Fingerprint
	Release     *model.ReleaseTarget
	DefaultBr   string
	AI          bool
	Candidates  []*Candidate
	// Refused is the reason nothing was searched, or "". A refusal is NOT SEARCHED
	// and deliberately never NO GAP.
	Refused string
	// RefusedShort is a one-line form of Refused.
	RefusedShort string
	Stats        Stats
}

// Stats counts what the scan examined.
type Stats struct {
	Candidates, Attributed, Silent, Exposed, TooOld int
	APICalls                                        int
}

// Exposures are the candidates that earn the word GAP, vendor-signalled first,
// then newest first.
func (r *Result) Exposures() []*Candidate {
	var out []*Candidate
	for _, c := range r.Candidates {
		if c.Exposed() {
			out = append(out, c)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].VendorSignalled() != out[j].VendorSignalled() {
			return out[i].VendorSignalled()
		}
		return out[i].Date().After(out[j].Date())
	})
	return out
}

// ------------------------------------------------------------------ gathering

// Gather reads the facts the scan needs over the API.
func Gather(ctx context.Context, api *ghapi.RepoAPI, windowDays int) (*fingerprint.Facts, error) {
	meta, err := api.Meta(ctx)
	if err != nil {
		return nil, err
	}
	rel, err := api.LatestRelease(ctx)
	if err != nil {
		return nil, err
	}
	facts := &fingerprint.Facts{Ref: api.Ref, Meta: meta, WindowDays: windowDays, Release: rel}
	if meta.Archived || rel == nil {
		// Settled by what is already in hand: no need to spend calls deriving
		// a detector for a repository whose answer is already known.
		return facts, nil
	}
	facts.Advisories = api.Advisories(ctx)
	facts.Commits, facts.Truncated, err = api.ListCommits(ctx, windowDays, MaxCommitPages)
	if err != nil {
		return nil, err
	}
	return facts, nil
}

// RefusalFor says why a repository cannot be searched at all, or "".
//
// Both answers are NOT SEARCHED rather than NO GAP, and both are named rather
// than merged, so a silent skip cannot be mistaken for a clean result.
func RefusalFor(f *fingerprint.Facts) string {
	if f.Meta.Archived {
		return "archived"
	}
	if f.Release == nil {
		// No published release means there is no "latest version" for a fix to
		// be missing from. The question this tool asks has no subject here.
		return "publishes no GitHub releases"
	}
	return ""
}

// ------------------------------------------------------------------ enumeration

// Enumerate matches the derived signals over the default branch's window.
//
// The log is read once and matched in Go: doing the regex in git would make
// the result depend on the local git build's regex flavour. Without AI, only
// vendor signals enumerate; the keyword tier and taxonomy references need the
// judge, because on their own they have a poor record.
func Enumerate(log []model.Commit, fp *fingerprint.Fingerprint, ai bool, limit int) []*Candidate {
	type matcher struct {
		kind string
		rx   interface{ MatchString(string) bool }
	}
	var matchers []matcher
	for _, sig := range fp.Signals {
		if sig.Grep == "" {
			continue
		}
		if !ai && !fingerprint.IsVendorKind(sig.Kind) {
			continue
		}
		matchers = append(matchers, matcher{sig.Kind, mustCI(sig.Grep)})
	}
	forkThreshold := 0
	if fp.PRLowWater > 0 {
		forkThreshold = fingerprint.ForkThreshold(fp.PRLowWater)
	}

	byIdx := map[string]*Candidate{}
	var order []string
	for _, c := range log {
		// Routine churn cannot be a backport gap in the vendor's own code, and a
		// dependency bump that name-drops a tracker or an upstream GHSA id would
		// otherwise outrank real fixes and consume the candidate budget.
		if keywords.NegativeRe.MatchString(c.Message) {
			continue
		}
		var hits []string
		unverifiedFork := false
		for _, m := range matchers {
			if !m.rx.MatchString(c.Message) {
				continue
			}
			if m.kind == fingerprint.KindFork {
				// The grep matches every merge commit; only a PR number far
				// below the public sequence is a suspect, and run verifies it.
				if n := c.MergePR(); n == 0 || forkThreshold == 0 || n >= forkThreshold {
					continue
				}
				unverifiedFork = true
			}
			hits = append(hits, m.kind)
		}
		if len(hits) == 0 {
			continue
		}
		if _, dup := byIdx[c.SHA]; !dup {
			order = append(order, c.SHA)
		}
		byIdx[c.SHA] = &Candidate{Commit: c, MatchedSignals: hits, forkUnverified: unverifiedFork}
	}

	if as := fp.ByKind(fingerprint.KindAuthor); as != nil {
		logins := map[string]bool{}
		for _, l := range as.Logins {
			logins[strings.ToLower(l)] = true
		}
		for _, sha := range order {
			c := byIdx[sha]
			if logins[strings.ToLower(c.Commit.AuthorLogin)] {
				c.MatchedSignals = append(c.MatchedSignals, fingerprint.KindAuthor)
			}
		}
	}

	cands := make([]*Candidate, 0, len(order))
	for _, sha := range order {
		cands = append(cands, byIdx[sha])
	}
	// Rank by signal precision so the strongest evidence survives the limit.
	rank := map[string]int{}
	for _, s := range fp.Signals {
		if s.Rank() > rank[s.Kind] {
			rank[s.Kind] = s.Rank()
		}
	}
	maxRank := func(c *Candidate) int {
		m := 0
		for _, k := range c.MatchedSignals {
			if rank[k] > m {
				m = rank[k]
			}
		}
		return m
	}
	sort.SliceStable(cands, func(i, j int) bool {
		a, b := cands[i], cands[j]
		if ra, rb := maxRank(a), maxRank(b); ra != rb {
			return ra > rb
		}
		if la, lb := len(a.MatchedSignals), len(b.MatchedSignals); la != lb {
			return la > lb
		}
		return a.Date().After(b.Date())
	})
	if len(cands) > limit {
		cands = cands[:limit]
	}
	return cands
}

// VerifyPrivateFork confirms a merge commit's PR number does not resolve to a
// public PR that is this commit.
func VerifyPrivateFork(ctx context.Context, api *ghapi.RepoAPI, c *Candidate, lowWater int) (bool, error) {
	pr := c.Commit.MergePR()
	if pr == 0 {
		return false, nil
	}
	if lowWater > 0 && pr >= fingerprint.ForkThreshold(lowWater) {
		return false, nil
	}
	sha, found, err := api.MergeCommitSHA(ctx, pr)
	if err != nil {
		return false, err
	}
	if !found {
		return true, nil
	}
	return sha != "" && sha != c.Commit.SHA, nil
}

// SubtractAdvisories removes commits that map to a published advisory,
// leaving the silently patched set.
func SubtractAdvisories(cands []*Candidate, advs []model.Advisory) (silent, attributed []*Candidate) {
	idx := ghapi.AdvisoryIndex(advs)
	var known []string
	for _, a := range advs {
		for _, s := range a.FixSHAs {
			known = append(known, strings.ToLower(s))
		}
	}
	for _, c := range cands {
		if cites := ghapi.CitedAdvisories(c.Commit.Message, idx); len(cites) > 0 {
			c.Advisory = cites[0]
			c.Dropped = "cites published advisory " + cites[0].GHSAID
			attributed = append(attributed, c)
			continue
		}
		sha := strings.ToLower(c.Commit.SHA)
		hit := false
		for _, s := range known {
			p := s
			if len(p) > 7 {
				p = p[:7]
			}
			if strings.HasPrefix(sha, p) {
				hit = true
				break
			}
		}
		if hit {
			c.Dropped = "commit is referenced by a published advisory"
			attributed = append(attributed, c)
			continue
		}
		silent = append(silent, c)
	}
	return silent, attributed
}

// --------------------------------------------------------------------- the run

func tagRef(tag string) string { return "refs/tags/" + tag }

// Run scans one repository. A refusal is reported in Result.Refused, not as
// an error; an error means the scan could not be completed.
func Run(ctx context.Context, cfg Config, ref model.RepoRef) (*Result, error) {
	cfg.defaults()
	api := &ghapi.RepoAPI{C: cfg.Client, Ref: ref}

	cfg.progress("reading %s metadata, releases and advisories", ref.Slug())
	facts, err := Gather(ctx, api, ScreenWindowDays)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", ref.Slug(), err)
	}
	res := &Result{Ref: ref, Facts: facts, Release: facts.Release, AI: cfg.AI, DefaultBr: facts.Meta.DefaultBranch}
	if r := RefusalFor(facts); r != "" {
		res.Refused, res.RefusedShort = r, r
		return res, nil
	}
	cfg.progress("latest release is %s; deriving the detector from %d recent commits and %d advisories",
		facts.Release.Tag, len(facts.Commits), len(facts.Advisories))

	fp := fingerprint.Derive(ctx, api, facts)
	res.Fingerprint = fp
	if !fp.Derivable {
		res.Refused = fp.Refusal
		res.RefusedShort = "no derivable detector"
		return res, nil
	}
	if !cfg.AI && !fp.HasVendorSignal() {
		res.Refused = noVendorSignalText(facts, fp)
		res.RefusedShort = "no vendor signal derivable (try --ai)"
		return res, nil
	}

	target := *facts.Release
	cutDays := cfg.WindowDays + ShallowMarginDays
	cut := time.Now().UTC().Add(-time.Duration(cutDays) * 24 * time.Hour)
	// The Latest tag may be older than the window; its commit must be inside the
	// fetched history or ancestry cannot be trusted.
	if tagCut := target.Published.Add(-60 * 24 * time.Hour); tagCut.Before(cut) {
		cut = tagCut
	}

	workRoot, err := os.MkdirTemp(cfg.WorkDir, "bgh-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(workRoot)

	env := gitrepo.AuthEnv(cfg.Token)
	url := ref.CloneURL()
	if cfg.CloneURL != nil {
		url = cfg.CloneURL(ref)
	}
	cfg.progress("cloning %s (blobless, bare; %s and tag %s)", ref.Slug(), facts.Meta.DefaultBranch, target.Tag)
	repo, err := gitrepo.Init(ctx, workRoot+"/repo.git", url, env)
	if err != nil {
		return nil, err
	}
	if err := repo.Fetch(ctx, gitrepo.FetchOptions{
		Branch: facts.Meta.DefaultBranch, Tag: target.Tag, ShallowSince: cut.Format("2006-01-02"),
	}); err != nil {
		return nil, fmt.Errorf("blobless fetch of %s failed: %w", ref.Slug(), err)
	}
	if !repo.ExistsRev(ctx, tagRef(target.Tag)) {
		return nil, fmt.Errorf("the Latest release tag %s could not be fetched from %s", target.Tag, ref.Slug())
	}

	since := time.Now().UTC().Add(-time.Duration(cfg.WindowDays) * 24 * time.Hour).Format("2006-01-02")
	log, err := repo.Log(ctx, facts.Meta.DefaultBranch, since, max(cfg.MaxCandidates*40, 20000))
	if err != nil {
		return nil, err
	}
	cands := Enumerate(log, fp, cfg.AI, cfg.MaxCandidates)
	res.Stats.Candidates = len(cands)
	cfg.progress("%d candidate commits on %s (last %d days)", len(cands), facts.Meta.DefaultBranch, cfg.WindowDays)

	silent, attributed := SubtractAdvisories(cands, facts.Advisories)
	res.Stats.Attributed = len(attributed)
	cfg.progress("%d map to a published advisory; %d silent", len(attributed), len(silent))

	// The requested cut is authoritative: commits too close to the history
	// boundary cannot have their ancestry trusted.
	cutoff := cut.Add(30 * 24 * time.Hour)
	var kept []*Candidate
	for _, c := range silent {
		if d := c.Date(); !d.IsZero() && !d.After(cutoff) {
			c.Dropped = fmt.Sprintf("older than the fetched history boundary (%s); ancestry cannot be trusted", cut.Format("2006-01-02"))
			res.Stats.TooOld++
			continue
		}
		kept = append(kept, c)
	}
	silent = kept

	for _, c := range silent {
		if !c.forkUnverified {
			continue
		}
		ok, err := VerifyPrivateFork(ctx, api, c, fp.PRLowWater)
		if err != nil {
			return nil, err
		}
		if !ok {
			c.MatchedSignals = removeOnce(c.MatchedSignals, fingerprint.KindFork)
		}
	}
	kept = kept[:0]
	for _, c := range silent {
		if len(c.MatchedSignals) > 0 {
			kept = append(kept, c)
		}
	}
	silent = kept
	res.Candidates = silent
	res.Stats.Silent = len(silent)

	cfg.progress("extracting fix signatures from %d commits", len(silent))
	if err := parallel(ctx, len(silent), cfg.Workers, func(i int) error {
		c := silent[i]
		// One fetch, two readings of it: what the fix looks like, and whether
		// it is a security fix at all. An empty patch is no diff, never a
		// neutral one: Evidence stays nil and Exposed refuses it.
		patch, err := api.CommitPatch(ctx, c.Commit.SHA)
		if err != nil {
			return err
		}
		c.Patch = patch
		c.Signature = signature.BuildSignature(patch, 14)
		if patch != "" {
			ev := signature.GradeDiff(patch)
			c.Evidence = &ev
		}
		return nil
	}); err != nil {
		return nil, err
	}

	// The exposure question, asked once per candidate against the one ref that
	// names something people run: the tag behind GitHub's Latest release.
	treeIdx, err := repo.TreeIndex(ctx, tagRef(target.Tag))
	if err != nil {
		return nil, err
	}
	tree := NewTree(treeIdx)
	reader := newFileReader(api, target.Tag)
	cfg.progress("testing %d candidates against %s", len(silent), target.Tag)
	if err := parallel(ctx, len(silent), cfg.Workers, func(i int) error {
		rf, err := CheckRelease(ctx, repo, target, silent[i], tree, reader.read)
		if err != nil {
			return err
		}
		silent[i].Release = rf
		return nil
	}); err != nil {
		return nil, err
	}
	for _, c := range silent {
		if c.Exposed() {
			res.Stats.Exposed++
		}
	}
	res.Stats.APICalls = cfg.Client.Spent()
	return res, nil
}

func noVendorSignalText(f *fingerprint.Facts, fp *fingerprint.Fingerprint) string {
	lines := []string{
		fmt.Sprintf("No vendor security signal is derivable for %s.", f.Ref.Slug()),
		"",
		"Without --ai, bgh only searches for fixes the vendor themselves marked: a GHSA id",
		"in a commit message, an internal tracker id, or a private-fork merge. None was found:",
		"",
	}
	for _, p := range fp.Probes {
		if p.Signal == "keyword" || p.Signal == "author" {
			continue
		}
		lines = append(lines, fmt.Sprintf("  [MISSING] %s: %s", p.Signal, p.LookedFor), "            -> "+p.Found)
	}
	lines = append(lines, "",
		"Re-run with --ai to add the keyword tier, judged by an AI CLI.",
		"This is not a clean bill of health - it means the repository was never searched.")
	return strings.Join(lines, "\n")
}

func removeOnce(s []string, v string) []string {
	out := make([]string, 0, len(s))
	for _, x := range s {
		if x == v {
			continue
		}
		out = append(out, x)
	}
	return out
}

// parallel runs fn over [0,n) with bounded concurrency and returns the first error.
func parallel(ctx context.Context, n, workers int, fn func(i int) error) error {
	if n == 0 {
		return nil
	}
	if workers > n {
		workers = n
	}
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		firstErr error
		next     int
	)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				mu.Lock()
				if firstErr != nil || next >= n || ctx.Err() != nil {
					mu.Unlock()
					return
				}
				i := next
				next++
				mu.Unlock()
				if err := fn(i); err != nil {
					mu.Lock()
					if firstErr == nil {
						firstErr = err
					}
					mu.Unlock()
					return
				}
			}
		}()
	}
	wg.Wait()
	if firstErr != nil {
		return firstErr
	}
	return ctx.Err()
}

// fileReader reads files at a tag over the API, once per path.
type fileReader struct {
	api *ghapi.RepoAPI
	tag string
	mu  sync.Mutex
	m   map[string]*fileEntry
}

type fileEntry struct {
	once    sync.Once
	content string
	ok      bool
	err     error
}

func newFileReader(api *ghapi.RepoAPI, tag string) *fileReader {
	return &fileReader{api: api, tag: tag, m: map[string]*fileEntry{}}
}

func (r *fileReader) read(ctx context.Context, path string) (string, bool, error) {
	r.mu.Lock()
	e := r.m[path]
	if e == nil {
		e = &fileEntry{}
		r.m[path] = e
	}
	r.mu.Unlock()
	e.once.Do(func() { e.content, e.ok, e.err = r.api.FileAt(ctx, r.tag, path) })
	return e.content, e.ok, e.err
}

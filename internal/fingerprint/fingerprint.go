// Package fingerprint derives a vendor's security-commit fingerprint from their
// own published advisories and commit history.
//
// No per-vendor configuration exists anywhere in this tool. Every
// vendor-specific pattern here is learned at runtime from that vendor's
// advisories and commit corpus.
//
// Signals, in descending precision:
//
//	ghsa             a commit message citing a GHSA id. GitHub writes these when
//	                 a private security fork is merged.
//	private-fork-pr  "Merge pull request #N" where PR N does not exist in the
//	                 public repo, or exists but is not this commit. Private
//	                 forks number their PRs from 1, far below the public sequence.
//	tracker          an internal tracker token (PREFIX-nnn) that leaks into
//	                 commit messages. Derived, never configured.
//	author           committers over-represented among known fix commits.
//	keyword          the universal security vocabulary.
package fingerprint

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/orcasecurity-research/bgh/internal/ghapi"
	"github.com/orcasecurity-research/bgh/internal/keywords"
	"github.com/orcasecurity-research/bgh/internal/model"
)

// Signal kinds.
const (
	KindGHSA     = "ghsa"
	KindFork     = "private-fork-pr"
	KindTracker  = "tracker"
	KindTaxonomy = "taxonomy"
	KindAuthor   = "author"
	KindKeyword  = "keyword"
)

// VendorKinds are the signals that say the vendor themselves marked a change
// as security work. The universal vocabulary only says the message contained
// likely words.
var VendorKinds = []string{KindTracker, KindGHSA, KindFork}

// IsVendorKind reports whether kind is a vendor signal.
func IsVendorKind(kind string) bool {
	for _, k := range VendorKinds {
		if k == kind {
			return true
		}
	}
	return false
}

// notATracker lists technical tokens that look like tracker references but are not.
var notATracker = map[string]bool{}

func init() {
	for _, w := range strings.Fields(`UTF ISO SHA AES RSA MD RFC HTTP HTTPS TLS SSL
		CVE GHSA UTC GMT EC X IPV OAUTH SAML JSON XML
		HTML CSS ES PY GB MB KB V PART STEP NODE
		CHACHA ED PBKDF HMAC SSH SOC PCI FIPS NIST`) {
		notATracker[w] = true
	}
}

// taxonomyPrefixes are standards taxonomies, not vendor trackers. They are
// high-precision markers of security work and stay usable for enumeration, but
// a commit citing one has not been filed as security work by the vendor, so it
// must not carry a vendor signal. CVE and GHSA are not here: they stay in
// notATracker, since the dedicated ghsa signal already covers them.
var taxonomyPrefixes = map[string]bool{"CWE": true, "CAPEC": true, "OWASP": true}

func signalKindForPrefix(prefix string) string {
	if taxonomyPrefixes[strings.ToUpper(prefix)] {
		return KindTaxonomy
	}
	return KindTracker
}

// IsOrphanGHSA: a GHSA id in a commit message with no advisory of its own on
// this repo. Excludes dependency bumps: dependabot cites the *upstream*
// advisory id, which says nothing about this vendor patching their own code.
func IsOrphanGHSA(message string) bool {
	if !model.GHSARe.MatchString(message) {
		return false
	}
	return !keywords.NegativeRe.MatchString(message)
}

// TierRank orders signal tiers.
var TierRank = map[string]int{"high": 3, "medium": 2, "low": 1, "none": 0}

// Probe is what we looked for and what we found. Printed verbatim on refusal.
type Probe struct {
	Signal    string
	LookedFor string
	Found     string
	OK        bool
}

// Signal is one derived detector.
type Signal struct {
	Name         string
	Kind         string
	Tier         string
	Grep         string // regexp source, matched case-insensitively; "" for none
	Support      int
	BaselineRate float64
	Note         string
	Prefix       string   // tracker prefix
	CorpusHits   int      // tracker corpus hits
	Logins       []string // author logins
	Verified     []string // private-fork verified shas
}

// Rank is the numeric tier.
func (s Signal) Rank() int { return TierRank[s.Tier] }

// KnownFix is a commit provably a security fix.
type KnownFix struct {
	SHA      string
	Commit   model.Commit
	Advisory *model.Advisory
	How      string
}

// Fingerprint is the derived detector for one repository.
type Fingerprint struct {
	Repo          model.RepoRef
	Signals       []Signal
	Probes        []Probe
	KnownFixes    []KnownFix
	BaselineSize  int
	AdvisoryCount int
	PRLowWater    int // 0 when unknown
	Derivable     bool
	Tier          string
	Refusal       string
	OrphanGHSA    []model.Commit
}

// ByKind finds the first signal of a kind.
func (f *Fingerprint) ByKind(kind string) *Signal {
	for i := range f.Signals {
		if f.Signals[i].Kind == kind {
			return &f.Signals[i]
		}
	}
	return nil
}

// HasVendorSignal reports whether any derived signal is a vendor signal.
func (f *Fingerprint) HasVendorSignal() bool {
	for _, s := range f.Signals {
		if IsVendorKind(s.Kind) {
			return true
		}
	}
	return false
}

// Facts is what the API handed over before derivation.
type Facts struct {
	Ref        model.RepoRef
	Meta       model.Meta
	Advisories []model.Advisory
	Commits    []model.Commit
	Truncated  bool
	WindowDays int
	Release    *model.ReleaseTarget
}

// --------------------------------------------------------------- known fixes

// CollectKnownFixes finds commits we can prove are security fixes, plus GHSA
// commits with no advisory. An orphan GHSA commit - a GHSA id in a commit
// message that matches no published advisory - is itself a finding shape: the
// fix shipped, the advisory did not.
func CollectKnownFixes(ctx context.Context, api *ghapi.RepoAPI, advs []model.Advisory, maxLookups int) ([]KnownFix, []model.Commit) {
	idx := ghapi.AdvisoryIndex(advs)
	var fixes []KnownFix
	have := map[string]bool{}
	add := func(c model.Commit, adv *model.Advisory, how string) {
		if !have[c.SHA] {
			have[c.SHA] = true
			fixes = append(fixes, KnownFix{SHA: c.SHA, Commit: c, Advisory: adv, How: how})
		}
	}
	budget := maxLookups
loop:
	for i := range advs {
		adv := &advs[i]
		for _, sha := range adv.FixSHAs {
			if budget <= 0 {
				break loop
			}
			budget--
			if c, _ := api.Commit(ctx, sha); c != nil {
				add(*c, adv, "advisory-references-commit")
			}
		}
		for _, pr := range adv.FixPRs {
			if budget <= 0 {
				break loop
			}
			budget -= 2
			sha, found, _ := api.MergeCommitSHA(ctx, pr)
			if !found || sha == "" {
				continue
			}
			if c, _ := api.Commit(ctx, sha); c != nil {
				add(*c, adv, fmt.Sprintf("advisory-references-PR-#%d", pr))
			}
		}
	}

	// Commit-message citations. Search indexes the default branch only, which
	// is exactly where fixes land first - safe here, never used for deciding
	// release status.
	var orphans []model.Commit
	for _, term := range []string{"GHSA", "CVE"} {
		for _, c := range api.SearchCommits(ctx, term, 2) {
			if cites := ghapi.CitedAdvisories(c.Message, idx); len(cites) > 0 {
				add(c, cites[0], "commit-cites-advisory")
			} else if IsOrphanGHSA(c.Message) {
				orphans = append(orphans, c)
			}
		}
	}
	return fixes, orphans
}

// ------------------------------------------------------------------- signals

func rate(re *regexp.Regexp, corpus []model.Commit) float64 {
	if len(corpus) == 0 {
		return 0
	}
	n := 0
	for _, c := range corpus {
		if re.MatchString(c.Message) {
			n++
		}
	}
	return float64(n) / float64(len(corpus))
}

func support(re *regexp.Regexp, fixes []KnownFix) int {
	n := 0
	for _, f := range fixes {
		if re.MatchString(f.Commit.Message) {
			n++
		}
	}
	return n
}

// trackerCandidates: prefix -> number of distinct numeric suffixes seen, and
// total uses. A real tracker is used with many different numbers; `UTF-8` and
// `SHA-256` always carry the same one, which is what removes them.
func trackerCandidates(messages []string) map[string]map[string]int {
	seen := map[string]map[string]int{}
	for _, msg := range messages {
		for _, m := range model.TrackerRe.FindAllStringSubmatch(msg, -1) {
			prefix, num := strings.ToUpper(m[1]), m[2]
			if notATracker[prefix] || len(prefix) < 2 || len(prefix) > 8 {
				continue
			}
			if seen[prefix] == nil {
				seen[prefix] = map[string]int{}
			}
			seen[prefix][num]++
		}
	}
	out := map[string]map[string]int{}
	for p, c := range seen {
		if len(c) >= 2 {
			out[p] = c
		}
	}
	return out
}

func total(c map[string]int) int {
	n := 0
	for _, v := range c {
		n += v
	}
	return n
}

// DeriveTracker returns all qualifying tracker prefixes, not just the
// strongest. A vendor can run more than one, and keeping only the best silently
// drops every fix filed under the other.
func DeriveTracker(fixes []KnownFix, corpus []model.Commit, probes *[]Probe) []Signal {
	var fixMsgs, corpusMsgs []string
	for _, f := range fixes {
		fixMsgs = append(fixMsgs, f.Commit.Message)
	}
	for _, c := range corpus {
		corpusMsgs = append(corpusMsgs, c.Message)
	}
	fromFixes := trackerCandidates(fixMsgs)
	fromCorpus := trackerCandidates(corpusMsgs)
	cands := map[string]bool{}
	for p := range fromFixes {
		cands[p] = true
	}
	for p, c := range fromCorpus {
		if total(c) >= 3 {
			cands[p] = true
		}
	}
	names := make([]string, 0, len(cands))
	for p := range cands {
		names = append(names, p)
	}
	sort.Strings(names)

	secCorpus := 0
	for _, c := range corpus {
		if hit, _ := keywords.Score(c.Message); hit {
			secCorpus++
		}
	}
	baseRate := 0.0
	if len(corpus) > 0 {
		baseRate = float64(secCorpus) / float64(len(corpus))
	}

	var accepted []Signal
	var rejected []string
	for _, prefix := range names {
		pat := `\b` + regexp.QuoteMeta(prefix) + `-\d{1,6}\b`
		rx := regexp.MustCompile(`(?i)` + pat)
		var hits []model.Commit
		for _, c := range corpus {
			if rx.MatchString(c.Message) {
				hits = append(hits, c)
			}
		}
		r := 0.0
		if len(corpus) > 0 {
			r = float64(len(hits)) / float64(len(corpus))
		}
		sup := support(rx, fixes)
		if r > 0.05 {
			rejected = append(rejected, fmt.Sprintf("%s- (%.1f%% of all commits: general tracker)", prefix, r*100))
			continue
		}
		// Enrichment: do this prefix's commits look like security work?
		secHits := 0
		for _, c := range hits {
			if hit, _ := keywords.Score(c.Message); hit {
				secHits++
			}
		}
		enrich := 0.0
		if len(hits) > 0 {
			enrich = float64(secHits) / float64(len(hits))
		}
		lift := enrich * 10
		if baseRate > 0 {
			lift = enrich / baseRate
		}

		var tier, why string
		switch {
		case sup >= 2:
			tier, why = "high", fmt.Sprintf("cited in %d advisory-linked fix commits", sup)
		case sup == 1 && lift >= 2:
			tier, why = "medium", fmt.Sprintf("cited in 1 advisory-linked fix commit, lift %.1fx", lift)
		case len(hits) >= 3 && lift >= 3 && enrich >= 0.5:
			tier, why = "medium", fmt.Sprintf("corpus-derived: %d commits, %.0f%% security-shaped (%.1fx baseline)",
				len(hits), enrich*100, lift)
		default:
			rejected = append(rejected, fmt.Sprintf("%s- (support=%d, lift=%.1fx)", prefix, sup, lift))
			continue
		}
		kind := signalKindForPrefix(prefix)
		label := "tracker"
		if kind == KindTaxonomy {
			label = "taxonomy"
		}
		accepted = append(accepted, Signal{
			Name: fmt.Sprintf("%s-nnn %s reference", prefix, label), Kind: kind, Tier: tier, Grep: pat,
			Support: sup, BaselineRate: r, Note: why, Prefix: prefix, CorpusHits: len(hits),
		})
	}
	sort.SliceStable(accepted, func(i, j int) bool {
		a, b := accepted[i], accepted[j]
		if a.Rank() != b.Rank() {
			return a.Rank() > b.Rank()
		}
		if a.Support != b.Support {
			return a.Support > b.Support
		}
		return a.CorpusHits > b.CorpusHits
	})

	var found string
	switch {
	case len(accepted) > 0:
		var parts []string
		for _, s := range accepted {
			parts = append(parts, fmt.Sprintf("%s-nnn (%s)", s.Prefix, s.Note))
		}
		found = "derived " + strings.Join(parts, "; ")
	case len(rejected) > 0:
		n := rejected
		if len(n) > 6 {
			n = n[:6]
		}
		found = "no qualifying prefix; considered: " + strings.Join(n, ", ")
	default:
		found = "no PREFIX-nnn token appears with two or more distinct numbers"
	}
	*probes = append(*probes, Probe{
		Signal:    "tracker-prefix",
		LookedFor: "internal tracker tokens (PREFIX-nnn) recurring in security fix commits",
		Found:     found, OK: len(accepted) > 0,
	})
	return accepted
}

// DeriveGHSA derives the GHSA-in-commit-message signal.
func DeriveGHSA(fixes []KnownFix, corpus []model.Commit, orphans []model.Commit, probes *[]Probe) *Signal {
	re := regexp.MustCompile(`(?i)` + model.GHSAPattern)
	sup := support(re, fixes)
	corpusHits := 0
	for _, c := range corpus {
		if IsOrphanGHSA(c.Message) {
			corpusHits++
		}
	}
	tot := sup + len(orphans)
	ok := tot > 0 || corpusHits > 0
	found := "no commit message in the corpus or search index cites a GHSA id"
	if ok {
		found = fmt.Sprintf("%d advisory-linked, %d with no published advisory, %d in the recent window",
			sup, len(orphans), corpusHits)
	}
	*probes = append(*probes, Probe{
		Signal:    "ghsa-merge",
		LookedFor: "commit messages citing a GHSA identifier (private security fork merges)",
		Found:     found, OK: ok,
	})
	if !ok {
		return nil
	}
	br := 0.0
	if len(corpus) > 0 {
		br = float64(corpusHits) / float64(len(corpus))
	}
	return &Signal{
		Name: "GHSA identifier in commit message", Kind: KindGHSA, Tier: "high", Grep: model.GHSAPattern,
		Support: sup, BaselineRate: br,
		Note: fmt.Sprintf("%d such commits found; %d cite no published advisory", tot, len(orphans)),
	}
}

// ForkThreshold is the PR number below which a merge commit's number is
// anomalous relative to the public sequence: half the window's low-water mark.
func ForkThreshold(lowWater int) int {
	t := int(float64(lowWater) * 0.5)
	if t < 1 {
		t = 1
	}
	return t
}

// DerivePrivateFork: private security forks number PRs from 1, far below the
// public sequence. Returns the signal (nil if none) and the window's lowest
// merged PR number (0 if there are no merge commits).
func DerivePrivateFork(ctx context.Context, api *ghapi.RepoAPI, fixes []KnownFix, corpus []model.Commit, probes *[]Probe) (*Signal, int) {
	lowWater, high := 0, 0
	for _, c := range corpus {
		if n := c.MergePR(); n > 0 {
			if lowWater == 0 || n < lowWater {
				lowWater = n
			}
			if n > high {
				high = n
			}
		}
	}
	var suspects []model.Commit
	if lowWater > 0 {
		th := ForkThreshold(lowWater)
		for _, c := range corpus {
			if n := c.MergePR(); n > 0 && n < th {
				suspects = append(suspects, c)
			}
		}
	}
	for _, f := range fixes {
		if f.Commit.MergePR() > 0 {
			suspects = append(suspects, f.Commit)
		}
	}

	type hit struct{ sha, why string }
	var verified []hit
	checked := 0
	seen := map[string]bool{}
	for _, c := range suspects {
		if seen[c.SHA] || checked >= 25 {
			continue
		}
		seen[c.SHA] = true
		checked++
		pr := c.MergePR()
		sha, found, err := api.MergeCommitSHA(ctx, pr)
		if err != nil {
			continue
		}
		switch {
		case !found:
			verified = append(verified, hit{c.SHA, fmt.Sprintf("PR #%d does not exist in the public repo", pr)})
		case sha != "" && sha != c.SHA:
			verified = append(verified, hit{c.SHA, fmt.Sprintf("PR #%d merged as %s, not this commit", pr, short(sha))})
		}
	}

	ok := len(verified) > 0
	var found string
	switch {
	case ok:
		found = fmt.Sprintf("%d of %d checked merge commits are unresolvable (public PR range in window: #%d-#%d)",
			len(verified), checked, lowWater, high)
	case checked > 0:
		found = fmt.Sprintf("checked %d merge commits, all resolve to public PRs", checked)
	default:
		found = "no 'Merge pull request #N' commits in the corpus"
	}
	*probes = append(*probes, Probe{
		Signal:    "private-fork-pr",
		LookedFor: "merge commits whose PR number does not resolve to a public pull request",
		Found:     found, OK: ok,
	})
	if !ok {
		return nil, lowWater
	}
	var whys []string
	var shas []string
	for i, v := range verified {
		shas = append(shas, v.sha)
		if i < 3 {
			whys = append(whys, v.why)
		}
	}
	br := 0.0
	if len(corpus) > 0 {
		br = float64(len(verified)) / float64(len(corpus))
	}
	return &Signal{
		Name: "private-fork PR number anomaly", Kind: KindFork, Tier: "high",
		Grep: `Merge pull request #\d+`, Support: len(verified), BaselineRate: br,
		Note: strings.Join(whys, "; "), Verified: shas,
	}, lowWater
}

func short(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}

// DeriveAuthors finds committers over-represented among known fix commits.
func DeriveAuthors(fixes []KnownFix, corpus []model.Commit, probes *[]Probe) *Signal {
	const looked = "committers over-represented among known fix commits"
	if len(fixes) < 3 {
		*probes = append(*probes, Probe{"author", looked,
			fmt.Sprintf("only %d known fix commits - too few to calibrate", len(fixes)), false})
		return nil
	}
	// Ordered by first appearance, for a deterministic report.
	var order []string
	fixAuthors := map[string]int{}
	for _, f := range fixes {
		if l := f.Commit.AuthorLogin; l != "" {
			if fixAuthors[l] == 0 {
				order = append(order, l)
			}
			fixAuthors[l]++
		}
	}
	base := map[string]int{}
	totalBase := 0
	for _, c := range corpus {
		if c.AuthorLogin != "" {
			base[c.AuthorLogin]++
			totalBase++
		}
	}
	if totalBase == 0 {
		totalBase = 1
	}
	type pick struct {
		login string
		n     int
		lift  float64
	}
	var picked []pick
	for _, login := range order {
		n := fixAuthors[login]
		if n < 2 {
			continue
		}
		pFix := float64(n) / float64(len(fixes))
		pBase := float64(base[login]+1) / float64(totalBase+1)
		if lift := pFix / pBase; lift >= 3 {
			picked = append(picked, pick{login, n, lift})
		}
	}
	sort.SliceStable(picked, func(i, j int) bool { return picked[i].lift > picked[j].lift })
	ok := len(picked) > 0
	found := "no committer is enriched in the known fix set"
	if ok {
		var parts []string
		for i, p := range picked {
			if i == 4 {
				break
			}
			parts = append(parts, fmt.Sprintf("%s (%d fixes, %.0fx baseline)", p.login, p.n, p.lift))
		}
		found = strings.Join(parts, "; ")
	}
	*probes = append(*probes, Probe{"author", looked, found, ok})
	if !ok {
		return nil
	}
	sig := &Signal{
		Name: "security-fix author enrichment", Kind: KindAuthor, Tier: "low",
		Note: "ranking hint only; never sufficient on its own",
	}
	for _, p := range picked {
		sig.Support += p.n
		sig.Logins = append(sig.Logins, p.login)
	}
	return sig
}

// DeriveKeywords calibrates the universal vocabulary against the known fixes.
func DeriveKeywords(fixes []KnownFix, corpus []model.Commit, probes *[]Probe) Signal {
	matched := 0
	for _, f := range fixes {
		if hit, _ := keywords.Score(f.Commit.Message); hit {
			matched++
		}
	}
	recall := 0.0
	if len(fixes) > 0 {
		recall = float64(matched) / float64(len(fixes))
	}
	corpusRate := 0.0
	if len(corpus) > 0 {
		n := 0
		for _, c := range corpus {
			if hit, _ := keywords.Score(c.Message); hit {
				n++
			}
		}
		corpusRate = float64(n) / float64(len(corpus))
	}
	tier := "low"
	if len(fixes) > 0 && recall >= 0.6 {
		tier = "medium"
	}
	found := fmt.Sprintf("no known fix commits to calibrate against; flags %.1f%% of the corpus", corpusRate*100)
	note := "uncalibrated"
	if len(fixes) > 0 {
		found = fmt.Sprintf("matches %d/%d known fix commits (%.0f%% recall), %.1f%% of the recent corpus",
			matched, len(fixes), recall*100, corpusRate*100)
		note = fmt.Sprintf("%.0f%% recall on known fixes", recall*100)
	}
	*probes = append(*probes, Probe{"keyword", "the universal security vocabulary applied to commit messages", found, true})
	return Signal{
		Name: "security vocabulary", Kind: KindKeyword, Tier: tier, Grep: keywords.GrepPattern,
		Support: matched, BaselineRate: corpusRate, Note: note,
	}
}

// ---------------------------------------------------------------- derivation

// Derive builds the fingerprint for a repository.
func Derive(ctx context.Context, api *ghapi.RepoAPI, facts *Facts) *Fingerprint {
	fixes, orphans := CollectKnownFixes(ctx, api, facts.Advisories, 120)
	corpus := facts.Commits
	var probes []Probe

	sGHSA := DeriveGHSA(fixes, corpus, orphans, &probes)
	trackers := DeriveTracker(fixes, corpus, &probes)
	sFork, lowWater := DerivePrivateFork(ctx, api, fixes, corpus, &probes)
	sAuth := DeriveAuthors(fixes, corpus, &probes)
	sKW := DeriveKeywords(fixes, corpus, &probes)

	var signals []Signal
	for _, s := range []*Signal{sGHSA, sFork, sAuth} {
		if s != nil {
			signals = append(signals, *s)
		}
	}
	signals = append(signals, sKW)
	signals = append(signals, trackers...)
	sort.SliceStable(signals, func(i, j int) bool {
		if signals[i].Rank() != signals[j].Rank() {
			return signals[i].Rank() > signals[j].Rank()
		}
		return signals[i].Support > signals[j].Support
	})

	best, mediums := 0, 0
	for _, s := range signals {
		if s.Rank() > best {
			best = s.Rank()
		}
		if s.Rank() >= 2 {
			mediums++
		}
	}
	derivable := best >= 3 || (best == 2 && len(fixes) >= 3) || (best == 2 && mediums >= 2)
	tier := map[int]string{3: "high", 2: "medium", 1: "low", 0: "none"}[best]

	fp := &Fingerprint{
		Repo: facts.Ref, Signals: signals, Probes: probes, KnownFixes: fixes,
		BaselineSize: len(corpus), AdvisoryCount: len(facts.Advisories),
		PRLowWater: lowWater, Derivable: derivable, Tier: tier, OrphanGHSA: orphans,
	}
	if !derivable {
		fp.Refusal = RefusalText(facts, fp)
	}
	return fp
}

// RefusalText explains exactly what was looked for and not found.
func RefusalText(facts *Facts, fp *Fingerprint) string {
	lines := []string{
		fmt.Sprintf("No security-commit fingerprint is derivable for %s.", facts.Ref.Slug()),
		"",
		fmt.Sprintf("  published advisories on this repository : %d", len(facts.Advisories)),
		fmt.Sprintf("  advisory-linked fix commits recovered   : %d", len(fp.KnownFixes)),
		fmt.Sprintf("  default-branch commits sampled          : %d (last %d days)", len(facts.Commits), facts.WindowDays),
		"",
		"Signals looked for:",
	}
	for _, p := range fp.Probes {
		mark := "MISSING"
		if p.OK {
			mark = "found  "
		}
		lines = append(lines, fmt.Sprintf("  [%s] %s: %s", mark, p.Signal, p.LookedFor),
			"            -> "+p.Found)
	}
	lines = append(lines, "",
		"A scan would enumerate candidates it cannot rank, so it is refused.",
		"This is not a clean bill of health - it means the repository was never searched.")
	return strings.Join(lines, "\n")
}

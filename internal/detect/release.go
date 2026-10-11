package detect

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/orcasecurity-research/bgh/internal/gitrepo"
	"github.com/orcasecurity-research/bgh/internal/model"
	"github.com/orcasecurity-research/bgh/internal/signature"
)

func mustCI(pattern string) *regexp.Regexp {
	return regexp.MustCompile(`(?i)` + pattern)
}

// Tree is a ref's file list: path -> blob oid, plus the paths in sorted order
// so candidate ranking is deterministic.
type Tree struct {
	Oid   map[string]string
	Paths []string
}

// NewTree indexes a path->oid map.
func NewTree(idx map[string]string) *Tree {
	t := &Tree{Oid: idx, Paths: make([]string, 0, len(idx))}
	for p := range idx {
		t.Paths = append(t.Paths, p)
	}
	sort.Strings(t.Paths)
	return t
}

// Has reports whether the tree holds path.
func (t *Tree) Has(path string) bool { _, ok := t.Oid[path]; return ok }

// ------------------------------------------------------------- file location

// nameSimilarity is difflib.SequenceMatcher(None, a, b).ratio() over
// lowercased runes: 2*M/T, where M is the matched characters of the recursive
// longest-common-block decomposition.
func nameSimilarity(a, b string) float64 {
	ra, rb := []rune(strings.ToLower(a)), []rune(strings.ToLower(b))
	if len(ra)+len(rb) == 0 {
		return 1
	}
	return 2 * float64(matchedRunes(ra, rb, 0, len(ra), 0, len(rb))) / float64(len(ra)+len(rb))
}

func matchedRunes(a, b []rune, alo, ahi, blo, bhi int) int {
	besti, bestj, bestk := alo, blo, 0
	prev := map[int]int{}
	for i := alo; i < ahi; i++ {
		cur := map[int]int{}
		for j := blo; j < bhi; j++ {
			if a[i] != b[j] {
				continue
			}
			k := prev[j-1] + 1
			cur[j] = k
			if k > bestk {
				besti, bestj, bestk = i-k+1, j-k+1, k
			}
		}
		prev = cur
	}
	if bestk == 0 {
		return 0
	}
	return bestk + matchedRunes(a, b, alo, besti, blo, bestj) +
		matchedRunes(a, b, besti+bestk, ahi, bestj+bestk, bhi)
}

func pathDistance(a, b string) int {
	pa, pb := strings.Split(a, "/"), strings.Split(b, "/")
	common := 0
	for i := 0; i < len(pa) && i < len(pb); i++ {
		if pa[i] == pb[i] {
			common++
		}
	}
	return len(pa) + len(pb) - 2*common
}

type guess struct{ path, how string }

// CandidatePaths lists where this code might live at a ref, best guess first.
// Reads nothing.
//
// A refactor can move a file, and a path-pinned check then falsely flags the
// tag as vulnerable. So the original path is only the first guess, and a file
// that moved or was renamed is followed by name rather than given up on.
func CandidatePaths(tree *Tree, sig *signature.FixSignature, limit int) []guess {
	var out []guess
	seen := map[string]bool{}
	add := func(path, how string) {
		if path != "" && tree.Has(path) && !seen[path] {
			seen[path] = true
			out = append(out, guess{path, how})
		}
	}
	add(sig.Path, "same path")
	add(sig.OldPath, "pre-fix path")

	base := sig.Basename()
	var sameBase []string
	for _, p := range tree.Paths {
		if p[strings.LastIndexByte(p, '/')+1:] == base && !seen[p] {
			sameBase = append(sameBase, p)
		}
	}
	sort.SliceStable(sameBase, func(i, j int) bool {
		return pathDistance(sameBase[i], sig.Path) < pathDistance(sameBase[j], sig.Path)
	})
	for i, p := range sameBase {
		if i == 2 {
			break
		}
		add(p, fmt.Sprintf("moved: %s at a different path", base))
	}

	dir := ""
	if i := strings.LastIndexByte(sig.Path, '/'); i >= 0 {
		dir = sig.Path[:i]
	}
	if dir != "" && len(out) < limit {
		type sib struct {
			p     string
			score float64
		}
		var sibs []sib
		for _, p := range tree.Paths {
			if strings.HasPrefix(p, dir+"/") && !seen[p] {
				sibs = append(sibs, sib{p, nameSimilarity(p[strings.LastIndexByte(p, '/')+1:], base)})
			}
		}
		sort.SliceStable(sibs, func(i, j int) bool { return sibs[i].score > sibs[j].score })
		room := limit - len(out)
		for i, s := range sibs {
			if i == room {
				break
			}
			// Below this the name resemblance is coincidence, and each guess
			// costs a network read that will not settle anything.
			if s.score >= 0.65 {
				add(s.p, fmt.Sprintf("renamed within %s (%.0f%% name match)", dir, s.score*100))
			}
		}
	}
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

// noCandidateFile means the fix's code could not be found in a ref's tree. It
// becomes UNRESOLVED, never a gap.
type noCandidateFile struct{ reason, how string }

func (e *noCandidateFile) Error() string { return e.reason }

// located is the result of finding where a fix's code lives at a ref.
type located struct {
	path, how string
	presence  *signature.Presence
	idents    bool
}

// reader reads a file at the release tag.
type reader func(ctx context.Context, path string) (string, bool, error)

// locateInRef finds where this fix's code lives at the ref, and tests what is
// there. The hard part - surviving a refactor that moved the file, and not
// being fooled by a shim left at the old path - is what this exists for.
//
// Guesses are read best-first, keeping whichever carries the most evidence
// either way, stopping as soon as one is conclusive: later guesses exist only
// for the case where the file moved, and each read is a network call.
//
// On the context path every guess is read and the symbol decides, because a
// context ratio scores high on generic surrounding code: a shim left at the old
// path, holding none of the guarded function, scores 1.00 on the pre-fix shape
// and would stop the loop and be reported as a gap against its own path.
// Ranking on the symbol first is not a new rule: StillVulnerable already
// refuses the context path without it.
func locateInRef(ctx context.Context, read reader, tree *Tree, sig *signature.FixSignature) (*located, error) {
	guesses := CandidatePaths(tree, sig, 4)
	if len(guesses) == 0 {
		return nil, &noCandidateFile{reason: fmt.Sprintf("%s is absent and no similarly named file exists here", sig.Path)}
	}
	contextPath := sig.VulnShapeKind() == signature.ShapeContext
	identsNearby := false
	var best *located
	var bestRank [2]float64
	for _, g := range guesses {
		content, ok, err := read(ctx, g.path)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		pres := signature.TestPresence(content, sig)
		identsNearby = identsNearby || pres.IdentifiersPresent
		ratio := pres.FixRatio
		if pres.VulnRatio > ratio {
			ratio = pres.VulnRatio
		}
		rank := [2]float64{0, ratio}
		if contextPath && pres.SymbolPresent {
			rank[0] = 1
		}
		if best == nil || rank[0] > bestRank[0] || (rank[0] == bestRank[0] && rank[1] > bestRank[1]) {
			best, bestRank = &located{path: g.path, how: g.how, presence: pres}, rank
		}
		if pres.Verdict == signature.FixPresent {
			break
		}
		// Removed lines are absent from a patched file by construction, so a
		// high ratio there is conclusive and the early stop stays.
		if !contextPath && rank[1] >= 0.6 {
			break
		}
	}
	if best == nil {
		return nil, &noCandidateFile{reason: "candidate files could not be read", how: guesses[0].how}
	}
	best.idents = identsNearby
	return best, nil
}

// ------------------------------------------------------------- release test

func daysBetween(a, b time.Time) int {
	d := a.Sub(b)
	if d < 0 {
		d = -d
	}
	return int(d.Hours() / 24)
}

// CheckRelease asks: does the version people can download lack this fix, with
// the bug still in it?
//
// Two conditions and one ref. There is deliberately no third condition about
// whether a release shipped after the fix: a fix public on the default branch
// that no release carries is a finding on the same terms as one the vendor
// shipped past six times, because in both cases what you can download lacks
// it. ShippedSinceFix records which it was and decides nothing.
//
// Ancestry first because it is free and exact. Everything after it exists
// because a backport can rewrite the sha - a cherry-pick, a re-implementation -
// and ancestry can then only ever answer "unreachable", which is also what it
// answers when the tag genuinely predates the fix. Only the file separates them.
func CheckRelease(ctx context.Context, repo *gitrepo.Repo, target model.ReleaseTarget, cand *Candidate,
	tree *Tree, read reader) (*ReleaseFinding, error) {
	sha := cand.Commit.SHA
	sig := cand.Signature
	fixDate := cand.Date()
	var shipped *bool
	if !fixDate.IsZero() {
		v := !target.Published.Before(fixDate)
		shipped = &v
	}
	newFinding := func(status, note string) *ReleaseFinding {
		return &ReleaseFinding{Ref: target.Tag, Status: status, Note: note, Published: target.Published,
			ShippedSinceFix: shipped, DaysPublic: -1}
	}

	if repo.IsAncestor(ctx, sha, tagRef(target.Tag)) {
		return newFinding(StatusBackported, "the release contains the fix commit itself"), nil
	}
	if sig == nil || !sig.Usable() {
		return newFinding(StatusUnresolved, "no testable signature could be built from the diff"), nil
	}

	loc, err := locateInRef(ctx, read, tree, sig)
	if err != nil {
		var nc *noCandidateFile
		if errors.As(err, &nc) {
			f := newFinding(StatusUnresolved, fmt.Sprintf("%s at %s", nc.reason, target.Tag))
			f.HowLocated = nc.how
			return f, nil
		}
		return nil, err
	}
	p := loc.presence
	// On the context path a name the fix introduced may have landed in a
	// neighbouring file, which means this release carries a reworded version
	// rather than nothing at all.
	if sig.VulnShapeKind() == signature.ShapeContext && loc.idents {
		p.IdentifiersPresent = true
	}

	f := newFinding(StatusUnresolved, "")
	f.Path, f.HowLocated, f.Presence = loc.path, loc.how, p
	if !fixDate.IsZero() {
		f.DaysPublic = daysBetween(time.Now(), fixDate)
	}

	switch p.Verdict {
	case signature.FixPresent:
		f.Status = StatusBackported
		f.Note = fmt.Sprintf("fix content present in %s at %s (%.0f%% of added lines)", loc.path, target.Tag, p.FixRatio*100)
		return f, nil
	case signature.Ambiguous:
		f.Status = StatusInconclusive
		f.Note = fmt.Sprintf("partial match in %s at %s: %.0f%% of the fix present, %.0f%% of the pre-fix %s still there",
			loc.path, target.Tag, p.FixRatio*100, p.VulnRatio*100, p.VulnShapeKind)
		return f, nil
	}

	// fix-absent. A gap only if the pre-fix shape is positively still present,
	// to the standard set by which shape it is - StillVulnerable owns that.
	f.VulnEvidence = p.VulnShapeKind
	if !p.StillVulnerable() {
		switch {
		case p.VulnShapeKind == signature.ShapeNone:
			f.Note = fmt.Sprintf("fix absent from %s at %s, but no testable pre-fix shape could be built from the diff - its absence cannot be confirmed as exposure",
				loc.path, target.Tag)
		case p.VulnShapeKind == signature.ShapeContext && p.IdentifiersPresent:
			f.Note = fmt.Sprintf("fix absent from %s at %s as written, but a name the fix introduced is present - this release may carry a reworded version of it",
				loc.path, target.Tag)
		default:
			f.Note = fmt.Sprintf("fix absent from %s at %s, but only %.0f%% of the pre-fix %s is present - this code has diverged, not regressed",
				loc.path, target.Tag, p.VulnRatio*100, p.VulnShapeKind)
		}
		return f, nil
	}

	f.Status = StatusGap
	since := "no release has shipped since the fix"
	if shipped != nil && *shipped {
		since = "a release has shipped since the fix"
	}
	f.Note = fmt.Sprintf("%s at %s lacks the fix (%.0f%% present) and still carries the pre-fix code (%.0f%%); %s was published %s and %s",
		loc.path, target.Tag, p.FixRatio*100, p.VulnRatio*100, target.Tag, target.Published.Format("2006-01-02"), since)
	return f, nil
}

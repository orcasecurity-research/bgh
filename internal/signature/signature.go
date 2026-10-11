// Package signature turns a fix commit into something testable against
// arbitrary file contents.
//
// Backport status is decided by reading files at the release tag, never by
// searching commit history: GitHub's commit search indexes the default branch
// only, and trusting it once produced a false "not backported" claim.
//
// A signature carries four things, and they are not symmetric in what they
// prove.
//
//	Added          the fix as written. Present at the tag means patched.
//	Removed        the pre-fix shape, for a fix that deleted something. Still
//	               present means still exposed.
//	ContextCode    the fallback pre-fix shape for a fix that deletes nothing,
//	               which is the commonest shape of a security fix: a guard put
//	               in front of code that already worked. The shape is then the
//	               code the guard protects.
//	FixIdentifiers the distinctive names the fix introduced.
//
// Requiring Added absent AND a pre-fix shape present is what separates a real
// gap from a tag whose code simply moved. A removed line is absent from a
// patched file by construction, so finding it is evidence by itself. A
// context line survives the patch, so a tag carrying a reworded backport
// matches the whole shape perfectly: there the ratio only says "right
// neighbourhood", and FixIdentifiers carries the rest - a reworded backport
// can restructure a guard, but it cannot invent new names for the allowlist it
// checks or the error it raises.
//
// Presence.StillVulnerable holds the resulting rule - one standard per shape -
// and is the only thing that should be asked whether a tag is exposed.
//
// Every threshold here errs towards refusing to decide, because the errors are
// not symmetric: a gap that turns out not to be real costs more to withdraw
// than any number of gaps found late.
package signature

import (
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/orcasecurity-research/bgh/internal/keywords"
)

// SkipPath excludes paths whose changes say nothing about the vendor's own
// shipped code: tests, docs, vendored code, dependency manifests, lockfiles
// and CI config.
//
// Dependency manifests are excluded because a fix that only bumps a pinned
// version patches a vulnerable dependency, not a gap in the vendor's own code.
// CI configuration does not ship in a release. `dev`, `bench` and friends are
// here because a benchmark harness can survive the filter, win the salience
// ranking and make the whole determination about a file that does not ship.
//
// `scripts` and `tools` are deliberately NOT here: plenty of projects ship
// real code from them, and excluding a shipped fix is the more expensive error.
var SkipPath = regexp.MustCompile(`(?i)(^|/)(tests?|spec|specs|__tests__|e2e|fixtures?|testdata|snapshots?|` +
	`docs?|examples?|vendor|third_party|node_modules|locales?|i18n|translations?|` +
	`dev|benchmarks?|bench|demos?|samples?|` +
	`\.github)(/|$)` +
	`|\.(md|rst|txt|lock|sum|snap|po|pot|svg|png|jpg|gif|map|gradle)$` +
	`|(^|/)(CHANGELOG|CHANGES|NEWS|AUTHORS|package-lock\.json|yarn\.lock|` +
	`pnpm-lock\.yaml|Gemfile\.lock|poetry\.lock|go\.sum|pyproject\.toml|` +
	`package\.json|requirements[\w.-]*\.txt|go\.mod|Cargo\.toml|pom\.xml)`)

var (
	trivialRe = regexp.MustCompile(`^[\s{}()\[\];,.:]*$`)
	commentRe = regexp.MustCompile(`^\s*(//|#|/\*|\*|--|;;)`)
	importRe  = regexp.MustCompile(`^\s*(import|from|require|use|using|#include|package)\b`)
)

// salientStem matches the vocabulary at a position. Go has no look-behind, so
// the word-start rule is applied by hand in Salient.
//
// A salient word may only start where an identifier word starts. Without that
// these are substrings and the match tells you nothing: de*sign*Tokens,
// as*sign*ee and in*valid*ateCache all scored as security vocabulary. Not plain
// \b, because the stems are prefixes on purpose (`perm` has to reach
// `permission`) and `_` is a word character (`has_permission`).
var salientStem = regexp.MustCompile(`(?i)^(?:perm|priv|auth|acl|role|admin|owner|can[-_]?(?:read|write|edit|view)|` +
	`escap|sanitiz|valid|check|assert|throw|raise|deny|forbid|reject|revoke|` +
	`403|401|unauthor|forbidden|token|secret|sign|verify|allow|filter|guard)`)

func isAlnum(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}

// wordStart: preceded by nothing alphanumeric (`has_permission`, `.filter(`),
// or sitting on a camelCase hump (`hasPermission`).
func wordStart(s string, i int) bool {
	if i == 0 {
		return true
	}
	prev := s[i-1]
	if !isAlnum(prev) {
		return true
	}
	return (prev >= 'a' && prev <= 'z' || prev >= '0' && prev <= '9') && s[i] >= 'A' && s[i] <= 'Z'
}

// Salient reports whether s contains security vocabulary at a word start.
func Salient(s string) bool {
	for i := 0; i < len(s); i++ {
		if wordStart(s, i) && salientStem.MatchString(s[i:]) {
			return true
		}
	}
	return false
}

// identifierRe is a distinctive name, long enough not to be incidental.
// Includes `-` for Lisps, where `can-read?` is one identifier. Five
// characters, not eight: eight sat exactly at the length of the names a guard
// is built from (isAdmin is 7), so the gate held `Forbidden` and discarded
// `isAdmin`, which is the shape of a false gap.
var (
	identifierRe = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_\-]{4,}`)
	longIdentRe  = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_\-]{9,}`)
)

// stringLiteralRe: a quoted string is message text for a human, not a name the
// fix introduces. Backticks are here because Go and JS quote with them.
// There is deliberately no single-quote arm: it over-stripped in the direction
// that fabricates gaps (Clojure `'allowed-host 'blocked-host` reads as a
// string, losing the allowlist name).
var stringLiteralRe = regexp.MustCompile("\"(?:\\\\.|[^\"\\\\])*\"|`(?:\\\\.|[^`\\\\])*`")

// identStoplist is language syntax and universal boilerplate only, kept
// minimal on purpose. Keeping a generic token makes identifiers-present
// likelier, which ends in UNRESOLVED: recall lost, nothing claimed. Dropping a
// token the fix really introduced makes identifiers-absent likelier, which
// ends in a gap report. So every entry names nothing, and when in doubt it is
// left out. `require` is not here: Solidity's require() is an access control
// primitive.
var identStoplist = map[string]bool{}

func init() {
	for _, w := range strings.Fields(`function continue interface implements namespace protected
		abstract override constructor undefined instanceof nullptr
		synchronized volatile transient template typename operator
		exception extends readonly internal explicit
		catch throw raise assert class const break while
		yield async await super false static struct switch
		import export lambda module public private package
		typedef define return string print range`) {
		identStoplist[w] = true
	}
}

// ExtractIdentifiers lists the distinctive names a fix introduced, read off
// its added lines.
//
// `borrowed` is the names the fix took from the code around it - the context
// and removed lines of its own hunk. They are excluded: a borrowed name is on
// every release, patched or not, so it is evidence of nothing, and keeping it
// made the gate tautological.
//
// Within the remaining set, still err towards collecting, and deliberately
// uncapped: dropping an identifier makes "no identifier present" likelier,
// which pushes towards a fabricated gap. Sorted for a stable report.
func ExtractIdentifiers(lines []string, borrowed map[string]bool) []string {
	seen := map[string]bool{}
	for _, line := range lines {
		if !Interesting(line) || commentRe.MatchString(line) || IsProse(line) {
			continue
		}
		code := stringLiteralRe.ReplaceAllString(line, " ")
		for _, tok := range identifierRe.FindAllString(code, -1) {
			if identStoplist[strings.ToLower(tok)] || borrowed[tok] {
				continue
			}
			seen[tok] = true
		}
	}
	out := make([]string, 0, len(seen))
	for t := range seen {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// Normalize is the whitespace-insensitive form of a line, so reindentation on
// a release is not a mismatch.
func Normalize(line string) string {
	return strings.Join(strings.Fields(line), " ")
}

// Interesting filters out blank, trivial, short and import lines.
func Interesting(line string) bool {
	n := strings.TrimSpace(line)
	if n == "" || trivialRe.MatchString(n) || utf8.RuneCountInString(Normalize(n)) < 8 {
		return false
	}
	return !importRe.MatchString(n)
}

var codeCharsRe = regexp.MustCompile(`[(){}\[\];=<>+\-*/%&|!~^]`)

// codeShapeRe: a line that opens with a statement keyword is code, whatever
// its punctuation. `if hostname not in ALLOWED_DOWNLOAD_HOSTS:` carries no
// operator characters and reads as four alphabetic words, so a pure shape test
// called it prose and dropped the canonical shape of an added guard.
// Case-sensitive on purpose: keywords are lowercase, so a docstring sentence
// beginning "If the user..." is still prose.
var codeShapeRe = regexp.MustCompile(`^\s*(if|elif|else|for|while|return|raise|throw|assert|def|fn|func|class` +
	`|import|package|switch|case|try|catch|except|finally|with` +
	`|yield|await|let|var|const|val|public|private|protected|static|unless` +
	`|when|require|panic)\b`)

// sentenceEndRe: ... unless the line finishes a sentence. Code does not end in
// sentences; prose does.
var sentenceEndRe = regexp.MustCompile(`[a-z]\.\s*$`)

var emphasisRe = regexp.MustCompile("[*`_]+(\\w[\\w '-]*)[*`_]+")

// ReadsAsProse is the shape test on its own: four or more words, almost all
// alphabetic, barely any operator characters. Split out from IsProse so the
// CODE_SHAPE short-circuit can override admission without overriding the
// weighting.
func ReadsAsProse(line string) bool {
	n := Normalize(line)
	words := strings.Fields(n)
	if len(words) < 4 {
		return false
	}
	// `*every*` and `user-id` in backticks are emphasis in a docstring, not
	// operators.
	n = emphasisRe.ReplaceAllString(n, "${1}")
	if len(codeCharsRe.FindAllString(n, -1)) > 1 {
		return false
	}
	alpha := 0
	for _, w := range words {
		w = strings.Trim(w, "`'\"*,.-")
		if w != "" && strings.IndexFunc(w, func(r rune) bool { return !unicode.IsLetter(r) }) < 0 {
			alpha++
		}
	}
	return float64(alpha)/float64(len(words)) >= 0.7
}

// IsProse is true for natural-language text: docstrings, and comments without
// a marker. A fix's docstring is tempting to match on, but it is not the fix:
// prose is useful for locating code, never evidence about whether it was
// patched.
func IsProse(line string) bool {
	if codeShapeRe.MatchString(line) && !sentenceEndRe.MatchString(line) {
		return false
	}
	return ReadsAsProse(line)
}

// Distinctiveness weights a line: longer, security-flavoured and
// identifier-rich lines carry more.
//
// Weighted on ReadsAsProse, not IsProse: IsProse asks whether a line may be
// evidence; ranking asks which line should carry the most weight, and
// admitting a line is no reason to rank it first.
func Distinctiveness(line string) float64 {
	n := Normalize(line)
	l := utf8.RuneCountInString(n)
	if l > 120 {
		l = 120
	}
	score := float64(l) / 120
	if Salient(n) {
		score += 0.6
	}
	if longIdentRe.MatchString(n) {
		score += 0.3
	}
	if commentRe.MatchString(line) || ReadsAsProse(line) {
		score -= 0.5
	}
	return score
}

// ------------------------------------------------------------------ diff parse

// Hunk is one `@@` block. Kept separate because context is only meaningful
// locally.
type Hunk struct {
	Header  string
	Added   []string
	Removed []string
	Context []string
}

// FileDiff is one file's changes in a patch.
type FileDiff struct {
	OldPath string
	NewPath string
	Added   []string
	Removed []string
	Context []string
	Renamed bool
	Hunks   []Hunk
}

// Path is the new path, or the old one for a deleted file.
func (f *FileDiff) Path() string {
	if f.NewPath != "/dev/null" {
		return f.NewPath
	}
	return f.OldPath
}

var (
	diffGitRe = regexp.MustCompile(`^diff --git a/(.+?) b/(.+)$`)
	hunkRe    = regexp.MustCompile(`^@@ -\S+ \+\S+ @@ ?(.*)$`)
)

// ParsePatch splits a unified diff into per-file changes.
func ParsePatch(patch string) []*FileDiff {
	var files []*FileDiff
	var cur *FileDiff
	for _, line := range strings.Split(patch, "\n") {
		line = strings.TrimSuffix(line, "\r")
		if strings.HasPrefix(line, "diff --git ") {
			if m := diffGitRe.FindStringSubmatch(line); m != nil {
				cur = &FileDiff{OldPath: m[1], NewPath: m[2]}
			} else {
				cur = &FileDiff{}
			}
			files = append(files, cur)
			continue
		}
		if cur == nil {
			continue
		}
		inHunk := len(cur.Hunks) > 0
		switch {
		case !inHunk && (strings.HasPrefix(line, "rename from ") || strings.HasPrefix(line, "rename to ")):
			cur.Renamed = true
		// File headers only count before the first hunk: inside one, a removed
		// line that reads `-- note` is content, not a header.
		case !inHunk && strings.HasPrefix(line, "--- "):
			cur.OldPath = strings.TrimPrefix(strings.TrimSpace(line[4:]), "a/")
		case !inHunk && strings.HasPrefix(line, "+++ "):
			cur.NewPath = strings.TrimPrefix(strings.TrimSpace(line[4:]), "b/")
		case strings.HasPrefix(line, "@@"):
			h := Hunk{}
			if m := hunkRe.FindStringSubmatch(line); m != nil {
				h.Header = strings.TrimSpace(m[1])
			}
			cur.Hunks = append(cur.Hunks, h)
		case !inHunk:
			// Metadata before the first hunk (index, mode lines).
		case strings.HasPrefix(line, "+"):
			cur.Added = append(cur.Added, line[1:])
			last := &cur.Hunks[len(cur.Hunks)-1]
			last.Added = append(last.Added, line[1:])
		case strings.HasPrefix(line, "-"):
			cur.Removed = append(cur.Removed, line[1:])
			last := &cur.Hunks[len(cur.Hunks)-1]
			last.Removed = append(last.Removed, line[1:])
		case strings.HasPrefix(line, " "):
			cur.Context = append(cur.Context, line[1:])
			last := &cur.Hunks[len(cur.Hunks)-1]
			last.Context = append(last.Context, line[1:])
		}
	}
	return files
}

// -------------------------------------------------------------------- signature

// FixSignature describes a fix well enough to test for elsewhere.
//
// Added and Removed are file-wide, while ContextCode, Symbol and the
// borrowed-name pool come from the fix's own hunk. That is deliberate. A
// pre-fix shape has to come from one hunk or a second, unrelated hunk supplies
// it and the ratio stops meaning anything about the code the fix touched. But
// Added answers "is any part of this fix here", and a multi-hunk fix that was
// backported in part is exactly the release worth catching.
type FixSignature struct {
	Path           string
	OldPath        string
	Added          []string
	Removed        []string
	Symbol         string
	Renamed        bool
	AllPaths       []string
	SkippedPaths   []string
	ContextCode    []string
	FixIdentifiers []string
}

// Basename is the final path element.
func (s *FixSignature) Basename() string {
	if i := strings.LastIndexByte(s.Path, '/'); i >= 0 {
		return s.Path[i+1:]
	}
	return s.Path
}

// KeyLine is the most distinctive added line.
func (s *FixSignature) KeyLine() string {
	return maxByDistinctiveness(s.Added)
}

func maxByDistinctiveness(lines []string) string {
	best, bestScore := "", -1e9
	for i, l := range lines {
		if sc := Distinctiveness(l); i == 0 || sc > bestScore {
			best, bestScore = l, sc
		}
	}
	return best
}

// Block is the added lines, normalised and joined.
func (s *FixSignature) Block() string {
	n := make([]string, len(s.Added))
	for i, l := range s.Added {
		n[i] = Normalize(l)
	}
	return strings.Join(n, "\n")
}

// Usable: enough distinctive added content to test for elsewhere.
func (s *FixSignature) Usable() bool {
	if len(s.Added) == 0 {
		return false
	}
	return len(s.Added) >= 2 || utf8.RuneCountInString(Normalize(s.KeyLine())) >= 24
}

// VulnShape is the pre-fix shape to test for at a release. Normally the
// removed lines; for a fix that adds a guard and removes nothing, the code the
// guard protects.
func (s *FixSignature) VulnShape() []string {
	if len(s.Removed) > 0 {
		return s.Removed
	}
	return s.ContextCode
}

// Shape kinds.
const (
	ShapeRemoved = "removed"
	ShapeContext = "context"
	ShapeNone    = "none"
)

// VulnShapeKind says which pre-fix shape a signature carries. The context
// shape needs two discriminators, and refuses without them: a name to look for
// (else an unpatched release cannot be told from one carrying a reworded
// fix) and an enclosing symbol (else the function the fix touched cannot be
// told from a file that merely shares boilerplate).
func (s *FixSignature) VulnShapeKind() string {
	if len(s.Removed) > 0 {
		return ShapeRemoved
	}
	if len(s.ContextCode) > 0 && len(s.FixIdentifiers) > 0 && s.Symbol != "" {
		return ShapeContext
	}
	return ShapeNone
}

func hunkWeight(h Hunk) float64 {
	var w float64
	for _, l := range h.Added {
		if Interesting(l) {
			w += Distinctiveness(l)
		}
	}
	return w
}

// Salience scores how well a file diff represents the fix.
func Salience(fd *FileDiff) float64 {
	text := strings.Join(append(append([]string{}, fd.Added...), fd.Removed...), "\n")
	hit, _ := keywords.Score(text)
	nInt := 0
	var sum float64
	for _, l := range fd.Added {
		if Interesting(l) {
			nInt++
			sum += Distinctiveness(l)
		}
	}
	denom := nInt
	if denom < 1 {
		denom = 1
	}
	if nInt > 10 {
		nInt = 10
	}
	s := sum/float64(denom) + float64(nInt)*0.1
	if hit {
		s += 3.0
	}
	return s
}

// --------------------------------------------------------------- diff evidence

// Directions of a change.
const (
	Hardening = "hardening"
	Loosening = "loosening"
	Neutral   = "neutral"
)

// DiffEvidence is security relevance read off the diff rather than the commit
// message. The message says what the author called the change; the diff says
// what it does. A subject line saying "fix permission" covers both adding a
// check and removing one, and one of those is the opposite of a security fix:
// when salient lines leave, the direction is Loosening, and the unpatched
// release is strictly more restrictive - calling its lack of the change a gap
// would be backwards.
//
// What it does not catch: a widening written as an ADDED permission check
// against a blanket refusal reads Hardening. Telling that apart needs the
// meaning of the code the check replaces, which no count of lines carries.
type DiffEvidence struct {
	AddedSalient   int
	RemovedSalient int
	StrongHit      bool
	Direction      string
}

func keptFiles(patch string) []*FileDiff {
	var kept []*FileDiff
	for _, fd := range ParsePatch(patch) {
		if fd.Path() == "" || SkipPath.MatchString(fd.Path()) {
			continue
		}
		if len(fd.Added) > 0 || len(fd.Removed) > 0 {
			kept = append(kept, fd)
		}
	}
	return kept
}

func primaryFile(kept []*FileDiff) *FileDiff {
	var best *FileDiff
	var bestS float64
	for i, fd := range kept {
		if s := Salience(fd); i == 0 || s > bestS {
			best, bestS = fd, s
		}
	}
	return best
}

// GradeDiff grades the same file BuildSignature will describe. Empty evidence
// for a commit that touches only skipped paths, rather than a guess either
// way. The unit is the line; its failure mode is re-wrapping, where a join
// reads Loosening and suppresses (safe) while a split reads Hardening.
func GradeDiff(patch string) DiffEvidence {
	kept := keptFiles(patch)
	if len(kept) == 0 {
		return DiffEvidence{Direction: Neutral}
	}
	primary := primaryFile(kept)
	count := func(lines []string) int {
		n := 0
		for _, l := range lines {
			if Interesting(l) && Salient(l) {
				n++
			}
		}
		return n
	}
	added, removed := count(primary.Added), count(primary.Removed)
	strong, _ := keywords.Score(strings.Join(append(append([]string{}, primary.Added...), primary.Removed...), "\n"))
	dir := Neutral
	switch {
	case added > removed:
		dir = Hardening
	case removed > added:
		dir = Loosening
	}
	return DiffEvidence{AddedSalient: added, RemovedSalient: removed, StrongHit: strong, Direction: dir}
}

// BuildSignature picks the file in the commit that best represents the fix,
// and describes it. nil when there is nothing testable.
func BuildSignature(patch string, maxLines int) *FixSignature {
	if maxLines <= 0 {
		maxLines = 14
	}
	var kept []*FileDiff
	var skipped []string
	for _, fd := range ParsePatch(patch) {
		switch {
		case fd.Path() == "" || SkipPath.MatchString(fd.Path()):
			skipped = append(skipped, fd.Path())
		case len(fd.Added) > 0 || len(fd.Removed) > 0:
			kept = append(kept, fd)
		}
	}
	if len(kept) == 0 {
		return nil
	}
	primary := primaryFile(kept)

	// Comment-only lines are excluded from the testable set: they are
	// frequently reworded or dropped when a fix is backported, and their
	// absence is not evidence the fix is missing.
	testable := func(l string) bool {
		return Interesting(l) && !commentRe.MatchString(l) && !IsProse(l)
	}
	filter := func(lines []string) []string {
		var out []string
		for _, l := range lines {
			if testable(l) {
				out = append(out, l)
			}
		}
		return out
	}
	sortDesc := func(lines []string) []string {
		sort.SliceStable(lines, func(i, j int) bool {
			return Distinctiveness(lines[i]) > Distinctiveness(lines[j])
		})
		return lines
	}
	added := sortDesc(filter(primary.Added))
	removed := sortDesc(filter(primary.Removed))

	// The pre-fix shape must come from the hunk the fix is in. Ranking context
	// across the whole file lets an unrelated hunk supply the shape. There is
	// no fallback for a primary file with no such hunk: that fallback was the
	// cross-hunk mismatch this scoping exists to prevent.
	var fixHunk *Hunk
	var bestW float64
	for i := range primary.Hunks {
		h := &primary.Hunks[i]
		if len(h.Added) == 0 {
			continue
		}
		if w := hunkWeight(*h); fixHunk == nil || w > bestW {
			fixHunk, bestW = h, w
		}
	}
	if fixHunk == nil {
		return nil
	}
	ctx := sortDesc(filter(fixHunk.Context))
	if len(ctx) > maxLines {
		ctx = ctx[:maxLines]
	}

	// Names the fix took from the code around it are on every release, patched
	// or not, so they are evidence of nothing. The hunk header is in the pool
	// too: the symbol-present gate asserts the header IS in the file, so a name
	// the guard shares with its own function signature would otherwise be
	// counted as evidence the fix is here.
	pool := append([]string{fixHunk.Header}, fixHunk.Context...)
	pool = append(pool, fixHunk.Removed...)
	borrowed := map[string]bool{}
	for _, id := range ExtractIdentifiers(pool, nil) {
		borrowed[id] = true
	}
	idents := ExtractIdentifiers(added, borrowed)

	if len(added) > maxLines {
		added = added[:maxLines]
	}
	if len(removed) > maxLines {
		removed = removed[:maxLines]
	}
	all := make([]string, len(kept))
	for i, f := range kept {
		all[i] = f.Path()
	}
	return &FixSignature{
		Path: primary.Path(), OldPath: primary.OldPath,
		Added: added, Removed: removed,
		// The symbol must name the function the shape came from, because the
		// symbol-present test is a gate on the context path. Empty header
		// text means the enclosing symbol is unknown, and VulnShapeKind
		// refuses the context path for that rather than guessing.
		Symbol:         fixHunk.Header,
		Renamed:        primary.Renamed,
		AllPaths:       all,
		SkippedPaths:   skipped,
		ContextCode:    ctx,
		FixIdentifiers: idents,
	}
}

// -------------------------------------------------------------------- presence

// Presence verdicts.
const (
	FixPresent = "fix-present"
	FixAbsent  = "fix-absent"
	Ambiguous  = "ambiguous"
)

// Presence is what a file's contents say about a signature.
type Presence struct {
	Verdict      string
	FixRatio     float64
	VulnRatio    float64
	KeyPresent   bool
	BlockPresent bool
	Matched      []string
	Missing      []string
	// These default to refusing: a Presence built without them must not get
	// gap-permitting behaviour.
	VulnShapeKind      string
	SymbolPresent      bool
	IdentifiersPresent bool
}

// StillVulnerable is the single standard for "this file still carries the
// pre-fix code", one per shape.
func (p *Presence) StillVulnerable() bool {
	if p.Verdict != FixAbsent {
		return false
	}
	switch p.VulnShapeKind {
	case ShapeRemoved:
		return p.VulnRatio >= 0.6
	case ShapeContext:
		// The ratio only says "right neighbourhood". Identifier absence is
		// what says "and no version of the fix is here".
		return p.VulnRatio >= 0.75 && p.SymbolPresent && !p.IdentifiersPresent
	}
	return false
}

// TestPresence tests a signature against file contents.
func TestPresence(content string, sig *FixSignature) *Presence {
	rawLines := strings.Split(content, "\n")
	norm := make([]string, len(rawLines))
	lineSet := map[string]bool{}
	for i, l := range rawLines {
		norm[i] = Normalize(l)
		if norm[i] != "" {
			lineSet[norm[i]] = true
		}
	}
	blob := strings.Join(norm, "\n")

	// Distinctiveness-weighted, so a filler line cannot swing the verdict.
	ratio := func(lines []string) (float64, []string, []string) {
		if len(lines) == 0 {
			return 0, nil, nil
		}
		var hit, miss []string
		var hitW, totalW float64
		for _, l := range lines {
			w := Distinctiveness(l)
			if w < 0.1 {
				w = 0.1
			}
			totalW += w
			if lineSet[Normalize(l)] {
				hit = append(hit, l)
				hitW += w
			} else {
				miss = append(miss, l)
			}
		}
		if totalW == 0 {
			return 0, hit, miss
		}
		return hitW / totalW, hit, miss
	}

	fixRatio, matched, missing := ratio(sig.Added)
	vulnRatio, _, _ := ratio(sig.VulnShape())
	idents := false
	for _, id := range sig.FixIdentifiers {
		if strings.Contains(content, id) {
			idents = true
			break
		}
	}
	// "Does the function the fix touched exist here at all?" With no symbol
	// there is nothing to look for, so this answers true - a fail-open, which
	// is why VulnShapeKind refuses the context path outright for a signature
	// with no symbol.
	symbolPresent := true
	if sig.Symbol != "" {
		symbolPresent = strings.Contains(blob, Normalize(sig.Symbol))
	}
	key := ""
	if len(sig.Added) > 0 {
		key = sig.KeyLine()
	}
	keyPresent := key != "" && lineSet[Normalize(key)]
	block := sig.Block()
	blockPresent := block != "" && strings.Contains(blob, block)
	if !blockPresent && key != "" && len(sig.Added) >= 2 {
		// A contiguous run of the two most distinctive added lines is still strong.
		top := append([]string(nil), sig.Added...)
		sort.SliceStable(top, func(i, j int) bool { return Distinctiveness(top[i]) > Distinctiveness(top[j]) })
		blockPresent = strings.Contains(blob, Normalize(top[0])+"\n"+Normalize(top[1]))
	}

	verdict := Ambiguous
	switch {
	case blockPresent || (fixRatio >= 0.6 && keyPresent):
		verdict = FixPresent
	case fixRatio <= 0.25 && !keyPresent:
		verdict = FixAbsent
	}
	return &Presence{
		Verdict: verdict, FixRatio: fixRatio, VulnRatio: vulnRatio,
		KeyPresent: keyPresent, BlockPresent: blockPresent,
		Matched: matched, Missing: missing,
		VulnShapeKind: sig.VulnShapeKind(), SymbolPresent: symbolPresent,
		IdentifiersPresent: idents,
	}
}

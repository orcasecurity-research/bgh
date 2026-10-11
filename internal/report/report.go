// Package report renders a scan outcome two ways: a concise terminal summary
// and a markdown report carrying everything needed to verify each gap, and fix
// it, by hand.
package report

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/orcasecurity-research/bgh/internal/scan"
	"github.com/orcasecurity-research/bgh/internal/signature"
)

// DefaultPath is <owner>-<repo>.md in the working directory.
func DefaultPath(o *scan.Outcome) string {
	return fmt.Sprintf("%s-%s.md", o.Ref.Owner, o.Ref.Name)
}

// Write renders the markdown report to path, creating parent directories.
func Write(path string, o *scan.Outcome, version string) error {
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	return os.WriteFile(path, []byte(Markdown(o, version)), 0o644)
}

// ------------------------------------------------------------------- terminal

// Style paints text for a terminal; the zero Style paints nothing.
type Style struct{ Color bool }

func (s Style) c(code, t string) string {
	if !s.Color {
		return t
	}
	return "\033[" + code + "m" + t + "\033[0m"
}

func (s Style) Bold(t string) string   { return s.c("1", t) }
func (s Style) Dim(t string) string    { return s.c("2", t) }
func (s Style) Red(t string) string    { return s.c("31;1", t) }
func (s Style) Green(t string) string  { return s.c("32;1", t) }
func (s Style) Yellow(t string) string { return s.c("33;1", t) }

// Paint colours a verdict word.
func (s Style) Paint(verdict string) string {
	switch verdict {
	case scan.Gap:
		return s.Red(verdict)
	case scan.NoGap:
		return s.Green(verdict)
	}
	return s.Yellow(verdict)
}

func trunc(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

func fixedDate(t time.Time) string {
	if t.IsZero() {
		return "unknown date"
	}
	return t.Format("2006-01-02")
}

// Terminal prints the concise summary. reportPath may be "" when none was written.
func Terminal(w io.Writer, o *scan.Outcome, reportPath string, st Style) {
	fmt.Fprintf(w, "%s  %s\n", st.Bold("bgh"), o.Ref.Slug())
	if r := o.Result; r != nil && r.Release != nil {
		fmt.Fprintf(w, "  Latest release  %s  (published %s)\n", r.Release.Tag, fixedDate(r.Release.Published))
	}
	mode := "vendor signals (ghsa, tracker, private-fork-pr)"
	if o.Provider != "" {
		mode = "vendor signals + keyword tier, judged by " + o.Provider
	}
	fmt.Fprintf(w, "  Mode            %s\n\n", mode)

	for i, f := range o.Findings {
		c := f.Cand
		fmt.Fprintf(w, "  %s  %s  %s\n", st.Red("GAP"), c.Commit.Short(), trunc(c.Commit.Subject(), 70))
		fmt.Fprintf(w, "       signal: %s; landed %s", strings.Join(c.Signals(), ", "), fixedDate(c.Date()))
		if rf := c.Release; rf != nil {
			if rf.DaysPublic >= 0 {
				fmt.Fprintf(w, " (%d days public)", rf.DaysPublic)
			}
			fmt.Fprintf(w, "\n       %s lacks it", rf.Ref)
			if rf.Path != "" {
				fmt.Fprintf(w, " in %s", rf.Path)
			}
		}
		fmt.Fprintln(w)
		if f.Verdict != nil && f.Verdict.Mechanism != "" {
			fmt.Fprintf(w, "       judge: %s\n", trunc(f.Verdict.Mechanism, 100))
		}
		if i < len(o.Findings)-1 {
			fmt.Fprintln(w)
		}
	}
	if len(o.Findings) > 0 {
		fmt.Fprintln(w)
	}

	fmt.Fprintf(w, "  %s  %s\n", st.Paint(o.Verdict), o.Detail)
	if o.Verdict == scan.NotSearched {
		fmt.Fprintln(w, st.Dim("  NOT SEARCHED is not a clean result: nothing was compared."))
	}
	if o.HiddenNotDefect > 0 {
		fmt.Fprintln(w, st.Dim(fmt.Sprintf("  %d keyword-tier candidate(s) hidden: the judge rated them not a defect.", o.HiddenNotDefect)))
	}
	if o.Unjudged > 0 && o.Verdict != scan.NotSearched {
		fmt.Fprintln(w, st.Dim(fmt.Sprintf("  %d keyword-tier candidate(s) could not be judged and are not shown.", o.Unjudged)))
	}
	if o.QuotaStopped {
		fmt.Fprintln(w, st.Dim("  The AI provider's quota ran out; judging stopped early."))
	}
	if reportPath != "" {
		fmt.Fprintf(w, "  Report: %s\n", reportPath)
	}
}

// ------------------------------------------------------------------- markdown

var evidenceWording = map[string]string{
	signature.ShapeRemoved: "The lines the fix deleted are still present in the file at the Latest release. " +
		"That is direct evidence of the pre-fix code.",
	signature.ShapeContext: "Context match only, which is weaker. The fix deleted no testable line, so what " +
		"this establishes is that the code the fix sat among is still present and no name the fix introduced " +
		"appears anywhere in the file - that no version of the fix is there, not that a deleted vulnerable line survived.",
	signature.ShapeNone: "No testable pre-fix shape could be built from the diff; exposure was not confirmed from file content.",
}

var ratioLabel = map[string]string{
	signature.ShapeRemoved: "Deleted lines still present",
	signature.ShapeContext: "Surrounding context still present",
	signature.ShapeNone:    "Pre-fix shape present",
}

func fence(lines []string, max int) string {
	if len(lines) > max {
		lines = append(append([]string{}, lines[:max]...), fmt.Sprintf("... (%d more)", len(lines)-max))
	}
	for i, l := range lines {
		lines[i] = strings.TrimRight(l, " \t\r")
	}
	return "```\n" + strings.Join(lines, "\n") + "\n```"
}

func codeSpan(s string) string {
	if strings.Contains(s, "`") {
		return "`` " + s + " ``"
	}
	return "`" + s + "`"
}

// Markdown renders the full report.
func Markdown(o *scan.Outcome, version string) string {
	var b strings.Builder
	p := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }
	res := o.Result

	p("# bgh report: %s", o.Ref.Slug())
	p("")
	p("**Verdict: %s** - %s", o.Verdict, o.Detail)
	p("")
	p("| | |")
	p("|---|---|")
	p("| Repository | [%s](https://github.com/%s) |", o.Ref.Slug(), o.Ref.Slug())
	if res != nil && res.Release != nil {
		p("| Latest release | [`%s`](https://github.com/%s/releases/tag/%s), published %s |",
			res.Release.Tag, o.Ref.Slug(), res.Release.Tag, fixedDate(res.Release.Published))
	}
	if res != nil && res.DefaultBr != "" {
		p("| Default branch | `%s` |", res.DefaultBr)
	}
	mode := "default: vendor signals only (ghsa, tracker, private-fork-pr)"
	if o.Provider != "" {
		mode = "`--ai`: vendor signals plus the keyword tier, judged by `" + o.Provider + "`"
	}
	p("| Mode | %s |", mode)
	if res != nil {
		p("| Examined | %d candidate commits, %d silent after removing advisory-linked ones, %d lacking the fix at the Latest release |",
			res.Stats.Candidates, res.Stats.Silent, res.Stats.Exposed)
	}
	p("| Scanned | %s by bgh %s |", o.Started.UTC().Format("2006-01-02 15:04 UTC"), version)
	p("")

	switch o.Verdict {
	case scan.NotSearched:
		p("## Not searched")
		p("")
		if res != nil && res.Refused != "" {
			p("```")
			p("%s", res.Refused)
			p("```")
		} else {
			p("%s", o.Detail)
		}
		p("")
		p("NOT SEARCHED is not a clean result. Nothing was compared, so this report says nothing about whether a gap exists.")
	case scan.NoGap:
		p("## No gap")
		p("")
		tag := "the Latest release"
		if res != nil && res.Release != nil {
			tag = "`" + res.Release.Tag + "`"
		}
		p("No fix on the default branch within the window was found missing from %s with its pre-fix code still present.", tag)
		if o.HiddenNotDefect > 0 {
			p("")
			p("%d keyword-tier candidate(s) were missing from the release but the judge rated them not a defect, so they are not shown.", o.HiddenNotDefect)
		}
	}
	if o.Verdict == scan.Gap {
		for i, f := range o.Findings {
			writeFinding(&b, o, i+1, f)
		}
		if o.HiddenNotDefect > 0 {
			p("---")
			p("")
			p("%d further keyword-tier candidate(s) lacked a fix at the Latest release but the judge rated them not a defect, so they are not shown.", o.HiddenNotDefect)
			p("")
		}
	}
	if o.Unjudged > 0 {
		p("")
		p("%d keyword-tier candidate(s) could not be judged by the AI provider and are not shown.", o.Unjudged)
	}
	p("")
	p("---")
	p("")
	p("A gap is a measurement of what shipped: the fix is absent from the Latest release's code and the pre-fix code is still there. ")
	p("It is not proof the change was a security fix or that the bug is exploitable. Verify by hand before reporting it.")
	return b.String()
}

func writeFinding(b *strings.Builder, o *scan.Outcome, n int, f scan.Finding) {
	p := func(format string, a ...any) { fmt.Fprintf(b, format+"\n", a...) }
	c := f.Cand
	slug := o.Ref.Slug()
	rf := c.Release
	tag := o.Result.Release.Tag
	sig := c.Signature

	p("")
	p("---")
	p("")
	p("## %d. %s %s", n, c.Commit.Short(), codeSpanSafe(c.Commit.Subject()))
	p("")
	p("| | |")
	p("|---|---|")
	p("| Fix commit | [`%s`](https://github.com/%s/commit/%s) |", c.Commit.SHA, slug, c.Commit.SHA)
	landed := fixedDate(c.Date())
	if rf != nil && rf.DaysPublic >= 0 {
		landed += fmt.Sprintf(" (%d days public)", rf.DaysPublic)
	}
	p("| Landed on `%s` | %s |", o.Result.DefaultBr, landed)
	p("| Latest tag lacking it | [`%s`](https://github.com/%s/tree/%s) |", tag, slug, tag)
	if rf != nil {
		p("| Tag published | %s |", fixedDate(rf.Published))
		if rf.ShippedSinceFix != nil {
			if *rf.ShippedSinceFix {
				p("| Released since the fix | yes: the vendor shipped a release and left it out |")
			} else {
				p("| Released since the fix | no: nothing has shipped since the fix landed |")
			}
		}
		if rf.Path != "" {
			p("| File read at the tag | [`%s`](https://github.com/%s/blob/%s/%s)%s |", rf.Path, slug, tag, rf.Path,
				ifNotEmpty(" (located: ", rf.HowLocated, ")"))
		}
	}
	tier := "vendor security signal"
	if !c.VendorSignalled() {
		tier = "keyword vocabulary only, rated a real defect by the AI judge"
	}
	p("| Signal | %s |", strings.Join(wrapAll(c.Signals()), ", "))
	p("| Evidence tier | %s |", tier)
	if ev := c.Evidence; ev != nil {
		p("| Diff direction | **%s**: %d security-relevant line(s) added, %d removed |", ev.Direction, ev.AddedSalient, ev.RemovedSalient)
	}
	p("")

	p("The fix is absent from `%s` and the pre-fix code is still there. That is a measurement of what shipped, not a claim that the change was a security fix.", tag)
	if c.VendorSignalled() {
		p("The vendor's own signal (a tracker id, a GHSA reference or a private-fork merge) says they filed this as security work.")
	}
	p("")

	if f.Verdict != nil {
		v := f.Verdict
		p("### AI judgement (%s)", v.Provider)
		p("")
		p("The keyword tier fires on generic vocabulary, so this finding is shown only because the judge rated the pre-fix behaviour a defect.")
		p("")
		p("- Reachable by an attacker: **%v**", v.IsReachable())
		p("- Defect before the change: **%v** (confidence: %s)", v.IsDefect(), orDash(v.Confidence))
		if v.Mechanism != "" {
			p("- Mechanism: %s", oneLine(v.Mechanism))
		}
		if v.AttackerInput != "" {
			p("- Attacker input: %s", oneLine(v.AttackerInput))
		}
		if len(v.Path) > 0 {
			p("- Path: %s", strings.Join(wrapAll(v.Path), ", "))
		}
		p("")
		p("A model's reading is a lead, not a conclusion. Check it against the code.")
		p("")
	}

	p("### Evidence")
	p("")
	if rf != nil {
		kind := rf.VulnEvidence
		if kind == "" {
			kind = signature.ShapeNone
		}
		p("%s", evidenceWording[kind])
		p("")
		if rf.Presence != nil {
			p("- Fix content present at the tag: **%.0f%%**", rf.Presence.FixRatio*100)
			p("- %s: **%.0f%%**", ratioLabel[kind], rf.Presence.VulnRatio*100)
			if rf.Presence.VulnShapeKind == signature.ShapeContext && sig != nil && len(sig.FixIdentifiers) > 0 {
				p("- Names the fix introduced, none of which appear in the file: %s", strings.Join(wrapAll(head(sig.FixIdentifiers, 8)), ", "))
			}
			if len(rf.Presence.Missing) > 0 {
				p("")
				p("Fix lines missing from `%s` at `%s`:", rf.Path, tag)
				p("")
				p("%s", fence(rf.Presence.Missing, 12))
			}
		}
		if rf.Note != "" {
			p("")
			p("Scan note: %s", rf.Note)
		}
		p("")
	}
	if sig != nil {
		switch {
		case sig.VulnShapeKind() == signature.ShapeRemoved:
			p("Pre-fix lines (deleted by the fix) that are still present at the tag:")
			p("")
			p("%s", fence(sig.Removed, 12))
			p("")
		case sig.VulnShapeKind() == signature.ShapeContext:
			p("The fix deleted no testable line. The code it sat among, used as the weaker pre-fix shape:")
			p("")
			p("%s", fence(sig.ContextCode, 12))
			p("")
		}
		if sig.Symbol != "" {
			p("Enclosing symbol: %s", codeSpan(sig.Symbol))
			p("")
		}
	}

	p("### Verify by hand")
	p("")
	path := ""
	if rf != nil {
		path = rf.Path
	}
	if path == "" && sig != nil {
		path = sig.Path
	}
	p("```sh")
	p("git clone --filter=blob:none https://github.com/%s.git && cd %s", slug, o.Ref.Name)
	p("git fetch origin tag %s", tag)
	p("# 1. is the fix commit part of the Latest tag? (expected: no)")
	p("git merge-base --is-ancestor %s %s && echo contained || echo 'not contained'", c.Commit.SHA, tag)
	p("# 2. what did the fix change?")
	p("git show %s", c.Commit.SHA)
	if path != "" {
		p("# 3. is the pre-fix code still in the file that shipped?")
		p("git show %s:%s", tag, shellPath(path))
	}
	p("```")
	p("")
	p("A refactor can move code, so if the path above no longer exists, search the tag for the added lines of the fix.")
	p("")

	p("### Fix")
	p("")
	p("Backport the fix onto the line the Latest release was cut from, then publish a patched release:")
	p("")
	p("```sh")
	p("git checkout -b backport-%s %s", c.Commit.Short(), tag)
	p("git cherry-pick -x %s", c.Commit.SHA)
	p("```")
	p("")
	p("If the cherry-pick conflicts, the diff below is the change to port by hand.")
	p("")
	if sig != nil && len(sig.Added) > 0 {
		p("Fix lines to look for (and add) in `%s`:", path)
		p("")
		p("%s", fence(sig.Added, 12))
		p("")
	}
	if c.Patch != "" {
		p("<details><summary>Full diff of the fix commit</summary>")
		p("")
		p("%s", diffFence(c.Patch, 400))
		p("")
		p("</details>")
		p("")
	}
	if len(f.CallSites) > 0 {
		p("<details><summary>Call sites found in the shipped tree</summary>")
		p("")
		for _, s := range f.CallSites {
			p("- `%s:%d` (hop %d)", s.Path, s.Line, s.Hop)
		}
		p("")
		p("</details>")
		p("")
	}
}

func diffFence(patch string, max int) string {
	lines := strings.Split(patch, "\n")
	if len(lines) > max {
		lines = append(lines[:max], fmt.Sprintf("... (%d more lines)", len(lines)-max))
	}
	return "```diff\n" + strings.Join(lines, "\n") + "\n```"
}

func ifNotEmpty(pre, s, post string) string {
	if s == "" {
		return ""
	}
	return pre + s + post
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

func head(s []string, n int) []string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func wrapAll(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = codeSpan(s)
	}
	return out
}

// codeSpanSafe renders a commit subject without letting it break the heading.
func codeSpanSafe(s string) string { return strings.ReplaceAll(oneLine(s), "|", "\\|") }

func shellPath(p string) string {
	if strings.ContainsAny(p, " '\"$&;()") {
		return "'" + strings.ReplaceAll(p, "'", `'\''`) + "'"
	}
	return p
}

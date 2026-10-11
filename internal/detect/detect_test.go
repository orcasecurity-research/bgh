package detect

import (
	"testing"
	"time"

	"github.com/orcasecurity-research/bgh/internal/fingerprint"
	"github.com/orcasecurity-research/bgh/internal/model"
	"github.com/orcasecurity-research/bgh/internal/signature"
)

func TestNameSimilarity(t *testing.T) {
	if s := nameSimilarity("files.py", "FILES.py"); s != 1 {
		t.Errorf("case-insensitive identical = %v", s)
	}
	// difflib: ratio("abcd", "bcde") = 2*3/8 = 0.75
	if s := nameSimilarity("abcd", "bcde"); s != 0.75 {
		t.Errorf("ratio = %v, want 0.75", s)
	}
	if s := nameSimilarity("abc", "xyz"); s != 0 {
		t.Errorf("disjoint = %v", s)
	}
}

func TestCandidatePathsFollowsMovedAndRenamedFiles(t *testing.T) {
	tree := NewTree(map[string]string{
		"src/auth/files.py":        "1",
		"src/api/files.py":         "2",
		"src/api/files_helpers.py": "3",
		"src/api/unrelated.py":     "4",
	})
	sig := &signature.FixSignature{Path: "src/api/handlers.py"}
	got := CandidatePaths(tree, sig, 4)
	if len(got) != 0 {
		t.Errorf("no resemblance should yield nothing, got %v", got)
	}
	sig = &signature.FixSignature{Path: "src/api/files.py"}
	got = CandidatePaths(tree, sig, 4)
	if len(got) < 3 || got[0].path != "src/api/files.py" || got[0].how != "same path" {
		t.Fatalf("got %v", got)
	}
	if got[1].path != "src/auth/files.py" {
		t.Errorf("moved copy should follow: %v", got)
	}
	sig = &signature.FixSignature{Path: "src/api/fileshandler.py"}
	got = CandidatePaths(tree, sig, 4)
	for _, g := range got {
		if g.path == "src/api/unrelated.py" {
			t.Errorf("low-similarity sibling guessed: %v", got)
		}
	}
}

func fpWith(sigs ...fingerprint.Signal) *fingerprint.Fingerprint {
	return &fingerprint.Fingerprint{Signals: sigs, PRLowWater: 1000}
}

func commit(sha, msg string, age int) model.Commit {
	return model.Commit{SHA: sha, Message: msg, Committed: time.Now().AddDate(0, 0, -age)}
}

func TestEnumerateModes(t *testing.T) {
	fp := fpWith(
		fingerprint.Signal{Kind: fingerprint.KindGHSA, Tier: "high", Grep: model.GHSAPattern},
		fingerprint.Signal{Kind: fingerprint.KindKeyword, Tier: "medium", Grep: `\bpermission`},
	)
	log := []model.Commit{
		commit("a", "fix thing GHSA-2222-3333-4444", 5),
		commit("b", "tighten permission checks", 3),
		commit("c", "chore(deps): bump x from 1 to 2 GHSA-2222-3333-4444", 2), // negative: routine churn
		commit("d", "unrelated", 1),
	}
	def := Enumerate(log, fp, false, 10)
	if len(def) != 1 || def[0].Commit.SHA != "a" || !def[0].VendorSignalled() {
		t.Fatalf("default mode: %+v", def)
	}
	ai := Enumerate(log, fp, true, 10)
	if len(ai) != 2 || ai[0].Commit.SHA != "a" || ai[1].VendorSignalled() {
		t.Fatalf("ai mode: %+v", ai)
	}
	if got := Enumerate(log, fp, true, 1); len(got) != 1 || got[0].Commit.SHA != "a" {
		t.Errorf("cap must keep the strongest evidence, got %+v", got)
	}
}

func TestEnumerateForkOnlySuspects(t *testing.T) {
	fp := fpWith(fingerprint.Signal{Kind: fingerprint.KindFork, Tier: "high", Grep: `Merge pull request #\d+`})
	log := []model.Commit{
		commit("pub", "Merge pull request #1500 from a/b", 3),
		commit("priv", "Merge pull request #7 from a/b", 3),
	}
	got := Enumerate(log, fp, false, 10)
	if len(got) != 1 || got[0].Commit.SHA != "priv" || !got[0].forkUnverified {
		t.Fatalf("%+v", got)
	}
}

func TestSubtractAdvisories(t *testing.T) {
	advs := []model.Advisory{{GHSAID: "GHSA-2222-3333-4444", FixSHAs: []string{"deadbee"}}}
	cands := []*Candidate{
		{Commit: model.Commit{SHA: "1111", Message: "fix (GHSA-2222-3333-4444)"}},
		{Commit: model.Commit{SHA: "deadbeef00", Message: "other"}},
		{Commit: model.Commit{SHA: "2222", Message: "silent"}},
	}
	silent, attributed := SubtractAdvisories(cands, advs)
	if len(silent) != 1 || silent[0].Commit.SHA != "2222" || len(attributed) != 2 {
		t.Errorf("silent=%d attributed=%d", len(silent), len(attributed))
	}
}

func TestExposedRules(t *testing.T) {
	gap := &ReleaseFinding{Status: StatusGap}
	hard := &signature.DiffEvidence{Direction: signature.Hardening}
	loose := &signature.DiffEvidence{Direction: signature.Loosening}
	cases := []struct {
		name string
		c    Candidate
		want bool
	}{
		{"gap+hardening", Candidate{Release: gap, Evidence: hard}, true},
		{"loosening is vetoed", Candidate{Release: gap, Evidence: loose}, false},
		{"no patch is no basis", Candidate{Release: gap}, false},
		{"not a gap", Candidate{Release: &ReleaseFinding{Status: StatusBackported}, Evidence: hard}, false},
		{"untested", Candidate{Evidence: hard}, false},
	}
	for _, c := range cases {
		if got := c.c.Exposed(); got != c.want {
			t.Errorf("%s: %v", c.name, got)
		}
	}
}

package fingerprint

import (
	"fmt"
	"testing"

	"github.com/orcasecurity-research/bgh/internal/model"
)

func corpus(msgs ...string) []model.Commit {
	var out []model.Commit
	for i, m := range msgs {
		out = append(out, model.Commit{SHA: fmt.Sprint(i), Message: m})
	}
	return out
}

func TestDeriveTrackerAcceptsEnrichedPrefixRejectsNoise(t *testing.T) {
	var msgs []string
	for i := 0; i < 40; i++ {
		msgs = append(msgs, fmt.Sprintf("refactor module %d (BOT-%d)", i, 100+i)) // general tracker, not security
	}
	for i := 0; i < 5; i++ {
		msgs = append(msgs, fmt.Sprintf("fix permission bypass in handler %d (SEC-%d)", i, 10+i))
	}
	msgs = append(msgs, "use UTF-8 and SHA-256 and UTF-8", "SHA-256 again")
	for i := 0; i < 150; i++ {
		msgs = append(msgs, fmt.Sprintf("misc change %d", i))
	}
	var probes []Probe
	sigs := DeriveTracker(nil, corpus(msgs...), &probes)
	if len(sigs) != 1 || sigs[0].Prefix != "SEC" || sigs[0].Kind != KindTracker || sigs[0].Tier != "medium" {
		t.Fatalf("%+v", sigs)
	}
	if !probes[0].OK {
		t.Error("probe should be ok")
	}
}

func TestTaxonomyPrefixIsNotAVendorSignal(t *testing.T) {
	if signalKindForPrefix("CWE") != KindTaxonomy || IsVendorKind(KindTaxonomy) {
		t.Error("CWE must not be a vendor tracker")
	}
	if signalKindForPrefix("SEC") != KindTracker || !IsVendorKind(KindTracker) {
		t.Error("SEC is a tracker")
	}
}

func TestOrphanGHSAExcludesDependencyBumps(t *testing.T) {
	if !IsOrphanGHSA("fix auth (GHSA-2222-3333-4444)") {
		t.Error("plain citation is an orphan")
	}
	if IsOrphanGHSA("chore: bump foo from 1.0 to 1.1 (GHSA-2222-3333-4444)") {
		t.Error("a dependency bump cites an upstream advisory")
	}
}

func TestDeriveGHSA(t *testing.T) {
	var probes []Probe
	if s := DeriveGHSA(nil, corpus("hello"), nil, &probes); s != nil || probes[0].OK {
		t.Error("no citations: no signal")
	}
	s := DeriveGHSA(nil, corpus("fix (GHSA-2222-3333-4444)"), nil, &probes)
	if s == nil || s.Tier != "high" {
		t.Errorf("%+v", s)
	}
}

func TestForkThreshold(t *testing.T) {
	if ForkThreshold(1000) != 500 || ForkThreshold(1) != 1 {
		t.Error("threshold")
	}
}

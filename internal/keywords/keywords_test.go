package keywords

import "testing"

func TestScore(t *testing.T) {
	cases := []struct {
		msg  string
		want bool
	}{
		{"fix XSS in the comment renderer", true},
		{"validate the session token before use", true},
		{"add a button to the toolbar", false},
		{"bump foo from 1.0 to 1.1 (fixes a vulnerability)", true}, // strong beats negative
		{"chore(deps): bump lodash, validate and sanitize", false},
		{"fix a typo in the permission docs and token text", false},
	}
	for _, c := range cases {
		if got, _ := Score(c.msg); got != c.want {
			t.Errorf("Score(%q) = %v, want %v", c.msg, got, c.want)
		}
	}
}

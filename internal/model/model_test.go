package model

import "testing"

func TestParseRepo(t *testing.T) {
	ok := map[string]string{
		"o/r":                            "o/r",
		"https://github.com/o/r":         "o/r",
		"https://github.com/o/r.git":     "o/r",
		"github.com/o/r/":                "o/r",
		"https://github.com/o/r/pull/12": "o/r",
		"git@github.com:o/r.git":         "o/r",
	}
	for in, want := range ok {
		got, err := ParseRepo(in)
		if err != nil || got.Slug() != want {
			t.Errorf("ParseRepo(%q) = %v, %v; want %s", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "justone", "o/", "a b/c", "o/r;rm"} {
		if _, err := ParseRepo(bad); err == nil {
			t.Errorf("ParseRepo(%q) should fail", bad)
		}
	}
}

func TestCommitHelpers(t *testing.T) {
	c := Commit{SHA: "0123456789abcdef", Message: "Merge pull request #42 from x/y\n\nbody"}
	if c.MergePR() != 42 || c.Short() != "0123456789ab" || c.Subject() != "Merge pull request #42 from x/y" {
		t.Errorf("%+v", c)
	}
}

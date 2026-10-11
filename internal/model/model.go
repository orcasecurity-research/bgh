// Package model holds the shared types. They are deliberately dumb: logic
// lives in the pass packages.
package model

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// GHSARe matches a GitHub Security Advisory identifier.
var GHSARe = regexp.MustCompile(`(?i)\bGHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}\b`)

// GHSAPattern is GHSARe's source, for use as a detector grep (matched
// case-insensitively by the caller).
const GHSAPattern = `\bGHSA-[23456789cfghjmpqrvwxCFGHJMPQRVWX]{4}-[23456789cfghjmpqrvwxCFGHJMPQRVWX]{4}-[23456789cfghjmpqrvwxCFGHJMPQRVWX]{4}\b`

var (
	CVERe      = regexp.MustCompile(`(?i)\bCVE-\d{4}-\d{4,7}\b`)
	TrackerRe  = regexp.MustCompile(`\b([A-Z][A-Z0-9]{1,9})-(\d{1,6})\b`)
	MergePRRe  = regexp.MustCompile(`Merge pull request #(\d+)`)
	repoNameRe = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
)

// RepoRef names a GitHub repository.
type RepoRef struct {
	Owner string
	Name  string
}

// ParseRepo accepts owner/name, github.com/owner/name and full URLs.
func ParseRepo(s string) (RepoRef, error) {
	orig := s
	s = strings.TrimSpace(s)
	for _, p := range []string{"https://", "http://", "ssh://"} {
		s = strings.TrimPrefix(s, p)
	}
	s = strings.TrimPrefix(s, "git@")
	s = strings.TrimPrefix(s, "www.")
	if strings.HasPrefix(s, "github.com") {
		s = strings.TrimPrefix(s, "github.com")
		s = strings.TrimLeft(s, ":/")
	}
	s = strings.TrimSuffix(strings.Trim(s, "/"), ".git")
	var parts []string
	for _, p := range strings.Split(s, "/") {
		if p != "" {
			parts = append(parts, p)
		}
	}
	if len(parts) < 2 || !repoNameRe.MatchString(parts[0]) || !repoNameRe.MatchString(parts[1]) {
		return RepoRef{}, fmt.Errorf("not an owner/name repository: %q", orig)
	}
	return RepoRef{Owner: parts[0], Name: strings.TrimSuffix(parts[1], ".git")}, nil
}

func (r RepoRef) Slug() string   { return r.Owner + "/" + r.Name }
func (r RepoRef) Path() string   { return "/repos/" + r.Owner + "/" + r.Name }
func (r RepoRef) String() string { return r.Slug() }

// CloneURL is the https URL git fetches from.
func (r RepoRef) CloneURL() string { return "https://github.com/" + r.Slug() + ".git" }

// Commit is a commit as the API or the local clone reports it.
type Commit struct {
	SHA         string
	Message     string
	Authored    time.Time
	Committed   time.Time
	AuthorLogin string
	AuthorEmail string
	Parents     []string
}

func (c Commit) Subject() string {
	if i := strings.IndexByte(c.Message, '\n'); i >= 0 {
		return strings.TrimRight(c.Message[:i], "\r")
	}
	return c.Message
}

func (c Commit) Short() string {
	if len(c.SHA) > 12 {
		return c.SHA[:12]
	}
	return c.SHA
}

// Date is the committer date, falling back to the author date. Zero if unknown.
func (c Commit) Date() time.Time {
	if !c.Committed.IsZero() {
		return c.Committed
	}
	return c.Authored
}

// MergePR is the PR number in a "Merge pull request #N" message, or 0.
func (c Commit) MergePR() int {
	m := MergePRRe.FindStringSubmatch(c.Message)
	if m == nil {
		return 0
	}
	var n int
	fmt.Sscanf(m[1], "%d", &n)
	return n
}

// Advisory is a published security advisory on the repository.
type Advisory struct {
	GHSAID    string
	CVEID     string
	Summary   string
	Severity  string
	Published time.Time
	// Advisory version ranges and patched-version fields disagree in practice;
	// the vulnerable range is the field to trust.
	VulnerableRanges []string
	PatchedVersions  []string
	FixSHAs          []string
	FixPRs           []int
}

// IDs lists every identifier a commit message might cite.
func (a Advisory) IDs() []string {
	var out []string
	if a.GHSAID != "" {
		out = append(out, a.GHSAID)
	}
	if a.CVEID != "" {
		out = append(out, a.CVEID)
	}
	return out
}

// ReleaseTarget is the release a user downloads today: GitHub's own Latest
// badge. It is the only ref the gap test asks about.
//
// Not releases[0]: that list includes drafts and prereleases and orders them
// first, so on a vendor who publishes release candidates it would measure
// exposure against a version nobody is running.
type ReleaseTarget struct {
	Tag       string
	Published time.Time
	Commitish string
}

// Meta is the slice of repository metadata the scan reads.
type Meta struct {
	DefaultBranch string
	Archived      bool
	Private       bool
	Fork          bool
}

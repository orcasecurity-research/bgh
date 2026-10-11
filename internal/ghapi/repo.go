package ghapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/orcasecurity-research/bgh/internal/model"
)

// RepoAPI is the typed view of one repository. No clone happens here.
type RepoAPI struct {
	C   *Client
	Ref model.RepoRef
}

func parseTS(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

// Meta reads the repository's metadata.
func (a *RepoAPI) Meta(ctx context.Context) (model.Meta, error) {
	var d struct {
		DefaultBranch string `json:"default_branch"`
		Archived      bool   `json:"archived"`
		Private       bool   `json:"private"`
		Fork          bool   `json:"fork"`
	}
	if err := a.C.Get(ctx, a.Ref.Path(), nil, &d); err != nil {
		return model.Meta{}, err
	}
	if d.DefaultBranch == "" {
		d.DefaultBranch = "main"
	}
	return model.Meta{DefaultBranch: d.DefaultBranch, Archived: d.Archived, Private: d.Private, Fork: d.Fork}, nil
}

// LatestRelease is the tag behind GitHub's Latest badge, or nil if there is
// no release.
//
// nil is a verdict rather than a failure: a vendor who publishes no GitHub
// releases has no "latest version" for a fix to be missing from, so the scan
// is refused instead of reporting NO GAP, which would read as "searched and
// found nothing" when nothing was compared at all.
//
// A release with no tag, or none this can date, is also nil: both the days
// exposed and the shipped-since-the-fix note are computed off that date.
func (a *RepoAPI) LatestRelease(ctx context.Context) (*model.ReleaseTarget, error) {
	var d struct {
		TagName         string `json:"tag_name"`
		PublishedAt     string `json:"published_at"`
		CreatedAt       string `json:"created_at"`
		TargetCommitish string `json:"target_commitish"`
	}
	ok, err := a.C.GetOptional(ctx, a.Ref.Path()+"/releases/latest", nil, &d)
	if err != nil || !ok || d.TagName == "" {
		return nil, err
	}
	pub := parseTS(d.PublishedAt)
	if pub.IsZero() {
		pub = parseTS(d.CreatedAt)
	}
	if pub.IsZero() {
		return nil, nil
	}
	return &model.ReleaseTarget{Tag: d.TagName, Published: pub, Commitish: d.TargetCommitish}, nil
}

type apiCommit struct {
	SHA    string `json:"sha"`
	Commit struct {
		Message string `json:"message"`
		Author  struct {
			Date  string `json:"date"`
			Email string `json:"email"`
		} `json:"author"`
		Committer struct {
			Date string `json:"date"`
		} `json:"committer"`
	} `json:"commit"`
	Author *struct {
		Login string `json:"login"`
	} `json:"author"`
	Parents []struct {
		SHA string `json:"sha"`
	} `json:"parents"`
	Files []struct {
		Filename         string `json:"filename"`
		PreviousFilename string `json:"previous_filename"`
		Status           string `json:"status"`
		Patch            string `json:"patch"`
	} `json:"files"`
}

func (d *apiCommit) toCommit() model.Commit {
	c := model.Commit{
		SHA:         d.SHA,
		Message:     d.Commit.Message,
		Authored:    parseTS(d.Commit.Author.Date),
		Committed:   parseTS(d.Commit.Committer.Date),
		AuthorEmail: d.Commit.Author.Email,
	}
	if d.Author != nil {
		c.AuthorLogin = d.Author.Login
	}
	for _, p := range d.Parents {
		c.Parents = append(c.Parents, p.SHA)
	}
	return c
}

// Commit fetches one commit; nil if it is not reachable in this repository.
func (a *RepoAPI) Commit(ctx context.Context, sha string) (*model.Commit, error) {
	var d apiCommit
	ok, err := a.C.GetOptional(ctx, a.Ref.Path()+"/commits/"+sha, nil, &d)
	if err != nil || !ok {
		return nil, err
	}
	c := d.toCommit()
	return &c, nil
}

// CommitPatch is the unified diff for a commit, from the API.
//
// Reading diffs out of a blobless clone means one lazy blob fetch per commit,
// and git answers each with a whole pack. The API returns the patch inline.
// An empty result means the commit could not be fetched or lists no files
// (a merge commit): that is "no diff", not a neutral one.
func (a *RepoAPI) CommitPatch(ctx context.Context, sha string) (string, error) {
	var d apiCommit
	ok, err := a.C.GetOptional(ctx, a.Ref.Path()+"/commits/"+sha, nil, &d)
	if err != nil || !ok {
		return "", err
	}
	var chunks []string
	for _, f := range d.Files {
		if f.Patch == "" {
			continue
		}
		old := f.PreviousFilename
		if old == "" {
			old = f.Filename
		}
		chunks = append(chunks, fmt.Sprintf("diff --git a/%s b/%s", old, f.Filename))
		if f.Status == "renamed" {
			chunks = append(chunks, "rename from "+old, "rename to "+f.Filename)
		}
		if f.Status != "added" {
			chunks = append(chunks, "--- a/"+old)
		} else {
			chunks = append(chunks, "--- /dev/null")
		}
		if f.Status != "removed" {
			chunks = append(chunks, "+++ b/"+f.Filename)
		} else {
			chunks = append(chunks, "+++ /dev/null")
		}
		chunks = append(chunks, f.Patch)
	}
	return strings.Join(chunks, "\n"), nil
}

// FileAt returns a file's contents at a ref. This is how backport status is
// decided: never GitHub's commit search, which indexes the default branch only.
// ok is false when the file is absent or too large for the contents API.
func (a *RepoAPI) FileAt(ctx context.Context, ref, path string) (content string, ok bool, err error) {
	segs := strings.Split(path, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	var d struct {
		Encoding string  `json:"encoding"`
		Content  *string `json:"content"`
	}
	found, err := a.C.GetOptional(ctx, a.Ref.Path()+"/contents/"+strings.Join(segs, "/"),
		url.Values{"ref": {ref}}, &d)
	if err != nil || !found {
		return "", false, err
	}
	if d.Encoding != "base64" || d.Content == nil {
		return "", false, nil
	}
	raw, derr := base64.StdEncoding.DecodeString(strings.ReplaceAll(*d.Content, "\n", ""))
	if derr != nil {
		return "", false, nil
	}
	return strings.ToValidUTF8(string(raw), "�"), true, nil
}

// MergeCommitSHA is a pull request's merge commit; found is false if the PR
// does not exist in this repository.
func (a *RepoAPI) MergeCommitSHA(ctx context.Context, number int) (sha string, found bool, err error) {
	var d struct {
		MergeCommitSHA *string `json:"merge_commit_sha"`
	}
	ok, err := a.C.GetOptional(ctx, fmt.Sprintf("%s/pulls/%d", a.Ref.Path(), number), nil, &d)
	if err != nil || !ok {
		return "", false, err
	}
	if d.MergeCommitSHA != nil {
		sha = *d.MergeCommitSHA
	}
	return sha, true, nil
}

// ListCommits is the default-branch commit corpus for the window. The bool
// reports truncation at maxPages.
func (a *RepoAPI) ListCommits(ctx context.Context, sinceDays, maxPages int) ([]model.Commit, bool, error) {
	since := time.Now().UTC().Add(-time.Duration(sinceDays) * 24 * time.Hour).Format("2006-01-02T15:04:05Z")
	raws, err := a.C.Paginate(ctx, a.Ref.Path()+"/commits", url.Values{"since": {since}}, maxPages)
	var out []model.Commit
	for _, r := range raws {
		var d apiCommit
		if json.Unmarshal(r, &d) == nil {
			out = append(out, d.toCommit())
		}
	}
	return out, len(raws) >= maxPages*100, err
}

// SearchCommits searches commit messages. It indexes the DEFAULT BRANCH ONLY:
// safe for finding fix commits on main, never usable for deciding whether a
// release carries a fix. Failures yield no results rather than an error.
func (a *RepoAPI) SearchCommits(ctx context.Context, term string, maxPages int) []model.Commit {
	q := fmt.Sprintf("repo:%s %s", a.Ref.Slug(), term)
	raws, _ := a.C.Paginate(ctx, "/search/commits", url.Values{"q": {q}}, maxPages)
	var out []model.Commit
	for _, r := range raws {
		var d apiCommit
		if json.Unmarshal(r, &d) == nil && d.SHA != "" {
			out = append(out, d.toCommit())
		}
	}
	return out
}

// Advisories are the advisories the vendor published on this repository.
func (a *RepoAPI) Advisories(ctx context.Context) []model.Advisory {
	// Cursor-paginated: `page` is ignored and returns page 1 again.
	raws, _ := a.C.PaginateLinked(ctx, a.Ref.Path()+"/security-advisories", nil, 5)
	var out []model.Advisory
	for _, r := range raws {
		var d struct {
			State           string `json:"state"`
			GHSAID          string `json:"ghsa_id"`
			CVEID           string `json:"cve_id"`
			Summary         string `json:"summary"`
			Description     string `json:"description"`
			Severity        string `json:"severity"`
			HTMLURL         string `json:"html_url"`
			URL             string `json:"url"`
			PublishedAt     string `json:"published_at"`
			UpdatedAt       string `json:"updated_at"`
			References      []any  `json:"references"`
			Vulnerabilities []struct {
				Range   string `json:"vulnerable_version_range"`
				Patched string `json:"patched_versions"`
			} `json:"vulnerabilities"`
		}
		if json.Unmarshal(r, &d) != nil {
			continue
		}
		if d.State != "" && d.State != "published" {
			continue
		}
		adv := model.Advisory{
			GHSAID: d.GHSAID, CVEID: d.CVEID, Summary: strings.TrimSpace(d.Summary),
			Severity: d.Severity, Published: parseTS(d.PublishedAt),
		}
		if adv.Published.IsZero() {
			adv.Published = parseTS(d.UpdatedAt)
		}
		for _, v := range d.Vulnerabilities {
			if v.Range != "" {
				adv.VulnerableRanges = append(adv.VulnerableRanges, v.Range)
			}
			if v.Patched != "" {
				adv.PatchedVersions = append(adv.PatchedVersions, v.Patched)
			}
		}
		// Vendors link the fix in wildly different places: the references
		// array, the prose description, or nowhere at all.
		texts := []string{d.HTMLURL, d.URL, d.Description, d.Summary}
		for _, ref := range d.References {
			switch v := ref.(type) {
			case string:
				texts = append(texts, v)
			case map[string]any:
				if s, ok := v["url"].(string); ok {
					texts = append(texts, s)
				}
			}
		}
		a.attachFixRefs(&adv, texts)
		out = append(out, adv)
	}
	return out
}

func (a *RepoAPI) attachFixRefs(adv *model.Advisory, texts []string) {
	slug := regexp.QuoteMeta(a.Ref.Slug())
	shaRe := regexp.MustCompile(`(?i)github\.com/` + slug + `/commit/([0-9a-f]{7,40})`)
	prRe := regexp.MustCompile(`(?i)github\.com/` + slug + `/pull/(\d+)`)
	for _, t := range texts {
		for _, m := range shaRe.FindAllStringSubmatch(t, -1) {
			if !containsStr(adv.FixSHAs, m[1]) {
				adv.FixSHAs = append(adv.FixSHAs, m[1])
			}
		}
		for _, m := range prRe.FindAllStringSubmatch(t, -1) {
			var n int
			fmt.Sscanf(m[1], "%d", &n)
			if n > 0 && !containsInt(adv.FixPRs, n) {
				adv.FixPRs = append(adv.FixPRs, n)
			}
		}
	}
}

func containsStr(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func containsInt(s []int, v int) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// AdvisoryIndex maps every identifier a commit message might cite to its advisory.
func AdvisoryIndex(advs []model.Advisory) map[string]*model.Advisory {
	idx := map[string]*model.Advisory{}
	for i := range advs {
		for _, id := range advs[i].IDs() {
			idx[strings.ToUpper(id)] = &advs[i]
		}
	}
	return idx
}

// CitedAdvisories lists the published advisories a commit message cites.
func CitedAdvisories(message string, idx map[string]*model.Advisory) []*model.Advisory {
	var found []*model.Advisory
	seen := map[string]bool{}
	ids := append(model.GHSARe.FindAllString(message, -1), model.CVERe.FindAllString(message, -1)...)
	for _, id := range ids {
		if adv := idx[strings.ToUpper(id)]; adv != nil && !seen[adv.GHSAID] {
			seen[adv.GHSAID] = true
			found = append(found, adv)
		}
	}
	return found
}

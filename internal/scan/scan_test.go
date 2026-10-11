package scan_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/orcasecurity-research/bgh/internal/detect"
	"github.com/orcasecurity-research/bgh/internal/ghapi"
	"github.com/orcasecurity-research/bgh/internal/judge"
	"github.com/orcasecurity-research/bgh/internal/model"
	"github.com/orcasecurity-research/bgh/internal/report"
	"github.com/orcasecurity-research/bgh/internal/scan"
)

const filesV1 = `def download_file(request, name):
    log_request(request)
    started = clock_now()
    metrics_counter("calls")
    audit_trail = start_trail(request)
    user = request.user
    path = resolve_path(name)
    data = open(path).read()
    return Response(data)
`

const filesFixed = `def download_file(request, name):
    log_request(request)
    started = clock_now()
    metrics_counter("calls")
    audit_trail = start_trail(request)
    user = request.user
    if not user.can_read(name):
        raise Forbidden("no access to file")
    if name not in ALLOWED_FILES:
        raise Forbidden("file not allowed")
    path = resolve_path(name)
    data = open(path).read()
    return Response(data)
`

const uploadV1 = `def handle_upload(request, name):
    log_request(request)
    started = clock_now()
    metrics_counter("calls")
    audit_trail = start_trail(request)
    user = request.user
    dest = build_destination(name)
    save_stream(request.body, dest)
    return Response("ok")
`

const uploadFixed = `def handle_upload(request, name):
    log_request(request)
    started = clock_now()
    metrics_counter("calls")
    audit_trail = start_trail(request)
    user = request.user
    if not user.can_write(name):
        raise Forbidden("upload not permitted")
    if name in BLOCKED_UPLOAD_NAMES:
        raise Forbidden("blocked name")
    dest = build_destination(name)
    save_stream(request.body, dest)
    return Response("ok")
`

type fixture struct {
	dir                string
	c1, c2, c3         string
	fixMsg, keywordMsg string
}

func git(t *testing.T, dir string, date time.Time, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	d := date.Format(time.RFC3339)
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_DATE="+d, "GIT_COMMITTER_DATE="+d,
		"GIT_AUTHOR_NAME=Dev", "GIT_AUTHOR_EMAIL=dev@example.invalid",
		"GIT_COMMITTER_NAME=Dev", "GIT_COMMITTER_EMAIL=dev@example.invalid", "GIT_CONFIG_GLOBAL=/dev/null")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// newFixture builds: c1 (tagged v1.0) -> c2 (GHSA-marked guard on files.py)
// -> c3 (keyword-only guard on upload.py). The tag predates both fixes.
func newFixture(t *testing.T, ghsaMsg string, tagAt string) *fixture {
	dir := t.TempDir()
	now := time.Now().UTC()
	git(t, dir, now, "init", "-q", "-b", "main")
	git(t, dir, now, "config", "uploadpack.allowFilter", "true")
	write := func(name, body string) {
		p := filepath.Join(dir, name)
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte(body), 0o644)
	}
	f := &fixture{dir: dir, fixMsg: ghsaMsg, keywordMsg: "fix permission bypass in upload handler"}
	write("app/files.py", filesV1)
	write("app/upload.py", uploadV1)
	git(t, dir, now, "add", "-A")
	git(t, dir, now.AddDate(0, 0, -45), "commit", "-q", "-m", "initial import")
	f.c1 = git(t, dir, now, "rev-parse", "HEAD")
	git(t, dir, now, "tag", "v1.0")
	write("app/files.py", filesFixed)
	git(t, dir, now, "commit", "-q", "-am", f.fixMsg)
	f.c2 = git(t, dir, now, "rev-parse", "HEAD")
	write("app/upload.py", uploadFixed)
	git(t, dir, now.AddDate(0, 0, -10), "commit", "-q", "-am", f.keywordMsg)
	f.c3 = git(t, dir, now, "rev-parse", "HEAD")
	if tagAt != "" {
		git(t, dir, now, "tag", "-f", "v1.0", tagAt)
	}
	// Re-date c2 properly: commits were authored with explicit dates above.
	return f
}

func (f *fixture) commitJSON(t *testing.T, sha string, withFiles bool) map[string]any {
	msg := git(t, f.dir, time.Now(), "log", "-1", "--format=%B", sha)
	date := git(t, f.dir, time.Now(), "log", "-1", "--format=%cI", sha)
	m := map[string]any{
		"sha": sha,
		"commit": map[string]any{
			"message":   msg,
			"author":    map[string]any{"date": date, "email": "dev@example.invalid"},
			"committer": map[string]any{"date": date},
		},
		"author": map[string]any{"login": "dev"},
	}
	if withFiles {
		var files []map[string]any
		names := git(t, f.dir, time.Now(), "diff-tree", "--no-commit-id", "--name-only", "-r", sha)
		for _, n := range strings.Fields(names) {
			patch := git(t, f.dir, time.Now(), "diff", sha+"^", sha, "--unified=3", "--", n)
			if i := strings.Index(patch, "@@"); i >= 0 {
				patch = patch[i:]
			}
			files = append(files, map[string]any{"filename": n, "status": "modified", "patch": patch})
		}
		m["files"] = files
	}
	return m
}

type apiOpts struct {
	noRelease bool
	tag       string
}

func (f *fixture) api(t *testing.T, o apiOpts) *httptest.Server {
	tag := o.tag
	if tag == "" {
		tag = "v1.0"
	}
	all := []map[string]any{f.commitJSON(t, f.c3, false), f.commitJSON(t, f.c2, false), f.commitJSON(t, f.c1, false)}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		enc := json.NewEncoder(w)
		switch {
		case path == "/repos/o/r":
			enc.Encode(map[string]any{"default_branch": "main"})
		case path == "/repos/o/r/releases/latest":
			if o.noRelease {
				w.WriteHeader(404)
				return
			}
			enc.Encode(map[string]any{"tag_name": tag, "published_at": time.Now().AddDate(0, 0, -40).Format(time.RFC3339)})
		case path == "/repos/o/r/security-advisories":
			w.Write([]byte("[]"))
		case path == "/repos/o/r/commits":
			if r.URL.Query().Get("page") == "1" {
				enc.Encode(all)
			} else {
				w.Write([]byte("[]"))
			}
		case path == "/search/commits":
			w.Write([]byte(`{"items":[]}`))
		case strings.HasPrefix(path, "/repos/o/r/commits/"):
			sha := strings.TrimPrefix(path, "/repos/o/r/commits/")
			enc.Encode(f.commitJSON(t, sha, true))
		case strings.HasPrefix(path, "/repos/o/r/contents/"):
			p := strings.TrimPrefix(path, "/repos/o/r/contents/")
			cmd := exec.Command("git", "-C", f.dir, "show", r.URL.Query().Get("ref")+":"+p)
			out, err := cmd.Output()
			if err != nil {
				w.WriteHeader(404)
				return
			}
			enc.Encode(map[string]any{"encoding": "base64", "content": b64(out)})
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func b64(b []byte) string {
	const tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var sb strings.Builder
	for i := 0; i < len(b); i += 3 {
		var n uint32
		l := 0
		for j := 0; j < 3; j++ {
			n <<= 8
			if i+j < len(b) {
				n |= uint32(b[i+j])
				l++
			}
		}
		for j := 0; j < 4; j++ {
			if j <= l {
				sb.WriteByte(tbl[(n>>(18-6*uint(j)))&63])
			} else {
				sb.WriteByte('=')
			}
		}
	}
	return sb.String()
}

func (f *fixture) config(srv *httptest.Server, p judge.Provider) scan.Config {
	c := ghapi.New("tok")
	c.BaseURL = srv.URL
	return scan.Config{
		Config: detect.Config{
			Client: c, Token: "tok", Workers: 2,
			CloneURL: func(model.RepoRef) string { return "file://" + f.dir },
		},
		Provider: p,
	}
}

var ref = model.RepoRef{Owner: "o", Name: "r"}

func TestGapDefaultMode(t *testing.T) {
	f := newFixture(t, "add access check (GHSA-2222-3333-4444)", "")
	srv := f.api(t, apiOpts{})
	out, err := scan.Run(context.Background(), f.config(srv, nil), ref)
	if err != nil {
		t.Fatal(err)
	}
	if out.Verdict != scan.Gap || len(out.Findings) != 1 {
		t.Fatalf("verdict %s %q findings %d", out.Verdict, out.Detail, len(out.Findings))
	}
	c := out.Findings[0].Cand
	if c.Commit.SHA != f.c2 || !c.VendorSignalled() || c.Release.Path != "app/files.py" {
		t.Errorf("finding %+v release %+v", c.Commit.SHA, c.Release)
	}
	// The keyword-only commit must not be searched without --ai.
	for _, cand := range out.Result.Candidates {
		if cand.Commit.SHA == f.c3 {
			t.Error("keyword tier enumerated in default mode")
		}
	}
	md := report.Markdown(out, "test")
	for _, want := range []string{"Verdict: GAP", f.c2, "git merge-base --is-ancestor", "app/files.py", "cherry-pick"} {
		if !strings.Contains(md, want) {
			t.Errorf("report missing %q", want)
		}
	}
}

func TestNoGapWhenTagCarriesFix(t *testing.T) {
	f := newFixture(t, "add access check (GHSA-2222-3333-4444)", "")
	git(t, f.dir, time.Now(), "tag", "-f", "v1.0", f.c3)
	srv := f.api(t, apiOpts{})
	out, err := scan.Run(context.Background(), f.config(srv, nil), ref)
	if err != nil {
		t.Fatal(err)
	}
	if out.Verdict != scan.NoGap {
		t.Fatalf("verdict %s %q", out.Verdict, out.Detail)
	}
}

func TestNotSearchedNeverNoGap(t *testing.T) {
	f := newFixture(t, "add access check (GHSA-2222-3333-4444)", "")
	srv := f.api(t, apiOpts{noRelease: true})
	out, err := scan.Run(context.Background(), f.config(srv, nil), ref)
	if err != nil || out.Verdict != scan.NotSearched || out.Detail != "publishes no GitHub releases" {
		t.Fatalf("%+v %v", out, err)
	}
	// No vendor signal: the fix message carries no GHSA/tracker.
	f2 := newFixture(t, "add access check", "")
	out, err = scan.Run(context.Background(), f2.config(f2.api(t, apiOpts{}), nil), ref)
	if err != nil || out.Verdict != scan.NotSearched {
		t.Fatalf("no signal: %+v %v", out, err)
	}
	if !strings.Contains(report.Markdown(out, "t"), "NOT SEARCHED is not a clean result") {
		t.Error("report must say NOT SEARCHED is not clean")
	}
}

type fakeJudge struct{ defect bool }

func (f fakeJudge) Name() string { return "fake" }
func (f fakeJudge) Ask(context.Context, string) (string, error) {
	return fmt.Sprintf(`{"reachable":true,"defect":%v,"confidence":"high","mechanism":"upload lacks a write check"}`, f.defect), nil
}

func TestAIModeShowsOnlyJudgedDefects(t *testing.T) {
	f := newFixture(t, "add access check (GHSA-2222-3333-4444)", "")
	srv := f.api(t, apiOpts{})

	out, err := scan.Run(context.Background(), f.config(srv, fakeJudge{defect: true}), ref)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Findings) != 2 || out.Findings[0].Verdict != nil || out.Findings[1].Verdict == nil {
		t.Fatalf("want vendor finding then judged keyword finding, got %d", len(out.Findings))
	}
	if out.Findings[1].Cand.Commit.SHA != f.c3 {
		t.Error("wrong keyword finding")
	}

	out, err = scan.Run(context.Background(), f.config(srv, fakeJudge{defect: false}), ref)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Findings) != 1 || out.HiddenNotDefect != 1 {
		t.Fatalf("findings %d hidden %d", len(out.Findings), out.HiddenNotDefect)
	}
}

type brokenJudge struct{}

func (brokenJudge) Name() string { return "broken" }
func (brokenJudge) Ask(context.Context, string) (string, error) {
	return "I cannot help", nil
}

func TestUnjudgedIsNotNoGap(t *testing.T) {
	// Only a keyword-tier exposure exists; the judge never answers.
	f := newFixture(t, "add access check (GHSA-2222-3333-4444)", "")
	// Make the vendor-signalled fix present at the tag, leaving only c3 exposed.
	git(t, f.dir, time.Now(), "tag", "-f", "v1.0", f.c2)
	srv := f.api(t, apiOpts{})
	out, err := scan.Run(context.Background(), f.config(srv, brokenJudge{}), ref)
	if err != nil {
		t.Fatal(err)
	}
	if out.Verdict != scan.NotSearched || out.Unjudged != 1 {
		t.Fatalf("verdict %s unjudged %d", out.Verdict, out.Unjudged)
	}
}

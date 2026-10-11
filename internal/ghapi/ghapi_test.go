package ghapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/orcasecurity-research/bgh/internal/model"
)

func newTest(t *testing.T, h http.Handler) *Client {
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c := New("tok")
	c.BaseURL = srv.URL
	c.sleep = func(context.Context, time.Duration) error { return nil }
	return c
}

func TestResolveTokenOrder(t *testing.T) {
	env := map[string]string{"GITHUB_TOKEN": "b", "GH_TOKEN": "a"}
	get := func(k string) string { return env[k] }
	if tok, _ := resolveToken(get, func() string { return "gh" }); tok != "a" {
		t.Errorf("GH_TOKEN first, got %q", tok)
	}
	delete(env, "GH_TOKEN")
	if tok, _ := resolveToken(get, func() string { return "gh" }); tok != "b" {
		t.Errorf("then GITHUB_TOKEN, got %q", tok)
	}
	delete(env, "GITHUB_TOKEN")
	if tok, _ := resolveToken(get, func() string { return "gh" }); tok != "gh" {
		t.Errorf("then gh login, got %q", tok)
	}
	if _, err := resolveToken(get, func() string { return "" }); !errors.Is(err, ErrNoToken) {
		t.Errorf("want ErrNoToken, got %v", err)
	}
}

func TestRateLimitRetry(t *testing.T) {
	var n atomic.Int32
	var slept time.Duration
	c := newTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) == 1 {
			w.Header().Set("X-RateLimit-Remaining", "0")
			w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(30*time.Second).Unix(), 10))
			w.WriteHeader(403)
			return
		}
		if r.Header.Get("Authorization") != "Bearer tok" {
			t.Error("missing bearer token")
		}
		w.Write([]byte(`{"ok":true}`))
	}))
	c.sleep = func(_ context.Context, d time.Duration) error { slept += d; return nil }
	var out struct{ OK bool }
	if err := c.Get(context.Background(), "/x", nil, &out); err != nil || !out.OK {
		t.Fatalf("err=%v out=%+v", err, out)
	}
	if slept < 30*time.Second || n.Load() != 2 {
		t.Errorf("slept %s over %d calls", slept, n.Load())
	}
}

func TestPlain403IsNotRetried(t *testing.T) {
	var n atomic.Int32
	c := newTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		w.WriteHeader(403)
	}))
	if err := c.Get(context.Background(), "/x", nil, nil); err == nil || n.Load() != 1 {
		t.Fatalf("err=%v calls=%d", err, n.Load())
	}
}

func TestNotFoundAndUnprocessableOptional(t *testing.T) {
	c := newTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/a" {
			w.WriteHeader(404)
		} else {
			w.WriteHeader(422)
		}
	}))
	for _, p := range []string{"/a", "/b"} {
		ok, err := c.GetOptional(context.Background(), p, nil, nil)
		if ok || err != nil {
			t.Errorf("%s: ok=%v err=%v", p, ok, err)
		}
	}
}

func TestBudget(t *testing.T) {
	c := newTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{}`)) }))
	c.Limit = 2
	var be *BudgetError
	var err error
	for i := 0; i < 3 && err == nil; i++ {
		err = c.Get(context.Background(), "/x", nil, nil)
	}
	if !errors.As(err, &be) {
		t.Fatalf("want budget error, got %v", err)
	}
}

func TestPaginateAndLinked(t *testing.T) {
	var srvURL string
	c := newTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/pages":
			if r.URL.Query().Get("page") == "1" {
				w.Write([]byte(`[1,2]`))
			} else {
				w.Write([]byte(`[3]`))
			}
		case "/linked":
			if r.URL.Query().Get("cursor") == "" {
				w.Header().Set("Link", `<`+srvURL+`/linked?cursor=2>; rel="next"`)
				w.Write([]byte(`[{"a":1}]`))
			} else {
				w.Write([]byte(`[{"a":2}]`))
			}
		}
	}))
	srvURL = c.BaseURL
	got, err := c.Paginate(context.Background(), "/pages", url.Values{"per_page": {"2"}}, 5)
	if err != nil || len(got) != 3 {
		t.Fatalf("paginate: %v %d", err, len(got))
	}
	got, err = c.PaginateLinked(context.Background(), "/linked", nil, 5)
	if err != nil || len(got) != 2 {
		t.Fatalf("linked: %v %d", err, len(got))
	}
}

func TestRepoAPI(t *testing.T) {
	c := newTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/o/r/releases/latest":
			w.Write([]byte(`{"tag_name":"v1.2.3","published_at":"2026-05-01T10:00:00Z","target_commitish":"main"}`))
		case "/repos/o/r/commits/abc":
			w.Write([]byte(`{"sha":"abc","commit":{"message":"m","author":{"date":"2026-01-01T00:00:00Z"},"committer":{"date":"2026-01-02T00:00:00Z"}},
			"files":[{"filename":"a/b.go","status":"modified","patch":"@@ -1 +1 @@\n-x\n+y"}]}`))
		case "/repos/o/r/contents/dir/f x.go":
			w.Write([]byte(`{"encoding":"base64","content":"aGVsbG8K"}`))
		case "/repos/o/r/security-advisories":
			w.Write([]byte(`[{"state":"published","ghsa_id":"GHSA-aaaa-bbbb-cccc","description":"fixed in https://github.com/o/r/commit/abcdef1 and https://github.com/o/r/pull/12"},
			{"state":"draft","ghsa_id":"GHSA-xxxx-xxxx-xxxx"}]`))
		default:
			w.WriteHeader(404)
		}
	}))
	api := &RepoAPI{C: c, Ref: model.RepoRef{Owner: "o", Name: "r"}}
	ctx := context.Background()
	rel, err := api.LatestRelease(ctx)
	if err != nil || rel == nil || rel.Tag != "v1.2.3" {
		t.Fatalf("release %+v %v", rel, err)
	}
	patch, _ := api.CommitPatch(ctx, "abc")
	want := "diff --git a/a/b.go b/a/b.go\n--- a/a/b.go\n+++ b/a/b.go\n@@ -1 +1 @@\n-x\n+y"
	if patch != want {
		t.Errorf("patch = %q", patch)
	}
	if s, ok, _ := api.FileAt(ctx, "v1", "dir/f x.go"); !ok || s != "hello\n" {
		t.Errorf("file = %q %v", s, ok)
	}
	if _, ok, _ := api.FileAt(ctx, "v1", "missing"); ok {
		t.Error("missing file reported present")
	}
	advs := api.Advisories(ctx)
	if len(advs) != 1 || len(advs[0].FixSHAs) != 1 || advs[0].FixPRs[0] != 12 {
		t.Errorf("advisories = %+v", advs)
	}
}

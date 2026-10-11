// Package gitrepo shells out to the user's installed git.
//
// Blobless partial clone is mandatory, not an optimisation: a full clone of a
// large repository can fail and delete itself while the exit code still reads
// 0 when piped. Every clone here is verified by inspecting the result, never
// by trusting a status.
package gitrepo

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/orcasecurity-research/bgh/internal/model"
)

const (
	recordSep = "\x1e" // safe inside commit messages
	fieldSep  = "\x1f"
)

// Repo is a local (bare) git repository.
type Repo struct {
	Path string
	// Env is extra environment for every git call (credentials live here, in
	// memory only).
	Env []string
}

// AuthEnv returns environment that makes git send the token to github.com
// over https without writing it to disk or argv.
func AuthEnv(token string) []string {
	env := []string{"GIT_TERMINAL_PROMPT=0", "GIT_ASKPASS=true"}
	if token == "" {
		return env
	}
	basic := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + token))
	return append(env,
		"GIT_CONFIG_COUNT=1",
		"GIT_CONFIG_KEY_0=http.https://github.com/.extraheader",
		"GIT_CONFIG_VALUE_0=Authorization: Basic "+basic,
	)
}

// Error is a failed git invocation.
type Error struct {
	Args   string
	Stderr string
}

func (e *Error) Error() string { return fmt.Sprintf("git %s: %s", e.Args, e.Stderr) }

func (r *Repo) command(ctx context.Context, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", r.Path}, args...)...)
	cmd.Env = append(os.Environ(), r.Env...)
	return cmd
}

// Run runs git and returns stdout. A non-zero exit is an *Error.
func (r *Repo) Run(ctx context.Context, args ...string) (string, error) {
	cmd := r.command(ctx, args...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		n := len(args)
		if n > 3 {
			n = 3
		}
		msg := strings.TrimSpace(errb.String())
		if len(msg) > 400 {
			msg = msg[:400]
		}
		return out.String(), &Error{Args: strings.Join(args[:n], " "), Stderr: msg}
	}
	return out.String(), nil
}

// OK reports whether a git command exits 0.
func (r *Repo) OK(ctx context.Context, args ...string) bool {
	return r.command(ctx, args...).Run() == nil
}

// Init creates an empty bare repository at path, configured as a blobless
// promisor of url.
func Init(ctx context.Context, path, url string, env []string) (*Repo, error) {
	cmd := exec.CommandContext(ctx, "git", "init", "--bare", "-q", path)
	cmd.Env = append(os.Environ(), env...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("git init: %s", strings.TrimSpace(string(out)))
	}
	r := &Repo{Path: path, Env: env}
	for _, args := range [][]string{
		{"remote", "add", "origin", url},
		// Mark the remote as a promisor so missing blobs are fetched on demand.
		{"config", "remote.origin.promisor", "true"},
		{"config", "remote.origin.partialclonefilter", "blob:none"},
	} {
		if _, err := r.Run(ctx, args...); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// FetchOptions selects what a blobless fetch brings down.
type FetchOptions struct {
	Branch string // default branch
	Tag    string // the release tag, fetched by name; "" for none
	// ShallowSince is a YYYY-MM-DD cut on history ("" for complete history).
	// It is safe for the two history questions this tool asks - "is the fix
	// an ancestor of this tag" and "did the tag land after the fix" - because
	// the fix and the tag both sit inside the window, so any path between
	// them does too.
	ShallowSince string
}

// Fetch brings the default branch and the release tag down, trees and commits
// only, then verifies the result.
func (r *Repo) Fetch(ctx context.Context, o FetchOptions) error {
	specs := []string{fmt.Sprintf("+refs/heads/%s:refs/heads/%s", o.Branch, o.Branch)}
	if o.Tag != "" {
		specs = append(specs, fmt.Sprintf("+refs/tags/%s:refs/tags/%s", o.Tag, o.Tag))
	}
	args := []string{"fetch", "--filter=blob:none", "--force", "-q", "--no-tags"}
	if o.ShallowSince != "" {
		args = append(args, "--shallow-since="+o.ShallowSince)
	}
	args = append(args, "origin")
	args = append(args, specs...)
	_, err := r.Run(ctx, args...)
	if err != nil && o.ShallowSince != "" && ctx.Err() == nil {
		// A repository quiet for longer than the cut has "no commits selected
		// for shallow requests". Fall back to complete history.
		o.ShallowSince = ""
		return r.Fetch(ctx, o)
	}
	if err != nil {
		return err
	}
	if _, err := r.Run(ctx, "symbolic-ref", "HEAD", "refs/heads/"+o.Branch); err != nil {
		return err
	}
	return r.Verify(ctx)
}

// Verify asserts the clone is real and usable. Never infer this from an exit code.
func (r *Repo) Verify(ctx context.Context) error {
	if _, err := os.Stat(r.Path); err != nil {
		return fmt.Errorf("%s does not exist", r.Path)
	}
	if !r.OK(ctx, "rev-parse", "--git-dir") {
		return fmt.Errorf("%s is not a git repository", r.Path)
	}
	head, _ := r.Run(ctx, "rev-parse", "HEAD")
	if len(strings.TrimSpace(head)) != 40 {
		return errors.New("HEAD does not resolve to a commit")
	}
	n, _ := r.Run(ctx, "rev-list", "--count", "HEAD")
	if c := strings.TrimSpace(n); c == "" || c == "0" {
		return errors.New("HEAD has no reachable history")
	}
	return nil
}

// ExistsRev reports whether rev resolves to a commit.
func (r *Repo) ExistsRev(ctx context.Context, rev string) bool {
	return r.OK(ctx, "rev-parse", "--verify", "--quiet", rev+"^{commit}")
}

// IsAncestor reports whether ancestor is reachable from descendant.
func (r *Repo) IsAncestor(ctx context.Context, ancestor, descendant string) bool {
	return r.OK(ctx, "merge-base", "--is-ancestor", ancestor, descendant)
}

// Log lists commits on rev since a YYYY-MM-DD date. Regex filtering is done by
// the caller in Go: git's --grep flavour depends on how the binary was built,
// and silently matching nothing is the worst possible failure for this tool.
func (r *Repo) Log(ctx context.Context, rev, since string, limit int) ([]model.Commit, error) {
	format := strings.Join([]string{"%H", "%an", "%ae", "%cI", "%aI", "%P", "%B"}, fieldSep) + recordSep
	args := []string{"log", rev, "--format=" + format, fmt.Sprintf("--max-count=%d", limit)}
	if since != "" {
		args = append(args, "--since="+since)
	}
	out, err := r.Run(ctx, args...)
	if err != nil {
		return nil, err
	}
	var commits []model.Commit
	for _, rec := range strings.Split(out, recordSep) {
		rec = strings.Trim(rec, "\n")
		if strings.TrimSpace(rec) == "" {
			continue
		}
		parts := strings.Split(rec, fieldSep)
		if len(parts) < 7 {
			continue
		}
		c := model.Commit{
			SHA:         strings.TrimSpace(parts[0]),
			Message:     strings.Join(parts[6:], fieldSep),
			Committed:   parseISO(parts[3]),
			Authored:    parseISO(parts[4]),
			AuthorLogin: strings.TrimSpace(parts[1]),
			AuthorEmail: strings.TrimSpace(parts[2]),
			Parents:     strings.Fields(parts[5]),
		}
		commits = append(commits, c)
	}
	return commits, nil
}

func parseISO(s string) time.Time {
	t, err := time.Parse(time.RFC3339, strings.TrimSpace(s))
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

// CommitDate is a commit's committer date; zero if unreadable.
func (r *Repo) CommitDate(ctx context.Context, rev string) time.Time {
	out, err := r.Run(ctx, "show", "-s", "--format=%cI", rev)
	if err != nil {
		return time.Time{}
	}
	return parseISO(out)
}

// TreeIndex maps path -> blob oid for a whole ref. Trees only; fetches no blobs.
//
// On a partial clone every unseen blob is a network round trip that git
// answers with a whole pack, so file contents come from the API instead. This
// makes path search - including finding a file that moved - free.
func (r *Repo) TreeIndex(ctx context.Context, rev string) (map[string]string, error) {
	out, err := r.Run(ctx, "ls-tree", "-r", "-z", rev)
	if err != nil {
		return nil, err
	}
	index := map[string]string{}
	for _, ent := range strings.Split(out, "\x00") {
		meta, path, ok := strings.Cut(ent, "\t")
		if !ok || path == "" {
			continue
		}
		f := strings.Fields(meta)
		if len(f) >= 3 && f[1] == "blob" {
			index[path] = f[2]
		}
	}
	return index, nil
}

// ReadBlob returns a blob's contents by oid (a lazy fetch on a partial clone).
func (r *Repo) ReadBlob(ctx context.Context, oid string) (string, bool) {
	out, err := r.Run(ctx, "cat-file", "-p", oid)
	if err != nil {
		return "", false
	}
	return out, true
}

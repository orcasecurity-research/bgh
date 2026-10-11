package gitrepo

import (
	"context"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuthEnvKeepsTokenOutOfArgv(t *testing.T) {
	env := strings.Join(AuthEnv("s3cret"), "\n")
	b := base64.StdEncoding.EncodeToString([]byte("x-access-token:s3cret"))
	if !strings.Contains(env, "GIT_CONFIG_VALUE_0=Authorization: Basic "+b) ||
		!strings.Contains(env, "http.https://github.com/.extraheader") {
		t.Errorf("env = %s", env)
	}
	if strings.Contains(strings.Join(AuthEnv(""), ""), "extraheader") {
		t.Error("no token, no header")
	}
}

func TestLogTreeAndAncestry(t *testing.T) {
	dir := t.TempDir()
	run := func(args ...string) {
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=a", "GIT_AUTHOR_EMAIL=a@x.invalid",
			"GIT_COMMITTER_NAME=a", "GIT_COMMITTER_EMAIL=a@x.invalid", "GIT_CONFIG_GLOBAL=/dev/null")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%v: %s", args, out)
		}
	}
	run("init", "-q", "-b", "main")
	os.MkdirAll(filepath.Join(dir, "a b"), 0o755)
	os.WriteFile(filepath.Join(dir, "a b", "f.txt"), []byte("1\n"), 0o644)
	run("add", "-A")
	run("commit", "-q", "-m", "first\n\nbody with GHSA-2222-3333-4444")
	run("tag", "v1")
	os.WriteFile(filepath.Join(dir, "g.txt"), []byte("2\n"), 0o644)
	run("add", "-A")
	run("commit", "-q", "-m", "second")

	r := &Repo{Path: dir}
	ctx := context.Background()
	log, err := r.Log(ctx, "main", "", 10)
	if err != nil || len(log) != 2 || log[1].Subject() != "first" || !strings.Contains(log[1].Message, "GHSA-2222") {
		t.Fatalf("%+v %v", log, err)
	}
	idx, err := r.TreeIndex(ctx, "v1")
	if err != nil || len(idx) != 1 || idx["a b/f.txt"] == "" {
		t.Fatalf("%v %v", idx, err)
	}
	if !r.IsAncestor(ctx, "v1", "main") || r.IsAncestor(ctx, "main", "v1") {
		t.Error("ancestry")
	}
	if !r.ExistsRev(ctx, "refs/tags/v1") || r.ExistsRev(ctx, "refs/tags/nope") {
		t.Error("ExistsRev")
	}
}

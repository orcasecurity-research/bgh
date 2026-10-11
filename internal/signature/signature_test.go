package signature

import (
	"strings"
	"testing"
)

const guardPatch = `diff --git a/app/files.py b/app/files.py
--- a/app/files.py
+++ b/app/files.py
@@ -10,6 +10,10 @@ def download_file(request, name):
     user = request.user
+    if not user.can_read(name):
+        raise Forbidden("no access to file")
+    if name not in ALLOWED_FILES:
+        raise Forbidden("file not allowed")
     path = resolve_path(name)
     data = open(path).read()
     return Response(data)
`

func TestSalientWordStart(t *testing.T) {
	yes := []string{"has_permission(x)", "hasPermission(x)", "if auth:", ".filter(a)", "Token"}
	no := []string{"assignee", "invalidateCache", "resignation_date"}
	for _, s := range yes {
		if !Salient(s) {
			t.Errorf("Salient(%q) = false, want true", s)
		}
	}
	for _, s := range no {
		if Salient(s) {
			t.Errorf("Salient(%q) = true, want false", s)
		}
	}
}

func TestProseVsCode(t *testing.T) {
	if !IsProse("this function returns the user that owns the thing") {
		t.Error("sentence should be prose")
	}
	if IsProse("if hostname not in ALLOWED_DOWNLOAD_HOSTS:") {
		t.Error("guard line must be code")
	}
	if IsProse("x = foo(bar) + baz") {
		t.Error("expression must be code")
	}
}

func TestParsePatchRemovedDashLine(t *testing.T) {
	p := "diff --git a/q.sql b/q.sql\n--- a/q.sql\n+++ b/q.sql\n@@ -1,2 +1,2 @@\n--- note\n+SELECT 1\n"
	fd := ParsePatch(p)
	if len(fd) != 1 || len(fd[0].Removed) != 1 || fd[0].Removed[0] != "-- note" {
		t.Fatalf("removed line starting with '-- ' mis-parsed: %+v", fd)
	}
}

func TestBuildSignatureContextShape(t *testing.T) {
	sig := BuildSignature(guardPatch, 14)
	if sig == nil || !sig.Usable() {
		t.Fatalf("expected a usable signature, got %+v", sig)
	}
	if sig.Path != "app/files.py" || sig.Symbol != "def download_file(request, name):" {
		t.Errorf("path/symbol = %q / %q", sig.Path, sig.Symbol)
	}
	if sig.VulnShapeKind() != ShapeContext {
		t.Errorf("shape = %s, want context", sig.VulnShapeKind())
	}
	found := false
	for _, id := range sig.FixIdentifiers {
		if id == "ALLOWED_FILES" {
			found = true
		}
		if id == "request" {
			t.Errorf("borrowed name %q must not be a fix identifier", id)
		}
	}
	if !found {
		t.Errorf("ALLOWED_FILES missing from %v", sig.FixIdentifiers)
	}
}

const unpatched = `def download_file(request, name):
    user = request.user
    path = resolve_path(name)
    data = open(path).read()
    return Response(data)
`

func TestPresenceUnpatchedIsStillVulnerable(t *testing.T) {
	sig := BuildSignature(guardPatch, 14)
	p := TestPresence(unpatched, sig)
	if p.Verdict != FixAbsent || !p.StillVulnerable() {
		t.Fatalf("unpatched file: %+v", p)
	}
}

func TestPresencePatchedAndReworded(t *testing.T) {
	sig := BuildSignature(guardPatch, 14)
	patched := strings.Replace(unpatched, "    path =", "    if not user.can_read(name):\n        raise Forbidden(\"no access to file\")\n    if name not in ALLOWED_FILES:\n        raise Forbidden(\"file not allowed\")\n    path =", 1)
	if p := TestPresence(patched, sig); p.Verdict != FixPresent || p.StillVulnerable() {
		t.Fatalf("patched file: %+v", p)
	}
	// Reworded backport: guard rewritten but the allowlist name survives.
	reworded := strings.Replace(unpatched, "    path =", "    check_allowed(name, ALLOWED_FILES)\n    path =", 1)
	p := TestPresence(reworded, sig)
	if p.StillVulnerable() {
		t.Fatalf("reworded backport must not be a gap: %+v", p)
	}
}

func TestPresenceMovedShimIsNotAGap(t *testing.T) {
	sig := BuildSignature(guardPatch, 14)
	shim := "from app.new_files import download_file\n"
	if p := TestPresence(shim, sig); p.StillVulnerable() {
		t.Fatalf("shim must not be vulnerable: %+v", p)
	}
}

const removedPatch = `diff --git a/srv/auth.go b/srv/auth.go
--- a/srv/auth.go
+++ b/srv/auth.go
@@ -5,5 +5,5 @@ func Login(r *Request) error {
-	if r.User.Token == adminDefaultToken {
-		return grantAdmin(r)
-	}
+	if err := verifyToken(r.User.Token); err != nil {
+		return denyLogin(r, err)
+	}
 	return nil
`

func TestRemovedShape(t *testing.T) {
	sig := BuildSignature(removedPatch, 14)
	if sig == nil || sig.VulnShapeKind() != ShapeRemoved {
		t.Fatalf("sig = %+v", sig)
	}
	old := "func Login(r *Request) error {\n\tif r.User.Token == adminDefaultToken {\n\t\treturn grantAdmin(r)\n\t}\n\treturn nil\n}\n"
	if p := TestPresence(old, sig); !p.StillVulnerable() {
		t.Fatalf("old code should be vulnerable: %+v", p)
	}
}

func TestGradeDiffDirection(t *testing.T) {
	hard := "diff --git a/srv/a.go b/srv/a.go\n--- a/srv/a.go\n+++ b/srv/a.go\n@@ -1,3 +1,5 @@ func H() {\n+\tif !user.CanRead(x) {\n+\t\treturn errForbidden\n+\t}\n \tserveTheFile(x)\n"
	if ev := GradeDiff(hard); ev.Direction != Hardening {
		t.Errorf("hardening patch graded %s", ev.Direction)
	}
	loosen := strings.ReplaceAll(hard, "\n+\t", "\n-\t")
	if ev := GradeDiff(loosen); ev.Direction != Loosening {
		t.Errorf("reversed patch graded %s", ev.Direction)
	}
	skip := "diff --git a/docs/x.md b/docs/x.md\n--- a/docs/x.md\n+++ b/docs/x.md\n@@ -1 +1 @@\n-a\n+b\n"
	if BuildSignature(skip, 14) != nil {
		t.Error("docs-only patch must yield no signature")
	}
}

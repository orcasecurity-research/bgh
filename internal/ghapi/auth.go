package ghapi

import (
	"errors"
	"os"
	"strings"

	"github.com/cli/go-gh/v2/pkg/auth"
)

// ErrNoToken is returned when no credential could be found.
var ErrNoToken = errors.New("no GitHub credentials found: set GH_TOKEN or GITHUB_TOKEN, or run `gh auth login`")

// ResolveToken finds a GitHub token: GH_TOKEN, then GITHUB_TOKEN, then the
// user's gh login (via go-gh). The token is returned in memory only.
func ResolveToken() (string, error) {
	return resolveToken(os.Getenv, func() string {
		tok, _ := auth.TokenForHost("github.com")
		return tok
	})
}

func resolveToken(getenv func(string) string, ghLogin func() string) (string, error) {
	for _, v := range []string{"GH_TOKEN", "GITHUB_TOKEN"} {
		if t := strings.TrimSpace(getenv(v)); t != "" {
			return t, nil
		}
	}
	if t := strings.TrimSpace(ghLogin()); t != "" {
		return t, nil
	}
	return "", ErrNoToken
}

// Command bgh is the Backport Gap Hunter: given a GitHub repository, it asks
// whether the tag behind "Latest release" lacks a security fix that is already
// on the default branch, with the pre-fix code still present in that tag.
package main

import (
	"os"

	"github.com/orcasecurity-research/bgh/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}

# bgh - Backport Gap Hunter

`bgh` checks whether the version people actually download from a GitHub repository is missing a fix that the maintainers already merged.

Point it at a repository. It answers one question: **does the tag behind GitHub's "Latest release" lack a security fix that is already on the default branch, while the pre-fix code is still present in that tag?**

It is built for people protecting their own repositories and applications: if you ship or depend on a project, this tells you which fixes you are not getting from its newest release.

## What is a backport gap?

Projects fix bugs on their default branch first. A fix only reaches users when it is released, and older release lines need the fix *backported* to them. A **backport gap** is the window where a fix is public on the default branch, but the release people install does not contain it. Anyone who reads the commit can see exactly what was wrong, and the release you run is still vulnerable.

## Why "bgh"?

**B**ackport **G**ap **H**unter. The name is the job: hunt for gaps between the default branch and the shipped release.

## Install

```sh
go install github.com/orcasecurity-research/bgh@latest
```

Requirements: Go, and `git` on your `PATH`. The binary is named `bgh`.

Credentials are read in this order: `GH_TOKEN`, `GITHUB_TOKEN`, then your `gh` login (run `gh auth login` once). Without any of them bgh exits and tells you so. The token is held in memory and handed to `git` through environment variables only; it is never written to disk or put on a command line.

## Usage

```sh
bgh owner/repo
bgh https://github.com/owner/repo
bgh --ai owner/repo            # add the keyword tier, judged by claude or codex
bgh --ai=codex owner/repo      # force a provider
bgh -o report.md owner/repo    # choose the report path
```

You get a short summary in the terminal and a markdown report at `./<owner>-<repo>.md` (or the path given to `-o`). Each gap section carries what you need to check it and fix it by hand: the fix commit, the Latest tag that lacks it, the signal that flagged it, the evidence, commands to verify, and the diff to port.

### Verdicts and exit codes

| Verdict | Exit code | Meaning |
|---|---|---|
| `NO GAP` | 0 | Nothing was found missing from the Latest release. |
| `GAP` | 1 | A fix on the default branch is missing from the Latest release, and the pre-fix code is still there. |
| `NOT SEARCHED` | 2 | The scan was refused or failed. Nothing was compared. |

`NOT SEARCHED` is never the same as `NO GAP`. A repository with no GitHub releases, an archived repository, or one where no detector can be derived was not searched, and the report says exactly what was looked for. Treat exit code 2 as "no answer", not "clean".

### Default mode

By default bgh only trusts signals the vendor leaked themselves, learned from the repository's own advisories and recent commits with no per-vendor configuration:

- **ghsa**: a commit message citing a GHSA id (GitHub writes these when a private security fork is merged).
- **tracker**: an internal tracker id such as `SEC-123` that recurs in security fixes.
- **private-fork-pr**: a "Merge pull request #N" whose number does not resolve to a public pull request.

Commits already tied to a published advisory are removed. For each remaining commit bgh builds a testable signature from the diff and reads the file at the Latest tag over the API (never GitHub's commit search, which only covers the default branch). A gap needs the fix absent *and* the pre-fix code positively present. A file that moved or was renamed is followed; changes that loosen a check are not reported.

### `--ai` mode

`--ai` adds the keyword tier: generic security vocabulary in commit messages. On its own that tier is noisy, so each keyword finding is handed to an AI CLI along with the shipped code and a bounded walk of its callers. Only findings the judge rates as a real defect are shown; the rest are hidden and counted. Findings carrying a vendor signal are always shown and are not judged.

bgh uses whichever of `claude` or `codex` is on your `PATH` (`claude` first). `--ai=claude` or `--ai=codex` forces one. No model is selected: the CLI's default applies. The judge runs with tools disabled (Claude) or a read-only sandbox (Codex), in an empty scratch directory, because the prompt embeds untrusted code.

If the judge gives no answer on a candidate, bgh does not call it `NO GAP`; with nothing else to show it reports `NOT SEARCHED`.

### Privacy

**`--ai` sends code to a third party.** For each keyword finding the diff, the shipped file at the Latest tag (up to 12,000 characters each), the commit subject and matching call-site lines are sent to the CLI you chose, and so to its vendor: Anthropic for `claude`, OpenAI for `codex`. Default mode does not use any AI and sends nothing beyond GitHub API calls and git fetches to github.com. Only run `--ai` on code you are allowed to share with that vendor.

## Limits

- A gap is a measurement of what shipped, not proof of a vulnerability or of exploitability. Read the diff before you act.
- Only public repositories, only the default branch's last 180 days of commits, and at most 400 candidates per run.
- The Latest release is the only ref tested. Other release lines are not.
- Thresholds err towards refusing to decide, so a missed gap is likelier than a false one.

## License

Apache-2.0. Copyright Orca Security.

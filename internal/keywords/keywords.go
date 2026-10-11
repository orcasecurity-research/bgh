// Package keywords is the universal security vocabulary.
//
// This is not per-vendor configuration: the same list applies to every
// repository. Vendor-specific signals are derived in package fingerprint.
//
// Split by strength because the cheap sweep is a recall instrument: a
// strong-term hit alone, or two distinct weak terms together, marks a message
// as security-shaped.
package keywords

import (
	"regexp"
	"sort"
	"strings"
)

var strong = []string{
	`vulnerab`, `\bCVE-\d{4}`, `\bGHSA-`, `\bXSS\b`, `cross[- ]site`,
	`\bCSRF\b`, `\bSSRF\b`, `\bRCE\b`, `remote code execution`,
	`sql injection`, `\bsqli\b`, `command injection`, `code injection`,
	`path traversal`, `directory traversal`, `zip slip`,
	`prototype pollution`, `open redirect`, `deserializ`,
	`privilege escalation`, `auth(?:oriz|entic)ation bypass`,
	`security (?:fix|issue|patch|vulnerability|advisory|hardening)`,
	`\bexploit`, `arbitrary (?:file|code|command)`, `unauthori[sz]ed access`,
	`information disclosure`, `sensitive data (?:exposure|leak)`,
	`session fixation`, `timing attack`, `\bssti\b`, `\bxxe\b`,
	`\bidor\b`, `mass assignment`, `insecure direct object`,
}

var weak = []string{
	`\bauthz\b`, `\bauthn\b`, `authori[sz]`, `authentic`,
	`\bpermission`, `\bprivilege`, `\bbypass`, `\bsanitiz`, `\bescap(?:e|ing)`,
	`\bvalidat`, `\bleak`, `\bdisclos`, `\bexposure`, `\btraversal`,
	`\bunsafe\b`, `\bharden`, `\bspoof`, `\bforgery`, `\btamper`,
	`\bsecret`, `\bcredential`, `\bsession\b`, `\btoken\b`, `\bACL\b`,
	`\bRBAC\b`, `\bsandbox`, `\bimpersonat`, `\brevoke`, `\brevocation`,
	`\bencrypt`, `\bsigning\b`, `\bsignature\b`, `\bcsp\b`,
	`\bdenial of service\b`, `\bDoS\b`, `\boverflow\b`, `\brace condition\b`,
	`\baccess control`, `\bsecurity\b`, `\bmalicious`, `\battack`,
	`\badmin(?:istrator)? only\b`, `\bnon[- ]admin\b`, `\bleast privilege\b`,
}

// Words that make a strong term meaningless in context (dependency bumps, docs).
var negative = []string{
	`bump .* from .* to `, `^chore\(deps`, `^build\(deps`, `dependabot`,
	`update (?:changelog|snapshot|translation)`, `^docs?:`, `merge branch `,
	`^revert `, `typo`, `lint`,
}

var (
	StrongRe   = regexp.MustCompile(`(?i)` + strings.Join(strong, "|"))
	WeakRe     = regexp.MustCompile(`(?i)` + strings.Join(weak, "|"))
	NegativeRe = regexp.MustCompile(`(?im)` + strings.Join(negative, "|"))
)

// GrepPattern is the whole vocabulary as one alternation, matched
// case-insensitively by the caller (in Go, never by git).
var GrepPattern = strings.Join(append(append([]string{}, strong...), weak...), "|")

func distinct(re *regexp.Regexp, text string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range re.FindAllString(text, -1) {
		l := strings.ToLower(m)
		if !seen[l] {
			seen[l] = true
			out = append(out, l)
		}
	}
	sort.Strings(out)
	return out
}

// Score reports whether text is security-shaped: a strong hit, or two
// distinct weak hits, unless it reads as routine churn. reasons says why.
func Score(text string) (hit bool, reasons []string) {
	strongHits := distinct(StrongRe, text)
	weakHits := distinct(WeakRe, text)
	if len(strongHits) > 0 {
		reasons = append(reasons, "strong:"+strings.Join(head(strongHits, 3), ","))
	}
	if len(weakHits) > 0 {
		reasons = append(reasons, "weak:"+strings.Join(head(weakHits, 4), ","))
	}
	if NegativeRe.MatchString(text) && len(strongHits) == 0 {
		return false, append(reasons, "suppressed:routine-change")
	}
	return len(strongHits) > 0 || len(weakHits) >= 2, reasons
}

func head(s []string, n int) []string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

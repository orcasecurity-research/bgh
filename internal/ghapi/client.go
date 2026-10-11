// Package ghapi is a small GitHub REST client: rate-limit discipline,
// retries, pagination, and the handful of typed lookups the scan needs.
package ghapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const (
	DefaultBaseURL = "https://api.github.com"
	userAgent      = "bgh (backport gap hunter)"
	maxAttempts    = 6
	// A single rate-limit nap is capped; longer waits are retried in slices.
	maxNap = 15 * time.Minute
)

// NotFoundError is a 404.
type NotFoundError struct{ URL string }

func (e *NotFoundError) Error() string { return "not found: " + e.URL }

// UnprocessableError is a 422.
//
// On /commits/{sha} GitHub answers 422 - not 404 - when the SHA is well formed
// but not reachable in this repository, which is routine: advisories cite fixes
// that live in a fork, a submodule, or history since rewritten. For a lookup
// that may come back empty it is the same condition as a 404.
type UnprocessableError struct{ URL string }

func (e *UnprocessableError) Error() string { return "unprocessable: " + e.URL }

// Error is any other API failure.
type Error struct {
	Status int
	URL    string
	Detail string
}

func (e *Error) Error() string {
	if e.Status == 0 {
		return fmt.Sprintf("%s: %s", e.URL, e.Detail)
	}
	return fmt.Sprintf("%d on %s: %s", e.Status, e.URL, e.Detail)
}

// BudgetError means the per-run call ceiling was hit.
type BudgetError struct{ Limit int }

func (e *BudgetError) Error() string {
	return fmt.Sprintf("API call budget of %d exhausted", e.Limit)
}

// Client talks to the GitHub REST API.
type Client struct {
	Token   string
	BaseURL string
	HTTP    *http.Client
	// Limit is the hard ceiling on network calls for one run (0 = unlimited).
	Limit int
	// Log receives rate-limit notices; may be nil.
	Log func(string)

	spent       atomic.Int64
	rateLimited atomic.Int64 // nanoseconds slept waiting out a limit
	sleep       func(context.Context, time.Duration) error
}

// New returns a client for api.github.com.
func New(token string) *Client {
	return &Client{
		Token:   token,
		BaseURL: DefaultBaseURL,
		HTTP:    &http.Client{Timeout: 90 * time.Second},
		Limit:   1200,
	}
}

// Spent reports how many network calls have been made.
func (c *Client) Spent() int { return int(c.spent.Load()) }

// RateLimitedFor reports the total time spent asleep on rate limits.
func (c *Client) RateLimitedFor() time.Duration { return time.Duration(c.rateLimited.Load()) }

func (c *Client) logf(format string, a ...any) {
	if c.Log != nil {
		c.Log(fmt.Sprintf(format, a...))
	}
}

func (c *Client) nap(ctx context.Context, d time.Duration) error {
	if c.sleep != nil {
		return c.sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (c *Client) charge() error {
	n := c.spent.Add(1)
	if c.Limit > 0 && int(n) > c.Limit {
		return &BudgetError{Limit: c.Limit}
	}
	return nil
}

func (c *Client) buildURL(path string, params url.Values) string {
	base := path
	if !strings.HasPrefix(path, "http") {
		base = strings.TrimRight(c.BaseURL, "/") + path
	}
	if len(params) == 0 {
		return base
	}
	return base + "?" + params.Encode()
}

// raw performs one GET with retries and returns the body and headers.
func (c *Client) raw(ctx context.Context, u string) ([]byte, http.Header, error) {
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if err := c.charge(); err != nil {
			return nil, nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, nil, err
		}
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
		req.Header.Set("User-Agent", userAgent)
		if c.Token != "" {
			req.Header.Set("Authorization", "Bearer "+c.Token)
		}
		resp, err := c.HTTP.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return nil, nil, ctx.Err()
			}
			lastErr = &Error{URL: u, Detail: "network error: " + err.Error()}
			if attempt == maxAttempts-1 {
				break
			}
			if e := c.nap(ctx, backoff(attempt)); e != nil {
				return nil, nil, e
			}
			continue
		}
		body, rerr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if rerr != nil {
			// Large payloads truncate often enough that a torn read is a retry.
			lastErr = &Error{URL: u, Detail: "truncated response: " + rerr.Error()}
			if attempt == maxAttempts-1 {
				break
			}
			if e := c.nap(ctx, backoff(attempt)); e != nil {
				return nil, nil, e
			}
			continue
		}
		switch {
		case resp.StatusCode >= 200 && resp.StatusCode < 300:
			return body, resp.Header, nil
		case resp.StatusCode == 404:
			return nil, nil, &NotFoundError{URL: u}
		case resp.StatusCode == 422:
			return nil, nil, &UnprocessableError{URL: u}
		case resp.StatusCode == 403 || resp.StatusCode == 429:
			wait, ok := retryAfter(resp.Header, time.Now())
			if !ok {
				// A 403 that is not a rate limit (bad scope, blocked repo).
				return nil, nil, &Error{Status: resp.StatusCode, URL: u, Detail: snippet(body)}
			}
			if attempt == maxAttempts-1 {
				return nil, nil, &Error{Status: resp.StatusCode, URL: u, Detail: "rate limited: " + snippet(body)}
			}
			if wait > maxNap {
				wait = maxNap
			}
			c.logf("rate limited, waiting %s", wait.Round(time.Second))
			if e := c.nap(ctx, wait); e != nil {
				return nil, nil, e
			}
			c.rateLimited.Add(int64(wait))
			continue
		case resp.StatusCode >= 500:
			lastErr = &Error{Status: resp.StatusCode, URL: u, Detail: snippet(body)}
			if attempt == maxAttempts-1 {
				break
			}
			if e := c.nap(ctx, backoff(attempt)); e != nil {
				return nil, nil, e
			}
			continue
		default:
			return nil, nil, &Error{Status: resp.StatusCode, URL: u, Detail: snippet(body)}
		}
	}
	if lastErr == nil {
		lastErr = &Error{URL: u, Detail: "exhausted retries"}
	}
	return nil, nil, lastErr
}

func backoff(attempt int) time.Duration { return time.Duration(1<<attempt) * time.Second }

func snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}

// retryAfter says how long to wait out a rate limit, and whether this 403/429
// is one at all. A 403 with neither header is an authorisation failure, not a
// limit, and retrying it only burns the budget.
func retryAfter(h http.Header, now time.Time) (time.Duration, bool) {
	if v := h.Get("Retry-After"); v != "" {
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil || n <= 0 {
			n = 60
		}
		return time.Duration(n) * time.Second, true
	}
	if h.Get("X-RateLimit-Remaining") == "0" {
		if reset, err := strconv.ParseInt(h.Get("X-RateLimit-Reset"), 10, 64); err == nil && reset > 0 {
			d := time.Unix(reset, 0).Sub(now) + 2*time.Second
			if d < time.Second {
				d = time.Second
			}
			return d, true
		}
		return 60 * time.Second, true
	}
	return 0, false
}

// Get fetches path and decodes the JSON body into out.
func (c *Client) Get(ctx context.Context, path string, params url.Values, out any) error {
	body, _, err := c.raw(ctx, c.buildURL(path, params))
	if err != nil {
		return err
	}
	if out == nil || len(body) == 0 {
		return nil
	}
	if err := json.Unmarshal(body, out); err != nil {
		return &Error{URL: path, Detail: "invalid JSON: " + err.Error()}
	}
	return nil
}

// GetOptional is Get, but a 404 or 422 is (false, nil).
func (c *Client) GetOptional(ctx context.Context, path string, params url.Values, out any) (bool, error) {
	err := c.Get(ctx, path, params, out)
	if err == nil {
		return true, nil
	}
	var nf *NotFoundError
	var un *UnprocessableError
	if errors.As(err, &nf) || errors.As(err, &un) {
		return false, nil
	}
	return false, err
}

// Paginate yields items across pages, up to maxPages. For search endpoints
// the items live under "items".
func (c *Client) Paginate(ctx context.Context, path string, params url.Values, maxPages int) ([]json.RawMessage, error) {
	p := cloneParams(params)
	if p.Get("per_page") == "" {
		p.Set("per_page", "100")
	}
	perPage, _ := strconv.Atoi(p.Get("per_page"))
	var all []json.RawMessage
	for page := 1; page <= maxPages; page++ {
		p.Set("page", strconv.Itoa(page))
		body, _, err := c.raw(ctx, c.buildURL(path, p))
		if err != nil {
			return all, err
		}
		items, err := decodeItems(body)
		if err != nil {
			return all, &Error{URL: path, Detail: "invalid JSON: " + err.Error()}
		}
		all = append(all, items...)
		if len(items) < perPage {
			break
		}
	}
	return all, nil
}

// PaginateLinked follows rel="next" Link headers. For cursor-paginated
// endpoints that ignore `page` without an error: the repo advisories endpoint
// answers page=2 with page 1 again, so Paginate would read the newest page
// repeatedly and never see the rest.
func (c *Client) PaginateLinked(ctx context.Context, path string, params url.Values, maxPages int) ([]json.RawMessage, error) {
	p := cloneParams(params)
	if p.Get("per_page") == "" {
		p.Set("per_page", "100")
	}
	u := c.buildURL(path, p)
	var all []json.RawMessage
	for i := 0; i < maxPages; i++ {
		body, hdr, err := c.raw(ctx, u)
		if err != nil {
			return all, err
		}
		items, err := decodeItems(body)
		if err != nil {
			return all, &Error{URL: path, Detail: "invalid JSON: " + err.Error()}
		}
		all = append(all, items...)
		next := nextLink(hdr.Get("Link"))
		if next == "" {
			break
		}
		u = next
	}
	return all, nil
}

func decodeItems(body []byte) ([]json.RawMessage, error) {
	trim := strings.TrimSpace(string(body))
	if trim == "" || trim == "null" {
		return nil, nil
	}
	if strings.HasPrefix(trim, "{") {
		var wrap struct {
			Items []json.RawMessage `json:"items"`
		}
		if err := json.Unmarshal(body, &wrap); err != nil {
			return nil, err
		}
		return wrap.Items, nil
	}
	var items []json.RawMessage
	if err := json.Unmarshal(body, &items); err != nil {
		return nil, err
	}
	return items, nil
}

func cloneParams(p url.Values) url.Values {
	out := url.Values{}
	for k, v := range p {
		out[k] = append([]string(nil), v...)
	}
	return out
}

// nextLink returns the rel="next" URL of a Link header, or "".
func nextLink(link string) string {
	for _, part := range strings.Split(link, ",") {
		if strings.Contains(part, `rel="next"`) {
			i, j := strings.Index(part, "<"), strings.Index(part, ">")
			if i >= 0 && j > i {
				return part[i+1 : j]
			}
		}
	}
	return ""
}

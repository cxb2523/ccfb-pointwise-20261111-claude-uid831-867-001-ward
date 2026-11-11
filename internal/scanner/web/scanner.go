// Package web runs HTTP exposure checks against deployed web roots.
//
// Unlike the filesystem rule engine these checks are stateful: each host is
// probed once with a random nonce URL to establish a soft-404 baseline, and
// responses are normalized before comparison so SPA catch-all fallbacks and
// templated error pages cannot produce false positives. The matching logic
// for exposed-git-config lives here on purpose — the generic YAML matchers
// cannot express it.
package web

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/eljakani/ward/internal/config"
	"github.com/eljakani/ward/internal/models"
)

const (
	// ExposedGitConfigRuleID is the YAML rule served by this scanner.
	ExposedGitConfigRuleID = "exposed-git-config"

	// ScannerName is the orchestrator-facing scanner identifier.
	ScannerName = "web-exposure-scanner"

	gitConfigPath = "/.git/config"
	probePathFmt  = "/.git/ward-%s.probe"

	defaultTimeout = 10 * time.Second
	// maxBodyBytes caps every response body so a large or streamed reply
	// cannot blow up the scan.
	maxBodyBytes = 1 << 20 // 1 MiB

	userAgent = "ward-security-scanner"
)

var (
	// Both patterns must match on separate lines of the raw body. Real git
	// config files tab-indent their key lines, so the line anchors tolerate
	// leading/trailing whitespace while still requiring a full-line match.
	coreSectionRE = regexp.MustCompile(`(?m)^\s*\[core\]\s*$`)
	versionRE     = regexp.MustCompile(`(?m)^\s*repositoryformatversion\s*=\s*\d+\s*$`)

	htmlTagRE = regexp.MustCompile(`(?is)<\s*(html|!doctype\s+html|head|body)\b`)
	// Catches login forms even in HTML fragments without a doctype.
	loginRE = regexp.MustCompile(`(?is)<input[^>]+type\s*=\s*["']?password["']?|<form[^>]+(login|signin|sign-in)`)
	// Matches the nonce probe path regardless of the generated nonce.
	probePathRE  = regexp.MustCompile(`(?i)/\.git/ward-[a-z0-9]*\.probe`)
	whitespaceRE = regexp.MustCompile(`\s+`)
)

// httpResponse is the trimmed, size-capped view of an HTTP reply.
type httpResponse struct {
	status int
	header http.Header
	body   []byte
}

// Scanner evaluates HTTP exposure rules against a fixed set of origins.
type Scanner struct {
	rule    *config.RuleDefinition
	origins []string
	client  *http.Client
	nonce   string

	// probeCache holds the soft-404 baseline per host for the lifetime of
	// one scan; a host is probed at most once.
	probeCache map[string]*probeResult
}

type probeResult struct {
	resp *httpResponse
	err  error
}

// Option customizes a Scanner, mainly for tests.
type Option func(*Scanner)

// WithTimeout overrides the per-request HTTP timeout.
func WithTimeout(d time.Duration) Option {
	return func(s *Scanner) {
		if d > 0 {
			s.client.Timeout = d
		}
	}
}

// WithHTTPClient swaps the HTTP client (tests use it to pin behavior).
func WithHTTPClient(c *http.Client) Option {
	return func(s *Scanner) {
		if c != nil {
			s.client = c
		}
	}
}

// WithNonce pins the probe nonce instead of generating a random one.
func WithNonce(nonce string) Option {
	return func(s *Scanner) {
		if nonce != "" {
			s.nonce = nonce
		}
	}
}

// New creates a web exposure Scanner. rule carries the finding metadata
// loaded from exposure.yaml; origins are web roots and are always reduced to
// scheme+host before any path is appended.
func New(rule *config.RuleDefinition, origins []string, opts ...Option) *Scanner {
	s := &Scanner{
		rule:       rule,
		origins:    origins,
		client:     newHTTPClient(defaultTimeout),
		nonce:      newNonce(),
		probeCache: make(map[string]*probeResult),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

func newHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		// Never follow redirects: a 3xx (login bounce, http->https, ...) is
		// itself a signal that the raw file is not directly readable.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func (s *Scanner) Name() string { return ScannerName }

func (s *Scanner) Description() string {
	return "HTTP exposure checks against deployed web roots"
}

// Scan runs every enabled HTTP exposure check against each configured origin.
// Network failures on a single origin are skipped rather than failing the
// whole (otherwise local) scan.
func (s *Scanner) Scan(ctx context.Context, _ models.ProjectContext, emit func(models.Finding)) ([]models.Finding, error) {
	if s.rule == nil || !s.rule.Enabled {
		return nil, nil
	}

	var findings []models.Finding
	seen := make(map[string]bool)

	for _, origin := range s.origins {
		origin = strings.TrimSpace(origin)
		if origin == "" || seen[origin] {
			continue
		}
		seen[origin] = true

		finding, err := s.checkGitConfig(ctx, origin)
		if err != nil || finding == nil {
			continue
		}
		findings = append(findings, *finding)
		emit(*finding)
	}

	return findings, nil
}

// checkGitConfig implements the dedicated exposed-git-config decision:
// strict raw-body match first, soft-404 suppression second, with probe
// failures never downgrading a strict raw hit.
func (s *Scanner) checkGitConfig(ctx context.Context, origin string) (*models.Finding, error) {
	realURL := joinOriginPath(origin, gitConfigPath)

	real, err := s.doGet(ctx, realURL)
	if err != nil {
		return nil, err
	}

	// A 200 alone is never sufficient.
	if real.status != http.StatusOK {
		return nil, nil
	}

	switch evaluateGitConfigBody(real) {
	case bodyNoMatch, bodyHTML:
		// HTML pages (SPA shells, login screens, path-echoing error pages)
		// are rejected outright — even if the probe later fails.
		return nil, nil
	}

	// Soft-404 baseline, cached per host for this scan. Only an actual
	// probe response can suppress; transport errors must not swallow the
	// strict raw match above.
	probe, probeErr := s.probeHost(ctx, origin)
	if probeErr == nil && probe != nil {
		if s.normalize(probe.body) == s.normalize(real.body) {
			return nil, nil
		}
	}

	return s.buildFinding(realURL, real), nil
}

type bodyVerdict int

const (
	bodyNoMatch bodyVerdict = iota
	bodyHTML
	bodyMatch
)

// evaluateGitConfigBody applies the strict content checks. Both required
// lines must be present, and the reply must not be an HTML/login document.
func evaluateGitConfigBody(resp *httpResponse) bodyVerdict {
	body := resp.body
	if len(bytes.TrimSpace(body)) == 0 {
		return bodyNoMatch
	}
	if looksLikeHTML(resp) {
		return bodyHTML
	}
	if !coreSectionRE.Match(body) || !versionRE.Match(body) {
		return bodyNoMatch
	}
	return bodyMatch
}

func looksLikeHTML(resp *httpResponse) bool {
	if ct := strings.ToLower(resp.header.Get("Content-Type")); strings.Contains(ct, "html") {
		return true
	}
	body := resp.body
	if head := len(body); head > 512 {
		body = body[:512]
	}
	if htmlTagRE.Match(body) {
		return true
	}
	// Password fields can appear in an HTML fragment without doctype/head.
	return loginRE.Match(resp.body)
}

// probeHost fetches the nonce probe URL once per host and caches the outcome.
func (s *Scanner) probeHost(ctx context.Context, origin string) (*httpResponse, error) {
	key := hostKey(origin)
	if cached, ok := s.probeCache[key]; ok {
		return cached.resp, cached.err
	}

	probeURL := joinOriginPath(origin, fmt.Sprintf(probePathFmt, s.nonce))
	resp, err := s.doGet(ctx, probeURL)
	s.probeCache[key] = &probeResult{resp: resp, err: err}
	return resp, err
}

// doGet issues a GET with no redirect following and a capped response body.
func (s *Scanner) doGet(ctx context.Context, rawurl string) (*httpResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawurl, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "*/*")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return nil, err
	}

	return &httpResponse{
		status: resp.StatusCode,
		header: resp.Header.Clone(),
		body:   body,
	}, nil
}

// normalize makes two templated responses comparable: lower-casing, removing
// the request paths/nonce that error pages tend to echo, and collapsing
// whitespace so indentation and line-ending differences disappear.
func (s *Scanner) normalize(body []byte) string {
	text := strings.ToLower(string(body))
	text = probePathRE.ReplaceAllString(text, "")
	text = strings.ReplaceAll(text, s.nonce, "")
	text = strings.ReplaceAll(text, strings.ToLower(gitConfigPath), "")
	text = whitespaceRE.ReplaceAllString(text, " ")
	return strings.TrimSpace(text)
}

func (s *Scanner) buildFinding(rawurl string, resp *httpResponse) *models.Finding {
	r := s.rule
	return &models.Finding{
		ID:          r.ID,
		Title:       r.Title,
		Description: r.Description,
		Severity:    models.ParseSeverity(r.Severity),
		Category:    r.Category,
		Scanner:     s.Name(),
		File:        rawurl,
		CodeSnippet: snippetFromBody(resp.body),
		Remediation: r.Remediation,
		References:  r.References,
	}
}

// snippetFromBody extracts the matching lines for the report, capped.
func snippetFromBody(body []byte) string {
	var lines []string
	sc := bufio.NewScanner(bytes.NewReader(body))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if coreSectionRE.MatchString(line) || versionRE.MatchString(line) {
			lines = append(lines, line)
			if len(lines) >= 4 {
				break
			}
		}
	}
	return strings.Join(lines, "\n")
}

// OriginsFromTarget builds the de-duplicated probe list. Configured origins
// come first; when the scan target is itself an http(s) URL its origin is
// appended, along with the opposite-scheme variant so a scheme mismatch does
// not silently skip the check. Non-HTTP targets (local paths, git@, ssh)
// contribute nothing.
func OriginsFromTarget(target string, extra []string) []string {
	var out []string
	seen := make(map[string]bool)

	add := func(raw string) {
		origin, ok := originOf(raw)
		if !ok || seen[origin] {
			return
		}
		seen[origin] = true
		out = append(out, origin)
	}

	for _, o := range extra {
		add(o)
	}

	if u, err := url.Parse(strings.TrimSpace(target)); err == nil &&
		(u.Scheme == "http" || u.Scheme == "https") && u.Host != "" {
		add(target)

		alt := *u
		if u.Scheme == "http" {
			alt.Scheme = "https"
		} else {
			alt.Scheme = "http"
		}
		add(alt.String())
	}

	return out
}

// originOf reduces an arbitrary URL to its scheme+host root, rejecting
// non-http(s) input. Business base paths are deliberately discarded so
// requests are built against the origin, never behind an app base path.
func originOf(raw string) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return "", false
	}
	u.Path = ""
	u.RawPath = ""
	u.RawQuery = ""
	u.Fragment = ""
	return u.String(), true
}

// joinOriginPath appends path to the origin root, dropping any base path
// carried by the configured origin.
func joinOriginPath(origin, path string) string {
	root, ok := originOf(origin)
	if !ok {
		// Should never happen: origins are validated at construction time.
		return strings.TrimRight(origin, "/") + path
	}
	return root + path
}

func hostKey(origin string) string {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return strings.ToLower(origin)
	}
	return strings.ToLower(u.Host)
}

func newNonce() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failing is exceptional; keep the probe unique anyway.
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(b)
}

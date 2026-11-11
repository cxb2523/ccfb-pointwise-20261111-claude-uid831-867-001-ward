package web

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/eljakani/ward/internal/config"
	"github.com/eljakani/ward/internal/models"
)

const realGitConfig = `[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
`

func testRule() *config.RuleDefinition {
	return &config.RuleDefinition{
		ID:          ExposedGitConfigRuleID,
		Title:       "Exposed .git/config over HTTP",
		Description: "The .git/config file is publicly readable.",
		Severity:    "high",
		Category:    "Exposure",
		Enabled:     true,
		Remediation: "Block web access to /.git",
		References:  []string{"https://cwe.mitre.org/data/definitions/538.html"},
	}
}

func newTestScanner(t *testing.T, srv *httptest.Server, opts ...Option) *Scanner {
	t.Helper()
	all := append([]Option{WithNonce("deadbeefcafe")}, opts...)
	return New(testRule(), []string{srv.URL}, all...)
}

func runScan(t *testing.T, s *Scanner) []models.Finding {
	t.Helper()
	findings, err := s.Scan(context.Background(), models.ProjectContext{}, func(models.Finding) {})
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	return findings
}

// 1. A genuinely exposed raw .git/config produces a high-severity finding,
// and the request must be a GET against the origin root with no redirect.
func TestScan_RealGitConfigHit(t *testing.T) {
	var method, path string
	var probeHits int32
	mux := http.NewServeMux()
	mux.HandleFunc("/.git/config", func(w http.ResponseWriter, r *http.Request) {
		method, path = r.Method, r.URL.Path
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte(realGitConfig))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/.git/ward-") {
			atomic.AddInt32(&probeHits, 1)
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	findings := runScan(t, newTestScanner(t, srv))

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.ID != ExposedGitConfigRuleID {
		t.Errorf("finding ID = %q, want %q", f.ID, ExposedGitConfigRuleID)
	}
	if f.Severity != models.SeverityHigh {
		t.Errorf("severity = %v, want High", f.Severity)
	}
	if f.Scanner != ScannerName {
		t.Errorf("scanner = %q, want %q", f.Scanner, ScannerName)
	}
	if !strings.HasSuffix(f.File, "/.git/config") || strings.Contains(f.File, "app") {
		t.Errorf("finding file %q must be the origin-level /.git/config", f.File)
	}
	if !strings.Contains(f.CodeSnippet, "[core]") ||
		!strings.Contains(f.CodeSnippet, "repositoryformatversion = 0") {
		t.Errorf("snippet should quote the matching lines, got %q", f.CodeSnippet)
	}
	if method != http.MethodGet {
		t.Errorf("method = %q, want GET", method)
	}
	if path != "/.git/config" {
		t.Errorf("request path = %q, want /.git/config (no business base path)", path)
	}
	if atomic.LoadInt32(&probeHits) != 1 {
		t.Errorf("probe should be requested exactly once, got %d", probeHits)
	}
}

// 2. SPA catch-all: every path answers 200 with the same HTML shell.
func TestScan_SPAAllPathsHTML(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<!doctype html><html><head><title>App</title></head>
<body><div id="app"></div><script src="/bundle.js"></script></body></html>`))
	}))
	defer srv.Close()

	if findings := runScan(t, newTestScanner(t, srv)); len(findings) != 0 {
		t.Fatalf("SPA shell must not be reported, got %d findings: %+v", len(findings), findings)
	}
}

// 3. An HTML page that echoes the raw config features (and whose probe
// fails) must still be rejected — HTML always wins over a probe error.
func TestScan_HTMLEchoesFeatures_ProbeFails(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/.git/config", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><body><h1>/.git/config</h1><pre>
[core]
repositoryformatversion = 0
</pre><a href="/login">login</a></body></html>`))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError) // probe unavailable
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	if findings := runScan(t, newTestScanner(t, srv)); len(findings) != 0 {
		t.Fatalf("HTML echo must not be reported even when the probe fails, got %+v", findings)
	}
}

// 4. Login bounce (3xx, must not be followed) and straight 403s.
func TestScan_LoginRedirectAndForbidden(t *testing.T) {
	t.Run("302 redirect to login is not followed", func(t *testing.T) {
		var followUps int32
		mux := http.NewServeMux()
		mux.HandleFunc("/.git/config", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/login", http.StatusFound)
		})
		mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&followUps, 1)
			w.WriteHeader(http.StatusOK)
		})
		srv := httptest.NewServer(mux)
		defer srv.Close()

		if findings := runScan(t, newTestScanner(t, srv)); len(findings) != 0 {
			t.Fatalf("redirect must not yield a finding, got %+v", findings)
		}
		if atomic.LoadInt32(&followUps) != 0 {
			t.Errorf("client followed the redirect %d times; redirects must be disabled", followUps)
		}
	})

	t.Run("403 login page", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`<html><body><form action="/login"><input type="password"></form></body></html>`))
		}))
		defer srv.Close()

		if findings := runScan(t, newTestScanner(t, srv)); len(findings) != 0 {
			t.Fatalf("403 must not yield a finding, got %+v", findings)
		}
	})
}

// 5. Probe is forbidden (or fails outright) but the raw config is genuinely
// readable: the strict raw hit must not be swallowed.
func TestScan_ProbeBlocked_RawConfigReadable(t *testing.T) {
	t.Run("probe returns 403", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/.git/config", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte(realGitConfig))
		})
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		})
		srv := httptest.NewServer(mux)
		defer srv.Close()

		if findings := runScan(t, newTestScanner(t, srv)); len(findings) != 1 {
			t.Fatalf("raw config must be reported despite probe 403, got %d findings", len(findings))
		}
	})

	t.Run("probe transport error", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/.git/config", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte(realGitConfig))
		})
		srv := httptest.NewServer(mux)
		defer srv.Close()

		client := &http.Client{
			Timeout:       srv.Client().Timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			Transport:     errorProbeTransport{base: srv.Client().Transport},
		}

		if findings := runScan(t, newTestScanner(t, srv, WithHTTPClient(client))); len(findings) != 1 {
			t.Fatalf("raw config must be reported despite probe transport failure, got %d findings", len(findings))
		}
	})
}

type errorProbeTransport struct {
	base http.RoundTripper
}

func (t errorProbeTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if probePathRE.MatchString(r.URL.Path) {
		return nil, errors.New("dial tcp: connection refused")
	}
	return t.base.RoundTrip(r)
}

// Soft-404 suppression: both replies satisfy the strict body shape but are
// the same templated page once request-specific paths are normalized away.
func TestScan_Soft404_NormalizedEqualSuppresses(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/.git/config", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(realGitConfig + "# requested: " + r.URL.Path + "\n"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(realGitConfig + "# requested: " + r.URL.Path + "\n"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	if findings := runScan(t, newTestScanner(t, srv)); len(findings) != 0 {
		t.Fatalf("normalized-equal soft-404 must be suppressed, got %+v", findings)
	}
}

// The probe baseline is fetched once per host even across multiple checks,
// and base paths on the origin are stripped before joining /.git paths.
func TestScan_ProbeCachedPerHostAndBasePathStripped(t *testing.T) {
	var probeHits, configHits int32
	var gotPath string
	mux := http.NewServeMux()
	mux.HandleFunc("/.git/config", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&configHits, 1)
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(realGitConfig))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/.git/ward-") {
			atomic.AddInt32(&probeHits, 1)
		}
		w.WriteHeader(http.StatusNotFound)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	s := newTestScanner(t, srv)

	// Same host, different business base paths — paths must be dropped and
	// the host-level probe cache must serve both checks.
	for _, origin := range []string{srv.URL + "/shop/public", srv.URL} {
		if _, err := s.checkGitConfig(context.Background(), origin); err != nil {
			t.Fatalf("checkGitConfig(%q): %v", origin, err)
		}
	}

	if gotPath != "/.git/config" {
		t.Errorf("request path = %q, want origin-level /.git/config", gotPath)
	}
	if got := atomic.LoadInt32(&probeHits); got != 1 {
		t.Errorf("probe requests = %d, want exactly 1 (per-host cache)", got)
	}
	if got := atomic.LoadInt32(&configHits); got != 2 {
		t.Errorf("config requests = %d, want 2", got)
	}
}

func TestOriginsFromTarget(t *testing.T) {
	got := OriginsFromTarget("https://app.example.com/deep/base/path?x=1", []string{
		"http://other.example.com",
		"  https://app.example.com/other ", // duplicate origin, different path
		"/local/path",
		"git@github.com:org/repo.git",
	})

	want := map[string]bool{
		"http://other.example.com": false,
		"https://app.example.com":  false,
		"http://app.example.com":   false, // opposite-scheme fallback
	}
	if len(got) != len(want) {
		t.Fatalf("got %d origins %v, want %d unique origins", len(got), got, len(want))
	}
	for _, o := range got {
		if _, ok := want[o]; !ok {
			t.Errorf("unexpected origin %q in %v", o, got)
		}
		u, err := url.Parse(o)
		if err != nil {
			t.Errorf("origin %q is not a valid URL: %v", o, err)
			continue
		}
		if u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
			t.Errorf("origin %q must be reduced to scheme+host, got path=%q query=%q", o, u.Path, u.RawQuery)
		}
	}

	if got := OriginsFromTarget("/home/user/project", nil); len(got) != 0 {
		t.Errorf("local path must yield no origins, got %v", got)
	}
}

func TestEvaluateGitConfigBody(t *testing.T) {
	raw := func(body, contentType string) *httpResponse {
		h := http.Header{}
		if contentType != "" {
			h.Set("Content-Type", contentType)
		}
		return &httpResponse{status: http.StatusOK, header: h, body: []byte(body)}
	}

	if v := evaluateGitConfigBody(raw(realGitConfig, "text/plain")); v != bodyMatch {
		t.Errorf("raw config verdict = %v, want bodyMatch", v)
	}
	if v := evaluateGitConfigBody(raw(realGitConfig, "text/html")); v != bodyHTML {
		t.Errorf("html content-type verdict = %v, want bodyHTML", v)
	}
	echo := "<html><body>[core]\nrepositoryformatversion = 0\n</body></html>"
	if v := evaluateGitConfigBody(raw(echo, "")); v != bodyHTML {
		t.Errorf("html echo verdict = %v, want bodyHTML", v)
	}
	if v := evaluateGitConfigBody(raw("[core]\nrepositoryformatversion = nope\n", "text/plain")); v != bodyNoMatch {
		t.Errorf("non-numeric version verdict = %v, want bodyNoMatch", v)
	}
	if v := evaluateGitConfigBody(raw("repositoryformatversion = 0\n", "text/plain")); v != bodyNoMatch {
		t.Errorf("missing [core] section verdict = %v, want bodyNoMatch", v)
	}
}

func TestNormalize_StripsRequestSpecificContent(t *testing.T) {
	s := New(testRule(), nil, WithNonce("abc123"))
	a := s.normalize([]byte("Error at /.git/config\t\nextra  space"))
	b := s.normalize([]byte("Error at /.git/ward-abc123.probe extra space"))
	if a != b {
		t.Errorf("normalized bodies should be equal:\n a=%q\n b=%q", a, b)
	}
}

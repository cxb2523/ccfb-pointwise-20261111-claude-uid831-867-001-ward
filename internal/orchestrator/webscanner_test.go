package orchestrator

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/eljakani/ward/internal/config"
	"github.com/eljakani/ward/internal/eventbus"
	"github.com/eljakani/ward/internal/models"
	webscanner "github.com/eljakani/ward/internal/scanner/web"
)

func newTestOrchestrator(cfg *config.WardConfig, target string) *Orchestrator {
	return &Orchestrator{
		bus:    eventbus.New(),
		cfg:    cfg,
		target: target,
	}
}

func TestBuildWebScanner_LocalTargetWithoutOrigins(t *testing.T) {
	o := newTestOrchestrator(config.Default(), "/home/user/project")
	if sc := o.buildWebScanner(nil); sc != nil {
		t.Errorf("expected no web scanner for a local target with no web.origins, got %T", sc)
	}
}

func TestBuildWebScanner_DisableAndOverride(t *testing.T) {
	cfg := config.Default()
	cfg.Web.Origins = []string{"https://app.example.com"}

	cfg.Rules.Disable = []string{webscanner.ExposedGitConfigRuleID}
	if sc := newTestOrchestrator(cfg, "/tmp").buildWebScanner(nil); sc != nil {
		t.Error("rules.disable must turn the web scanner off")
	}

	cfg.Rules.Disable = nil
	disabled := false
	cfg.Rules.Override = map[string]config.RuleOverride{
		webscanner.ExposedGitConfigRuleID: {Enabled: &disabled},
	}
	if sc := newTestOrchestrator(cfg, "/tmp").buildWebScanner(nil); sc != nil {
		t.Error("rules.override enabled:false must turn the web scanner off")
	}
}

func TestBuildWebScanner_UserRuleMetadataWinsAndRuns(t *testing.T) {
	// Live httptest origin: raw config readable, probe answers 404.
	mux := http.NewServeMux()
	mux.HandleFunc("/.git/config", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("[core]\n\trepositoryformatversion = 0\n"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cfg := config.Default()
	cfg.Web.Origins = []string{srv.URL + "/shop/public"} // base path must be dropped

	userRules := []config.RuleDefinition{{
		ID:       webscanner.ExposedGitConfigRuleID,
		Title:    "Custom title from ~/.ward/rules",
		Severity: "critical",
		Category: "Exposure",
		Enabled:  true,
	}}

	sc := newTestOrchestrator(cfg, "/tmp").buildWebScanner(userRules)
	if sc == nil {
		t.Fatal("web scanner should be built for a configured origin")
	}

	findings, err := sc.Scan(context.Background(), models.ProjectContext{}, func(models.Finding) {})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.ID != webscanner.ExposedGitConfigRuleID {
		t.Errorf("finding ID = %q", f.ID)
	}
	if f.Severity != models.SeverityCritical {
		t.Errorf("user override severity not applied: got %v, want Critical", f.Severity)
	}
	if f.Title != "Custom title from ~/.ward/rules" {
		t.Errorf("user rule metadata not used: title = %q", f.Title)
	}
	if f.File != srv.URL+"/.git/config" {
		t.Errorf("finding URL %q must use the origin root, no /shop/public base path", f.File)
	}
}

package auth

import (
	"testing"
)

func TestEvaluateRBAC_NilPolicy(t *testing.T) {
	d := EvaluateRBAC(nil, "mcp:github:list_repos.list", "", 0)
	if !d.Allowed {
		t.Fatalf("expected allowed with nil policy, got denied: %s", d.Reason)
	}
}

func TestEvaluateRBAC_Step1_DeniedAction(t *testing.T) {
	policy := &RBACPolicy{
		DeniedActions: []string{"mcp:*:*.delete", "mcp:*:*.destroy"},
	}
	d := EvaluateRBAC(policy, "mcp:github:file.delete", "", 0)
	if d.Allowed {
		t.Fatal("expected denied by denied_actions")
	}
	if d.Step != 1 || d.StepName != "denied_actions" {
		t.Fatalf("expected step 1/denied_actions, got %d/%s", d.Step, d.StepName)
	}
}

func TestEvaluateRBAC_Step2_NotInAllowed(t *testing.T) {
	policy := &RBACPolicy{
		AllowedActions: []string{"mcp:filesystem:*", "mcp:git:read.*"},
	}
	d := EvaluateRBAC(policy, "mcp:github:list_repos.list", "", 0)
	if d.Allowed {
		t.Fatal("expected denied by allowed_actions")
	}
	if d.Step != 2 || d.StepName != "allowed_actions" {
		t.Fatalf("expected step 2/allowed_actions, got %d/%s", d.Step, d.StepName)
	}
}

func TestEvaluateRBAC_Step2_EmptyAllowed(t *testing.T) {
	// Empty allowed_actions = allow all
	policy := &RBACPolicy{
		AllowedActions: []string{},
	}
	d := EvaluateRBAC(policy, "mcp:github:list_repos.list", "", 0)
	if !d.Allowed {
		t.Fatalf("expected allowed with empty allowed_actions, got: %s", d.Reason)
	}
}

func TestEvaluateRBAC_Step3_DeniedResource(t *testing.T) {
	policy := &RBACPolicy{
		DeniedResources: []string{"repo:myorg/secrets"},
	}
	d := EvaluateRBAC(policy, "mcp:github:read.list", "repo:myorg/secrets", 0)
	if d.Allowed {
		t.Fatal("expected denied by denied_resources")
	}
	if d.Step != 3 || d.StepName != "denied_resources" {
		t.Fatalf("expected step 3/denied_resources, got %d/%s", d.Step, d.StepName)
	}
}

func TestEvaluateRBAC_Step4_ResourceNotAllowed(t *testing.T) {
	policy := &RBACPolicy{
		AllowedResources: []string{"repo:myorg/public-*"},
	}
	d := EvaluateRBAC(policy, "mcp:github:read.list", "repo:myorg/private-repo", 0)
	if d.Allowed {
		t.Fatal("expected denied by allowed_resources")
	}
	if d.Step != 4 || d.StepName != "allowed_resources" {
		t.Fatalf("expected step 4/allowed_resources, got %d/%s", d.Step, d.StepName)
	}
}

func TestEvaluateRBAC_Step5_SensitivityExceeded(t *testing.T) {
	policy := &RBACPolicy{
		SensitivityLevel: 3,
	}
	d := EvaluateRBAC(policy, "mcp:github:read.list", "", 5)
	if d.Allowed {
		t.Fatal("expected denied by sensitivity_level")
	}
	if d.Step != 5 || d.StepName != "sensitivity_level" {
		t.Fatalf("expected step 5/sensitivity_level, got %d/%s", d.Step, d.StepName)
	}
}

func TestEvaluateRBAC_Step5_SensitivityWithinLimit(t *testing.T) {
	policy := &RBACPolicy{
		SensitivityLevel: 5,
	}
	d := EvaluateRBAC(policy, "mcp:github:read.list", "", 3)
	if !d.Allowed {
		t.Fatalf("expected allowed with sensitivity within limit, got: %s", d.Reason)
	}
}

func TestEvaluateRBAC_Step6_AllChecksPass(t *testing.T) {
	policy := &RBACPolicy{
		AllowedActions:   []string{"mcp:filesystem:*", "mcp:git:*"},
		DeniedActions:    []string{"mcp:*:*.delete"},
		AllowedResources: []string{"repo:myorg/*"},
		DeniedResources:  []string{"repo:myorg/secrets"},
		SensitivityLevel: 5,
	}
	d := EvaluateRBAC(policy, "mcp:filesystem:read_file.read", "repo:myorg/public", 2)
	if !d.Allowed {
		t.Fatalf("expected allowed, got: step=%d reason=%s", d.Step, d.Reason)
	}
	if d.Step != 6 {
		t.Fatalf("expected step 6, got %d", d.Step)
	}
}

func TestGlobMatchAction_Exact(t *testing.T) {
	if !GlobMatchAction("mcp:github:list_repos.list", "mcp:github:list_repos.list") {
		t.Fatal("exact match failed")
	}
}

func TestGlobMatchAction_Star(t *testing.T) {
	if !GlobMatchAction("*", "anything") {
		t.Fatal("star should match anything")
	}
}

func TestGlobMatchAction_WildcardSegment(t *testing.T) {
	if !GlobMatchAction("mcp:*:*.delete", "mcp:github:file.delete") {
		t.Fatal("wildcard segment match failed")
	}
	if GlobMatchAction("mcp:*:*.delete", "mcp:github:file.read") {
		t.Fatal("should not match different verb")
	}
}

func TestGlobMatchAction_DoubleWildcard(t *testing.T) {
	if !GlobMatchAction("mcp:**", "mcp:github:list_repos.list") {
		t.Fatal("double wildcard should match across segments")
	}
}

func TestGlobMatchAction_PrefixWildcard(t *testing.T) {
	if !GlobMatchAction("mcp:filesystem:*", "mcp:filesystem:read_file.read") {
		t.Fatal("prefix wildcard match failed")
	}
}

func TestNarrowRBAC_UnionDenied(t *testing.T) {
	parent := &RBACPolicy{
		DeniedActions: []string{"mcp:*:*.delete"},
	}
	child := &RBACPolicy{
		DeniedActions: []string{"mcp:*:*.destroy"},
	}
	narrowed := NarrowRBAC(parent, child)
	if len(narrowed.DeniedActions) != 2 {
		t.Fatalf("expected 2 denied actions, got %d", len(narrowed.DeniedActions))
	}
}

func TestNarrowRBAC_MinSensitivity(t *testing.T) {
	parent := &RBACPolicy{SensitivityLevel: 5}
	child := &RBACPolicy{SensitivityLevel: 3}
	narrowed := NarrowRBAC(parent, child)
	if narrowed.SensitivityLevel != 3 {
		t.Fatalf("expected min sensitivity 3, got %d", narrowed.SensitivityLevel)
	}
}

func TestNarrowRBAC_MinMaxRisk(t *testing.T) {
	parent := &RBACPolicy{MaxRiskScore: 75}
	child := &RBACPolicy{MaxRiskScore: 50}
	narrowed := NarrowRBAC(parent, child)
	if narrowed.MaxRiskScore != 50 {
		t.Fatalf("expected min risk score 50, got %d", narrowed.MaxRiskScore)
	}
}

func TestValidateNarrowing_Valid(t *testing.T) {
	parent := &RBACPolicy{
		DeniedActions:    []string{"mcp:*:*.delete"},
		SensitivityLevel: 5,
		MaxRiskScore:     75,
	}
	child := &RBACPolicy{
		DeniedActions:    []string{"mcp:*:*.delete", "mcp:*:*.destroy"},
		SensitivityLevel: 3,
		MaxRiskScore:     50,
	}
	if err := ValidateNarrowing(parent, child); err != nil {
		t.Fatalf("expected valid narrowing, got: %v", err)
	}
}

func TestValidateNarrowing_MissingDenied(t *testing.T) {
	parent := &RBACPolicy{
		DeniedActions: []string{"mcp:*:*.delete"},
	}
	child := &RBACPolicy{
		DeniedActions: []string{"mcp:*:*.destroy"}, // missing parent's denied
	}
	if err := ValidateNarrowing(parent, child); err == nil {
		t.Fatal("expected error for missing parent denied action")
	}
}

func TestValidateNarrowing_SensitivityExceeded(t *testing.T) {
	parent := &RBACPolicy{SensitivityLevel: 3}
	child := &RBACPolicy{SensitivityLevel: 5}
	if err := ValidateNarrowing(parent, child); err == nil {
		t.Fatal("expected error for exceeding sensitivity")
	}
}

func TestValidateNarrowing_RiskExceeded(t *testing.T) {
	parent := &RBACPolicy{MaxRiskScore: 50}
	child := &RBACPolicy{MaxRiskScore: 75}
	if err := ValidateNarrowing(parent, child); err == nil {
		t.Fatal("expected error for exceeding max risk score")
	}
}

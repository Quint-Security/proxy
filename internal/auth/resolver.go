package auth

import "fmt"

// TokenResolver provides unified token resolution across local and cloud auth.
// It decides which path to take based on the token prefix.
type TokenResolver struct {
	localDB        *DB
	cloudValidator *CloudValidator
	cloudClient    *AuthServiceClient
}

// NewTokenResolver creates a resolver. Either or both of localDB/cloudValidator may be nil.
func NewTokenResolver(localDB *DB, cloudValidator *CloudValidator, cloudClient *AuthServiceClient) *TokenResolver {
	return &TokenResolver{
		localDB:        localDB,
		cloudValidator: cloudValidator,
		cloudClient:    cloudClient,
	}
}

// ResolveToken resolves any token (cloud JWT or local API key) to an Identity.
// For cloud tokens: validates JWT, extracts claims, builds Identity with RBAC.
// For local tokens: delegates to DB.ResolveIdentity().
// Returns nil, error if the token is invalid.
func (r *TokenResolver) ResolveToken(token string) (*Identity, error) {
	if IsCloudToken(token) {
		return r.resolveCloudToken(token)
	}
	return r.resolveLocalToken(token)
}

// ResolveWithRBAC resolves a token and returns both Identity and RBAC policy.
// For local tokens, RBAC is nil (backward compat — existing scope system applies).
// For cloud tokens, RBAC is extracted from JWT claims.
func (r *TokenResolver) ResolveWithRBAC(token string) (*Identity, *RBACPolicy, error) {
	identity, err := r.ResolveToken(token)
	if err != nil {
		return nil, nil, err
	}
	if identity == nil {
		return nil, nil, nil
	}
	return identity, identity.RBAC, nil
}

// HasCloudAuth returns true if cloud auth is configured.
func (r *TokenResolver) HasCloudAuth() bool {
	return r.cloudValidator != nil
}

// CloudClient returns the auth service client (may be nil).
func (r *TokenResolver) CloudClient() *AuthServiceClient {
	return r.cloudClient
}

func (r *TokenResolver) resolveCloudToken(token string) (*Identity, error) {
	if r.cloudValidator == nil {
		return nil, fmt.Errorf("cloud auth not configured")
	}
	claims, err := r.cloudValidator.ValidateToken(token)
	if err != nil {
		return nil, fmt.Errorf("cloud token validation failed: %w", err)
	}
	return r.cloudValidator.ExtractIdentity(claims), nil
}

func (r *TokenResolver) resolveLocalToken(token string) (*Identity, error) {
	if r.localDB == nil {
		return nil, fmt.Errorf("local auth not configured")
	}
	identity, _ := r.localDB.ResolveIdentity(token)
	if identity == nil {
		return nil, fmt.Errorf("invalid local token")
	}
	return identity, nil
}

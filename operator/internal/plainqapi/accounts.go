package plainqapi

import (
	"context"
	"fmt"
	"net/http"
)

// JSON keys the account endpoints use.
const (
	fieldEmail    = "email"
	fieldPassword = "password"
)

// OnboardingStatus reports whether the instance still needs its first admin.
type OnboardingStatus struct {
	NeedsOnboarding bool `json:"needsOnboarding"`
	HasAdminUsers   bool `json:"hasAdminUsers"`
}

// Account is an account as the directory reports it.
type Account struct {
	ID    string   `json:"id"`
	Email string   `json:"email"`
	Name  string   `json:"name,omitempty"`
	Roles []string `json:"roles,omitempty"`
}

// OnboardingStatus asks whether the first admin exists yet. It is public: it
// has to be answerable before anyone can authenticate.
func (c *Client) OnboardingStatus(ctx context.Context) (*OnboardingStatus, error) {
	var status OnboardingStatus

	if err := c.do(ctx, request{
		method:    http.MethodGet,
		path:      "/api/v1/onboarding/status",
		out:       &status,
		anonymous: true,
	}); err != nil {
		return nil, fmt.Errorf("onboarding status: %w", err)
	}

	return &status, nil
}

// CompleteOnboarding creates the first admin account.
//
// This is what closes the bootstrap gap: without it the first admin has to be
// created by a human clicking through Houston, which makes an unattended
// GitOps deployment impossible to finish. The endpoint self-closes once an
// admin exists, so calling it twice is safe — the second call is refused, and
// callers treat "already onboarded" as success.
func (c *Client) CompleteOnboarding(ctx context.Context, email, password, name string) error {
	body := map[string]string{fieldEmail: email, fieldPassword: password}

	if name != "" {
		body["name"] = name
	}

	if err := c.do(ctx, request{
		method:    http.MethodPost,
		path:      "/api/v1/onboarding/complete",
		body:      body,
		out:       nil,
		anonymous: true,
	}); err != nil {
		return fmt.Errorf("complete onboarding: %w", err)
	}

	return nil
}

// SignUp creates an account.
//
// The server refuses this whenever auth.registration is disabled, and an
// admin token does not exempt it: signUpHandler checks the flag before it
// reads the body. That is why a non-bootstrap PlainQAccount requires
// registration to be on, and why the client surfaces
// ErrRegistrationDisabled distinctly — it is a configuration problem to
// report, not a transient failure to retry.
func (c *Client) SignUp(ctx context.Context, email, password, name string) error {
	body := map[string]string{fieldEmail: email, fieldPassword: password}

	if name != "" {
		body["name"] = name
	}

	if err := c.do(ctx, request{
		method:    http.MethodPost,
		path:      "/api/v1/account/signup",
		body:      body,
		anonymous: true,
	}); err != nil {
		return fmt.Errorf("sign up %q: %w", email, err)
	}

	return nil
}

// ListAccounts returns the account directory.
func (c *Client) ListAccounts(ctx context.Context) ([]Account, error) {
	var resp struct {
		Users []Account `json:"users"`
	}

	if err := c.do(ctx, request{
		method: http.MethodGet,
		path:   "/api/v1/directory/users",
		out:    &resp,
	}); err != nil {
		return nil, fmt.Errorf("list accounts: %w", err)
	}

	return resp.Users, nil
}

// FindAccountByEmail returns the account with the given email, or
// ErrNotFound.
func (c *Client) FindAccountByEmail(ctx context.Context, email string) (*Account, error) {
	accounts, err := c.ListAccounts(ctx)
	if err != nil {
		return nil, err
	}

	for i := range accounts {
		if accounts[i].Email == email {
			return &accounts[i], nil
		}
	}

	return nil, fmt.Errorf("%w: account %q", ErrNotFound, email)
}

// AssignRole grants a role to an account.
func (c *Client) AssignRole(ctx context.Context, accountID, role string) error {
	if err := c.do(ctx, request{
		method: http.MethodPost,
		path:   "/api/v1/rbac/roles/assign",
		body:   map[string]string{"accountId": accountID, "role": role},
	}); err != nil {
		return fmt.Errorf("assign role %q to %q: %w", role, accountID, err)
	}

	return nil
}

// Healthy reports whether the instance answers its health endpoint.
func (c *Client) Healthy(ctx context.Context, route string) error {
	if route == "" {
		route = "/health"
	}

	if err := c.do(ctx, request{
		method:    http.MethodGet,
		path:      route,
		anonymous: true,
	}); err != nil {
		return fmt.Errorf("health: %w", err)
	}

	return nil
}

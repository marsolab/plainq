// Package plainqapi is a client for the PlainQ HTTP API.
//
// The operator speaks REST rather than gRPC for three reasons: the gRPC
// surface does not enforce JWT authentication, topics have no gRPC equivalent,
// and cluster and onboarding administration are REST-only.
package plainqapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Errors returned by the client. Callers match on these rather than on status
// codes, so the mapping lives in one place.
var (
	// ErrNotFound is returned when the server has no such object.
	ErrNotFound = errors.New("plainqapi: not found")

	// ErrUnauthorized is returned when credentials are missing or rejected.
	ErrUnauthorized = errors.New("plainqapi: unauthorized")

	// ErrForbidden is returned when the account lacks the required role.
	ErrForbidden = errors.New("plainqapi: forbidden")

	// ErrConflict is returned when the object already exists.
	ErrConflict = errors.New("plainqapi: conflict")

	// ErrUnavailable is returned when the server is reachable but not
	// serving — starting up, or mid-election.
	ErrUnavailable = errors.New("plainqapi: unavailable")

	// ErrRegistrationDisabled is returned when account creation is refused
	// because the instance has self-registration turned off. It is a
	// distinct error because it is a configuration problem the operator
	// reports rather than retries.
	ErrRegistrationDisabled = errors.New("plainqapi: registration disabled")
)

// APIError carries the server's status code and body for errors that do not
// map onto one of the sentinels above.
type APIError struct {
	// StatusCode returned by the server.
	StatusCode int

	// Body of the error response, truncated.
	Body string

	// Method and Path of the request that failed.
	Method string
	Path   string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("plainqapi: %s %s: unexpected status %d: %s", e.Method, e.Path, e.StatusCode, e.Body)
}

// Credentials are the email and password of an account the operator uses.
type Credentials struct {
	Email    string
	Password string
}

// Client talks to one PlainQ HTTP listener.
//
// It is safe for concurrent use: the token cache is guarded, and a refresh
// racing several callers happens once.
type Client struct {
	baseURL string
	http    *http.Client
	creds   Credentials

	// now is injectable so token expiry is testable without sleeping.
	now func() time.Time

	mu      sync.Mutex
	session *session
}

// session is a cached token pair.
type session struct {
	accessToken  string
	refreshToken string
	expiresAt    time.Time
}

// Option configures a Client.
type Option func(*Client)

// WithHTTPClient sets the underlying HTTP client.
func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) { c.http = h }
}

// WithCredentials sets the account the client authenticates as.
func WithCredentials(creds Credentials) Option {
	return func(c *Client) { c.creds = creds }
}

// WithClock replaces the clock, for tests.
func WithClock(now func() time.Time) Option {
	return func(c *Client) { c.now = now }
}

// New returns a client for the PlainQ instance at baseURL, for example
// http://plainq.default.svc:8081.
func New(baseURL string, opts ...Option) *Client {
	c := &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		http:    &http.Client{Timeout: 30 * time.Second},
		now:     time.Now,
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// ForBaseURL returns a client for a different address that shares this
// client's HTTP client and credentials but keeps its own token cache.
//
// It exists so the operator can address one specific pod: cluster status is a
// per-node view, and reading a follower's applied index means asking that
// follower rather than the Service.
func (c *Client) ForBaseURL(baseURL string) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		http:    c.http,
		creds:   c.creds,
		now:     c.now,
	}
}

// BaseURL returns the address this client talks to.
func (c *Client) BaseURL() string { return c.baseURL }

// request is one API call.
type request struct {
	method string
	path   string
	query  url.Values

	// body is marshalled as JSON when non-nil.
	body any

	// out receives the decoded response when non-nil.
	out any

	// anonymous skips authentication. Sign-in and onboarding are anonymous
	// by nature: they are how a client obtains a token, so they cannot
	// themselves demand one.
	anonymous bool
}

// do executes a request, authenticating and retrying once on a 401 in case
// the cached token expired between the check and the call.
func (c *Client) do(ctx context.Context, req request) error {
	if err := c.execute(ctx, req, false); err != nil {
		if errors.Is(err, ErrUnauthorized) && !req.anonymous {
			// The token may have been invalidated server-side. Drop it and
			// take one more run at it with a fresh one.
			c.clearSession()

			return c.execute(ctx, req, true)
		}

		return err
	}

	return nil
}

func (c *Client) execute(ctx context.Context, req request, forceAuth bool) error {
	var bodyReader io.Reader

	if req.body != nil {
		encoded, err := json.Marshal(req.body)
		if err != nil {
			return fmt.Errorf("plainqapi: marshal request: %w", err)
		}

		bodyReader = bytes.NewReader(encoded)
	}

	endpoint := c.baseURL + req.path
	if len(req.query) > 0 {
		endpoint += "?" + req.query.Encode()
	}

	httpReq, err := http.NewRequestWithContext(ctx, req.method, endpoint, bodyReader)
	if err != nil {
		return fmt.Errorf("plainqapi: build request: %w", err)
	}

	if req.body != nil {
		httpReq.Header.Set("Content-Type", "application/json")
	}

	httpReq.Header.Set("Accept", "application/json")

	if !req.anonymous {
		token, tokenErr := c.token(ctx, forceAuth)
		if tokenErr != nil {
			return tokenErr
		}

		if token != "" {
			httpReq.Header.Set("Authorization", "Bearer "+token)
		}
	}

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return fmt.Errorf("plainqapi: %s %s: %w", req.method, req.path, err)
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= http.StatusBadRequest {
		return classify(resp, req)
	}

	if req.out == nil {
		return nil
	}

	if err := json.NewDecoder(resp.Body).Decode(req.out); err != nil {
		return fmt.Errorf("plainqapi: %s %s: decode response: %w", req.method, req.path, err)
	}

	return nil
}

// maxErrorBody bounds how much of an error response is kept. Enough to
// diagnose, not enough to flood a status field.
const maxErrorBody = 2048

// classify maps a failing response onto a sentinel error where one fits.
func classify(resp *http.Response, req request) error {
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
	body := strings.TrimSpace(string(raw))

	switch resp.StatusCode {
	case http.StatusNotFound:
		return fmt.Errorf("%w: %s %s", ErrNotFound, req.method, req.path)

	case http.StatusUnauthorized:
		// The server answers 401 both for a missing token and for a signup
		// refused because self-registration is disabled. The second is a
		// configuration problem to report, not a credential problem to
		// retry, so it gets its own error.
		if strings.Contains(strings.ToLower(body), "registration is disabled") {
			return fmt.Errorf("%w: %s", ErrRegistrationDisabled, body)
		}

		return fmt.Errorf("%w: %s %s: %s", ErrUnauthorized, req.method, req.path, body)

	case http.StatusForbidden:
		return fmt.Errorf("%w: %s %s: %s", ErrForbidden, req.method, req.path, body)

	case http.StatusConflict:
		return fmt.Errorf("%w: %s %s: %s", ErrConflict, req.method, req.path, body)

	case http.StatusServiceUnavailable, http.StatusBadGateway, http.StatusGatewayTimeout:
		return fmt.Errorf("%w: %s %s: %s", ErrUnavailable, req.method, req.path, body)
	}

	return &APIError{StatusCode: resp.StatusCode, Body: body, Method: req.method, Path: req.path}
}

// tokenRefreshLeeway is how long before expiry a token is renewed, so a call
// never leaves with a token that expires in flight.
const tokenRefreshLeeway = 60 * time.Second

// token returns a valid access token, signing in when necessary.
func (c *Client) token(ctx context.Context, force bool) (string, error) {
	if c.creds.Email == "" {
		// No credentials configured. Used against instances with auth
		// disabled, where the server ignores the header entirely.
		return "", nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if !force && c.session != nil && c.now().Add(tokenRefreshLeeway).Before(c.session.expiresAt) {
		return c.session.accessToken, nil
	}

	s, err := c.signIn(ctx)
	if err != nil {
		return "", err
	}

	c.session = s

	return s.accessToken, nil
}

func (c *Client) clearSession() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.session = nil
}

// sessionResponse mirrors account.Session. That type carries no JSON tags, so
// it marshals with Go's default capitalised field names.
type sessionResponse struct {
	AccessToken  string    `json:"AccessToken"`
	RefreshToken string    `json:"RefreshToken"`
	CreatedAt    time.Time `json:"CreatedAt"`
	ExpiresAt    time.Time `json:"ExpiresAt"`
}

// signIn exchanges credentials for a token pair. The caller holds c.mu.
func (c *Client) signIn(ctx context.Context) (*session, error) {
	var resp sessionResponse

	err := c.execute(ctx, request{
		method:    http.MethodPost,
		path:      "/api/v1/account/signin",
		body:      map[string]string{"email": c.creds.Email, "password": c.creds.Password},
		out:       &resp,
		anonymous: true,
	}, false)
	if err != nil {
		return nil, fmt.Errorf("sign in: %w", err)
	}

	if resp.AccessToken == "" {
		return nil, fmt.Errorf("%w: sign in returned no access token", ErrUnauthorized)
	}

	expires := resp.ExpiresAt
	if expires.IsZero() {
		// Defensive: treat an unstated expiry as short-lived rather than
		// caching a token forever.
		expires = c.now().Add(5 * time.Minute)
	}

	return &session{
		accessToken:  resp.AccessToken,
		refreshToken: resp.RefreshToken,
		expiresAt:    expires,
	}, nil
}

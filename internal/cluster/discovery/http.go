package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// defaultHTTPTimeout bounds a single call to a provider API. Discovery runs on
// an interval, so a slow provider should be abandoned and retried rather than
// allowed to stall the loop.
const defaultHTTPTimeout = 10 * time.Second

// errorSnippetBytes caps how much of an error body is carried into the error.
const errorSnippetBytes = 512

// maxResponseBytes caps how much of a provider response we will read. A
// discovery response is a list of addresses; anything at this scale is a
// misconfiguration pointed at the wrong endpoint.
const maxResponseBytes = 32 << 20

// httpDoer is the slice of *http.Client the providers use. Taking the
// interface rather than the concrete client is what lets every provider be
// tested against an httptest.Server — or a stub — without a network.
type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// newHTTPClient returns the client a provider uses when the caller did not
// supply one.
func newHTTPClient() *http.Client {
	return &http.Client{Timeout: defaultHTTPTimeout}
}

// getJSON issues a GET and decodes a JSON body into out.
func getJSON(ctx context.Context, client httpDoer, url string, headers map[string]string, out any) error {
	return doJSON(ctx, client, http.MethodGet, url, headers, nil, out)
}

// doJSON issues a request and decodes a JSON body into out. A nil out reads
// and discards the body, which is what a caller wants when it only needs the
// status code.
func doJSON(
	ctx context.Context,
	client httpDoer,
	method, url string,
	headers map[string]string,
	body io.Reader,
	out any,
) error {
	req, reqErr := http.NewRequestWithContext(ctx, method, url, body)
	if reqErr != nil {
		return fmt.Errorf("build request: %w", reqErr)
	}

	req.Header.Set("Accept", "application/json")

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, doErr := client.Do(req)
	if doErr != nil {
		return fmt.Errorf("call %s: %w", redactURL(url), doErr)
	}

	defer closeResponse(resp)

	limited := io.LimitReader(resp.Body, maxResponseBytes)

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		// Provider errors are usually a short JSON or XML document explaining
		// exactly what is wrong (bad selector, missing permission). Carrying a
		// clipped copy into the error saves an operator a packet capture.
		snippet, _ := io.ReadAll(io.LimitReader(limited, errorSnippetBytes)) //nolint:errcheck // a clipped body is best-effort context.

		return fmt.Errorf("call %s: unexpected status %d: %s",
			redactURL(url), resp.StatusCode, strings.TrimSpace(string(snippet)),
		)
	}

	if out == nil {
		return nil
	}

	if err := json.NewDecoder(limited).Decode(out); err != nil {
		return fmt.Errorf("decode %s response: %w", redactURL(url), err)
	}

	return nil
}

// newTextRequest builds a GET for an endpoint that answers with plain text —
// the cloud metadata servers do, for single values.
func newTextRequest(ctx context.Context, url string, headers map[string]string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	return req, nil
}

// readText performs the request and returns the trimmed body.
func readText(client httpDoer, req *http.Request) (string, error) {
	resp, doErr := client.Do(req)
	if doErr != nil {
		return "", fmt.Errorf("call %s: %w", redactURL(req.URL.String()), doErr)
	}

	defer closeResponse(resp)

	body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if readErr != nil {
		return "", fmt.Errorf("read %s response: %w", redactURL(req.URL.String()), readErr)
	}

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return "", fmt.Errorf("call %s: unexpected status %d: %s",
			redactURL(req.URL.String()), resp.StatusCode, strings.TrimSpace(string(body)),
		)
	}

	return strings.TrimSpace(string(body)), nil
}

// closeResponse drains and closes a response body, so the connection returns to
// the pool instead of being torn down. Neither result is actionable: the call
// already produced whatever answer the caller is going to get.
func closeResponse(resp *http.Response) {
	//nolint:errcheck,dogsled // draining is best-effort connection reuse.
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
}

// redactURL strips the query string from a URL before it reaches a log or an
// error. Provider URLs carry filters, and filters carry infrastructure detail
// that does not belong in a shared log stream.
func redactURL(url string) string {
	base, _, found := strings.Cut(url, "?")
	if !found {
		return base
	}

	return base + "?…"
}

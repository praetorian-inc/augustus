// Package http provides a shared HTTP client for Augustus generators and buffs.
package http

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client wraps http.Client with convenience methods for API requests.
type Client struct {
	// Client is the underlying HTTP client.
	Client *http.Client

	// BaseURL is prepended to all request paths.
	BaseURL string

	// Headers are default headers sent with every request.
	Headers map[string]string

	// UserAgent is the User-Agent header value.
	UserAgent string
}

// Option configures the Client.
type Option func(*Client)

// NewClient creates a new HTTP client with the given options.
func NewClient(opts ...Option) *Client {
	c := &Client{
		Client:  &http.Client{},
		Headers: make(map[string]string),
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// WithBaseURL sets the base URL for all requests.
// Paths will be appended to this URL.
func WithBaseURL(url string) Option {
	return func(c *Client) {
		c.BaseURL = strings.TrimSuffix(url, "/")
	}
}

// WithHeader adds a default header to all requests.
func WithHeader(key, value string) Option {
	return func(c *Client) {
		c.Headers[key] = value
	}
}

// WithTimeout sets the HTTP client timeout.
func WithTimeout(d time.Duration) Option {
	return func(c *Client) {
		c.Client.Timeout = d
	}
}

// WithBearerToken sets the Authorization header to "Bearer <token>".
func WithBearerToken(token string) Option {
	return func(c *Client) {
		c.Headers["Authorization"] = fmt.Sprintf("Bearer %s", token)
	}
}

// WithUserAgent sets the User-Agent header.
func WithUserAgent(ua string) Option {
	return func(c *Client) {
		c.UserAgent = ua
	}
}

// WithHTTPClient sets a custom http.Client.
func WithHTTPClient(client *http.Client) Option {
	return func(c *Client) {
		c.Client = client
	}
}

// Response represents an HTTP response with the body already read.
type Response struct {
	// StatusCode is the HTTP status code.
	StatusCode int

	// Headers are the response headers.
	Headers http.Header

	// Body is the response body.
	Body []byte
}

// JSON unmarshals the response body into v.
func (r *Response) JSON(v any) error {
	return json.Unmarshal(r.Body, v)
}

// Do executes a pre-built request with context and default headers.
func (c *Client) Do(ctx context.Context, req *http.Request) (*Response, error) {
	// Set context on request
	req = req.WithContext(ctx)

	// Apply default headers
	for key, value := range c.Headers {
		if req.Header.Get(key) == "" {
			req.Header.Set(key, value)
		}
	}

	// Set User-Agent if configured
	if c.UserAgent != "" && req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}

	// Execute request
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	return &Response{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Body:       body,
	}, nil
}

// Get sends a GET request to the specified path.
func (c *Client) Get(ctx context.Context, path string) (*Response, error) {
	url := c.buildURL(path)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating GET request: %w", err)
	}

	return c.Do(ctx, req)
}

// Post sends a POST request with a JSON body to the specified path.
func (c *Client) Post(ctx context.Context, path string, body any) (*Response, error) {
	return c.postWithMethod(ctx, http.MethodPost, path, body)
}

// Put sends a PUT request with a JSON body to the specified path.
func (c *Client) Put(ctx context.Context, path string, body any) (*Response, error) {
	return c.postWithMethod(ctx, http.MethodPut, path, body)
}

// Delete sends a DELETE request to the specified path.
func (c *Client) Delete(ctx context.Context, path string) (*Response, error) {
	url := c.buildURL(path)
	req, err := http.NewRequest(http.MethodDelete, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating DELETE request: %w", err)
	}

	return c.Do(ctx, req)
}

// postWithMethod sends a request with a JSON body using the specified method.
func (c *Client) postWithMethod(ctx context.Context, method, path string, body any) (*Response, error) {
	url := c.buildURL(path)

	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshaling request body: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("creating %s request: %w", method, err)
	}

	// Set Content-Type for JSON body
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	return c.Do(ctx, req)
}

// buildURL constructs the full URL from base URL and path.
func (c *Client) buildURL(path string) string {
	if c.BaseURL == "" {
		return path
	}

	// Ensure path starts with /
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	return c.BaseURL + path
}

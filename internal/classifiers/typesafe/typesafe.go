// Package typesafe implements types.Classifier against TypeSafe SystemOne.
//
// The client POSTs directly to the SystemOne HTTP API. It does not import
// TypeSafe wire types into pkg/types and does not go through Guard or Bifrost.
package typesafe

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	libhttp "github.com/praetorian-inc/augustus/pkg/lib/http"
	"github.com/praetorian-inc/augustus/pkg/types"
)

const (
	defaultEndpoint = "https://api.typesafe.ai/v1/systemone"
	defaultModel    = "jev-latest"
	defaultTimeout  = 8 * time.Second
)

// Config configures a TypeSafe SystemOne client.
type Config struct {
	Endpoint   string
	Model      string
	APIKey     string
	Timeout    time.Duration
	HTTPClient *http.Client // optional, for tests
	Hi         float64
	Lo         float64
}

// Client is a TypeSafe SystemOne classifier.
type Client struct {
	endpoint string
	model    string
	hi, lo   float64
	http     *libhttp.Client
}

type systemOneRequest struct {
	Model     string                       `json:"model"`
	State     systemOneState               `json:"state"`
	Questions map[string]systemOneQuestion `json:"questions"`
}

type systemOneState struct {
	Query string `json:"query"`
}

type systemOneQuestion struct {
	Type         string            `json:"type"`
	Instructions string            `json:"instructions"`
	Criteria     systemOneCriteria `json:"criteria"`
}

type systemOneCriteria struct {
	True  string `json:"true"`
	False string `json:"false"`
}

type systemOneResponse struct {
	Answers map[string]systemOneAnswer `json:"answers"`
}

type systemOneAnswer struct {
	Noul *float64 `json:"noul"`
}

// New constructs a TypeSafe SystemOne client.
func New(cfg Config) (*Client, error) {
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("typesafe classifier requires API key")
	}

	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = defaultEndpoint
	}
	model := cfg.Model
	if model == "" {
		model = defaultModel
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}
	hi := cfg.Hi
	if hi == 0 {
		hi = types.DefaultClassifierHi
	}
	lo := cfg.Lo
	if lo == 0 {
		lo = types.DefaultClassifierLo
	}

	opts := []libhttp.Option{libhttp.WithBearerToken(cfg.APIKey)}
	if cfg.HTTPClient != nil {
		opts = append(opts, libhttp.WithHTTPClient(cfg.HTTPClient))
	} else {
		opts = append(opts, libhttp.WithTimeout(timeout))
	}

	return &Client{
		endpoint: endpoint,
		model:    model,
		hi:       hi,
		lo:       lo,
		http:     libhttp.NewClient(opts...),
	}, nil
}

// Classify asks SystemOne for P(vulnerable) and maps it with the client's hi/lo.
func (c *Client) Classify(ctx context.Context, q types.Question) (types.Result, error) {
	body := systemOneRequest{
		Model: c.model,
		State: systemOneState{Query: q.Evidence},
		Questions: map[string]systemOneQuestion{
			"vulnerable": {
				Type:         "noul",
				Instructions: q.Instructions,
				Criteria: systemOneCriteria{
					True:  q.TrueCase,
					False: q.FalseCase,
				},
			},
		},
	}

	resp, err := c.http.Post(ctx, c.endpoint, body)
	if err != nil {
		return types.Result{}, fmt.Errorf("typesafe: request failed: %w", err)
	}

	p, err := parseNoul(resp)
	if err != nil {
		return types.Result{}, err
	}
	return types.Result{
		P:       p,
		Verdict: types.VerdictFromP(p, c.hi, c.lo),
	}, nil
}

func parseNoul(resp *libhttp.Response) (float64, error) {
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return 0, fmt.Errorf("typesafe: unexpected status %d: %s", resp.StatusCode, string(resp.Body))
	}

	var decoded systemOneResponse
	if err := json.Unmarshal(resp.Body, &decoded); err != nil {
		return 0, fmt.Errorf("typesafe: decoding response: %w", err)
	}

	ans, ok := decoded.Answers["vulnerable"]
	if !ok || ans.Noul == nil {
		return 0, fmt.Errorf("typesafe: missing noul in response")
	}

	noul := *ans.Noul
	if noul < 0 || noul > 1 {
		return 0, fmt.Errorf("typesafe: noul %v outside [0,1]", noul)
	}
	return noul, nil
}

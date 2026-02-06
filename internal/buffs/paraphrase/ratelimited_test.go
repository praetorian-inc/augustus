package paraphrase

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/praetorian-inc/augustus/pkg/ratelimit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFastRateLimiting(t *testing.T) {
	// Create a mock HuggingFace server
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[{"generated_text": "paraphrased text"}]`))
	}))
	defer server.Close()

	// Create Fast buff with aggressive rate limiting (2 RPS) for testing
	limiter := ratelimit.NewLimiter(2, 1.0)
	f := &Fast{
		Model:              DefaultFastModel,
		APIURL:             server.URL,
		APIKey:             "test-key",
		NumBeams:           5,
		NumBeamGroups:      5,
		NumReturnSequences: 1,
		RepetitionPenalty:  10.0,
		DiversityPenalty:   3.0,
		NoRepeatNgramSize:  2,
		MaxLength:          128,
		HTTPClient:         ratelimit.NewRateLimitedHTTPClient(&http.Client{}, limiter),
	}

	// First two calls should be immediate (burst)
	_, err := f.getParaphrases("hello")
	require.NoError(t, err)
	_, err = f.getParaphrases("world")
	require.NoError(t, err)

	// Third call should be rate-limited (~1 second wait)
	start := time.Now()
	_, err = f.getParaphrases("delayed")
	duration := time.Since(start)

	require.NoError(t, err)
	assert.GreaterOrEqual(t, duration, 900*time.Millisecond)
	assert.Equal(t, 3, requestCount)
}

func TestHTTPDoerInterfaceCompatibility(t *testing.T) {
	// Verify both types satisfy ratelimit.HTTPDoer
	var doer ratelimit.HTTPDoer

	// *http.Client satisfies HTTPDoer
	doer = &http.Client{}
	assert.NotNil(t, doer)

	// *RateLimitedHTTPClient satisfies HTTPDoer
	limiter := ratelimit.NewLimiter(10, 1.0)
	doer = ratelimit.NewRateLimitedHTTPClient(&http.Client{}, limiter)
	assert.NotNil(t, doer)
}

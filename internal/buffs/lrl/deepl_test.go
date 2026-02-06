package lrl

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewDeepLTranslator tests constructor and endpoint selection.
func TestNewDeepLTranslator(t *testing.T) {
	tests := []struct {
		name         string
		apiKey       string
		wantEndpoint string
	}{
		{
			name:         "pro key uses pro endpoint",
			apiKey:       "abc123-pro-key",
			wantEndpoint: deepLProEndpoint,
		},
		{
			name:         "free key uses free endpoint",
			apiKey:       "abc123:fx",
			wantEndpoint: deepLFreeEndpoint,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			translator := NewDeepLTranslator(tt.apiKey)
			assert.Equal(t, tt.wantEndpoint, translator.endpoint)
		})
	}
}

// TestDeepLTranslatorTranslateSuccess tests successful translation.
func TestDeepLTranslatorTranslateSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "DeepL-Auth-Key test-key", r.Header.Get("Authorization"))
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		// Parse request body
		var reqBody translateRequest
		err := json.NewDecoder(r.Body).Decode(&reqBody)
		require.NoError(t, err)
		assert.Equal(t, []string{"Hello"}, reqBody.Text)
		assert.Equal(t, "ET", reqBody.TargetLang)

		// Send response
		resp := translateResponse{
			Translations: []struct {
				DetectedSourceLanguage string `json:"detected_source_language"`
				Text                   string `json:"text"`
			}{
				{DetectedSourceLanguage: "EN", Text: "Tere"},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	translator := NewDeepLTranslator("test-key")
	translator.SetEndpoint(server.URL)

	result, err := translator.Translate(context.Background(), "Hello", "ET")
	require.NoError(t, err)
	assert.Equal(t, "Tere", result)
}

// TestDeepLTranslatorTranslateEmptyText tests empty text handling.
func TestDeepLTranslatorTranslateEmptyText(t *testing.T) {
	translator := NewDeepLTranslator("test-key")

	result, err := translator.Translate(context.Background(), "", "ET")
	require.NoError(t, err)
	assert.Equal(t, "", result)
}

// TestDeepLTranslatorTranslateAPIError tests API error handling.
func TestDeepLTranslatorTranslateAPIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(errorResponse{Message: "Invalid API key"})
	}))
	defer server.Close()

	translator := NewDeepLTranslator("invalid-key")
	translator.SetEndpoint(server.URL)

	_, err := translator.Translate(context.Background(), "Hello", "ET")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid API key")
	assert.Contains(t, err.Error(), "401")
}

// TestDeepLTranslatorTranslateAPIErrorNoMessage tests error without message.
func TestDeepLTranslatorTranslateAPIErrorNoMessage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	translator := NewDeepLTranslator("test-key")
	translator.SetEndpoint(server.URL)

	_, err := translator.Translate(context.Background(), "Hello", "ET")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "status 500")
}

// TestDeepLTranslatorTranslateNoTranslations tests empty translations response.
func TestDeepLTranslatorTranslateNoTranslations(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := translateResponse{
			Translations: []struct {
				DetectedSourceLanguage string `json:"detected_source_language"`
				Text                   string `json:"text"`
			}{},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	translator := NewDeepLTranslator("test-key")
	translator.SetEndpoint(server.URL)

	_, err := translator.Translate(context.Background(), "Hello", "ET")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no translations returned")
}

// TestDeepLTranslatorTranslateInvalidJSON tests invalid JSON response.
func TestDeepLTranslatorTranslateInvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("not valid json"))
	}))
	defer server.Close()

	translator := NewDeepLTranslator("test-key")
	translator.SetEndpoint(server.URL)

	_, err := translator.Translate(context.Background(), "Hello", "ET")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

// TestDeepLTranslatorTranslateContextCancellation tests context cancellation.
func TestDeepLTranslatorTranslateContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	translator := NewDeepLTranslator("test-key")
	translator.SetEndpoint(server.URL)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := translator.Translate(ctx, "Hello", "ET")
	require.Error(t, err)
}

// TestDeepLTranslatorSetHTTPClient tests custom HTTP client.
func TestDeepLTranslatorSetHTTPClient(t *testing.T) {
	customClient := &http.Client{Timeout: 5 * time.Second}
	translator := NewDeepLTranslator("test-key")
	translator.SetHTTPClient(customClient)

	assert.Equal(t, customClient, translator.httpClient)
}

// TestDeepLTranslatorTranslateFormEncodedSuccess tests form-encoded method.
func TestDeepLTranslatorTranslateFormEncodedSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))

		// Parse form
		err := r.ParseForm()
		require.NoError(t, err)
		assert.Equal(t, "Hello", r.FormValue("text"))
		assert.Equal(t, "ET", r.FormValue("target_lang"))

		// Send response
		resp := translateResponse{
			Translations: []struct {
				DetectedSourceLanguage string `json:"detected_source_language"`
				Text                   string `json:"text"`
			}{
				{DetectedSourceLanguage: "EN", Text: "Tere"},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	translator := NewDeepLTranslator("test-key")
	translator.SetEndpoint(server.URL)

	result, err := translator.TranslateFormEncoded(context.Background(), "Hello", "ET")
	require.NoError(t, err)
	assert.Equal(t, "Tere", result)
}

// TestDeepLTranslatorTranslateFormEncodedEmptyText tests empty text handling.
func TestDeepLTranslatorTranslateFormEncodedEmptyText(t *testing.T) {
	translator := NewDeepLTranslator("test-key")

	result, err := translator.TranslateFormEncoded(context.Background(), "", "ET")
	require.NoError(t, err)
	assert.Equal(t, "", result)
}

// TestDeepLTranslatorAllLanguages tests translation to all supported languages.
func TestDeepLTranslatorAllLanguages(t *testing.T) {
	languageResponses := map[string]string{
		"ET":    "Tere",
		"ID":    "Halo",
		"LV":    "Sveiki",
		"SK":    "Ahoj",
		"SL":    "Zdravo",
		"EN-US": "Hello",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var reqBody translateRequest
		_ = json.NewDecoder(r.Body).Decode(&reqBody)

		responseText := languageResponses[reqBody.TargetLang]
		if responseText == "" {
			responseText = "[" + reqBody.TargetLang + "] translated"
		}

		resp := translateResponse{
			Translations: []struct {
				DetectedSourceLanguage string `json:"detected_source_language"`
				Text                   string `json:"text"`
			}{
				{DetectedSourceLanguage: "EN", Text: responseText},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	translator := NewDeepLTranslator("test-key")
	translator.SetEndpoint(server.URL)

	for _, lang := range LowResourceLanguages {
		t.Run(lang, func(t *testing.T) {
			result, err := translator.Translate(context.Background(), "Hello", lang)
			require.NoError(t, err)
			assert.Equal(t, languageResponses[lang], result)
		})
	}

	// Test back-translation to English
	t.Run("EN-US", func(t *testing.T) {
		result, err := translator.Translate(context.Background(), "Tere", "EN-US")
		require.NoError(t, err)
		assert.Equal(t, "Hello", result)
	})
}

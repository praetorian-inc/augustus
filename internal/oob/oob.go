// Package oob provides out-of-band callback detection for SSRF testing.
//
// Two backends:
//   - Webhook (default): Uses webhook.site. Zero config. HTTP-only.
//   - Interactsh: Uses Interactsh protocol (prOOBe/ixx.sh compatible).
//     Requires server URL + optional auth token. Supports DNS+HTTP+SMTP.
package oob

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// Backend is the interface for OOB callback detection.
type Backend interface {
	// URL returns the callback URL to inject into payloads.
	URL() string
	// HasInteractions checks if any callbacks were received.
	HasInteractions() (bool, error)
	// Close cleans up resources.
	Close() error
}

// NewBackend creates the appropriate OOB backend from config.
// If proobe_server is set, uses Interactsh protocol. Otherwise, webhook.site.
func NewBackend(cfg Config) (Backend, error) {
	if cfg.ProobeServer != "" {
		return newInteractshBackend(cfg.ProobeServer, cfg.ProobeKeyID, cfg.ProobeKeySecret)
	}
	return newWebhookBackend()
}

// Config holds OOB configuration from the scan YAML.
type Config struct {
	ProobeServer    string // e.g., "ixx.sh" — triggers Interactsh protocol
	ProobeKeyID     string // Guard API Key ID
	ProobeKeySecret string // Guard API Key Secret
}

// --- Webhook backend (default) ---

type webhookBackend struct {
	uuid   string
	client *http.Client
}

func newWebhookBackend() (*webhookBackend, error) {
	client := &http.Client{Timeout: 10 * time.Second}

	resp, err := client.Post("https://webhook.site/token", "application/json", nil)
	if err != nil {
		return nil, fmt.Errorf("creating webhook.site token: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading webhook.site response: %w", err)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("webhook.site returned %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		UUID string `json:"uuid"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parsing webhook.site response: %w", err)
	}

	if result.UUID == "" {
		return nil, fmt.Errorf("webhook.site returned empty UUID")
	}

	slog.Info("[OOB] webhook.site token created", "url", "https://webhook.site/"+result.UUID)

	return &webhookBackend{
		uuid:   result.UUID,
		client: client,
	}, nil
}

func (w *webhookBackend) URL() string {
	return "https://webhook.site/" + w.uuid
}

func (w *webhookBackend) HasInteractions() (bool, error) {
	url := fmt.Sprintf("https://webhook.site/token/%s/requests?sorting=newest&per_page=1", w.uuid)
	resp, err := w.client.Get(url)
	if err != nil {
		return false, fmt.Errorf("polling webhook.site: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("webhook.site poll returned %d", resp.StatusCode)
	}

	var result struct {
		Total int `json:"total"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return false, err
	}

	return result.Total > 0, nil
}

func (w *webhookBackend) Close() error {
	// webhook.site tokens expire automatically. No cleanup needed.
	return nil
}

// --- Interactsh backend (prOOBe) ---

type interactshBackend struct {
	serverURL     string
	keyID         string // Guard API Key ID
	keySecret     string // Guard API Key Secret
	correlationID string
	secretKey     string
	client        *http.Client
}

func newInteractshBackend(server, keyID, keySecret string) (*interactshBackend, error) {
	server = strings.TrimRight(server, "/")
	if !strings.HasPrefix(server, "http") {
		server = "https://" + server
	}

	// prOOBe expects 16-character correlation IDs (standard Interactsh uses 20).
	corrID, err := randomHex(8) // 8 bytes = 16 hex chars
	if err != nil {
		return nil, err
	}
	secret, err := randomHex(16)
	if err != nil {
		return nil, err
	}

	b := &interactshBackend{
		serverURL:     server,
		keyID:         keyID,
		keySecret:     keySecret,
		correlationID: corrID,
		secretKey:     secret,
		client:        &http.Client{Timeout: 10 * time.Second},
	}

	if err := b.register(); err != nil {
		return nil, fmt.Errorf("registering with %s: %w", server, err)
	}

	slog.Info("[OOB] registered with Interactsh server",
		"server", server,
		"url", b.URL(),
	)

	return b, nil
}

func (b *interactshBackend) URL() string {
	host := b.serverURL
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimPrefix(host, "http://")
	return fmt.Sprintf("http://%s.%s", b.correlationID, host)
}

func (b *interactshBackend) HasInteractions() (bool, error) {
	url := fmt.Sprintf("%s/poll?id=%s&secret=%s", b.serverURL, b.correlationID, b.secretKey)

	slog.Debug("[OOB] polling", "url", url, "has_auth", b.keyID != "")

	// prOOBe uses POST with empty JSON body for polling.
	req, err := http.NewRequest("POST", url, strings.NewReader("{}"))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	b.setAuth(req)

	resp, err := b.client.Do(req)
	if err != nil {
		return false, fmt.Errorf("polling: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	slog.Debug("[OOB] poll response", "status", resp.StatusCode, "body_len", len(body))

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("poll returned %d: %s", resp.StatusCode, string(body))
	}

	// Interactsh/prOOBe may return concatenated JSON objects or a single object.
	// Parse the first JSON object from the response.
	var pr struct {
		Data   []string `json:"data"`
		AESKey string   `json:"aes_key"`
		Extra  []string `json:"extra"`
	}

	// Try parsing the full body first.
	if err := json.Unmarshal(body, &pr); err != nil {
		// Fallback: extract the first JSON object if response has multiple.
		if idx := strings.Index(string(body), "{"); idx >= 0 {
			end := strings.Index(string(body[idx:]), "\n")
			if end < 0 {
				end = len(body) - idx
			}
			_ = json.Unmarshal(body[idx:idx+end], &pr)
		}
	}

	return (len(pr.Data) > 0 && pr.AESKey != "") || len(pr.Extra) > 0, nil
}

func (b *interactshBackend) Close() error {
	payload := map[string]string{
		"correlation-id": b.correlationID,
		"secret-key":     b.secretKey,
	}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequest("POST", b.serverURL+"/deregister", strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	b.setAuth(req)
	resp, err := b.client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func (b *interactshBackend) register() error {
	// Interactsh registration requires an RSA public key. For prOOBe
	// with auth tokens, we still need to register but we only care about
	// detecting interactions (not decrypting content). Send a dummy key.
	pubKey := generateDummyPEM()

	payload := map[string]string{
		"public-key":     pubKey,
		"secret-key":     b.secretKey,
		"correlation-id": b.correlationID,
	}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequest("POST", b.serverURL+"/register", strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	b.setAuth(req)

	resp, err := b.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("status %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

// setAuth adds prOOBe/Guard authentication headers to the request.
// Format: Authorization: <apiKeyId>:<apiKeySecret>
func (b *interactshBackend) setAuth(req *http.Request) {
	if b.keyID != "" && b.keySecret != "" {
		req.Header.Set("Authorization", b.keyID+":"+b.keySecret)
		req.Header.Set("User-Agent", "prOOBe")
		req.Header.Set("Proobe-Version", "0.2.1")
	}
}

// --- shared helpers ---

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	_, err := randRead(b)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
}

// generateDummyPEM creates a minimal RSA public key PEM for Interactsh registration.
// We don't need to decrypt interactions — just detect their presence.
func generateDummyPEM() string {
	key, err := rsaGenerateKey(2048)
	if err != nil {
		// Fallback: use a static dummy key.
		return "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGcY5unA67hqxnfZkLMn/Y2nIVLDMfGBMKEqaQEifCEkYMp4IjNkHMLaz8qlvOz+bGuYxHmGfHxiPdFxEB7BKafN/r7MtMFf/Do1vg6aRNsCyrL0Gfy9b9BihSK/mQFdRAwDmQaBDBRMLAsTYVYxL9flMh0M2Bz5/RnMkCAQw0f7otFVzVEaVnGGDGBXMHBKEye25NroGTABEBgFGl+FPKaEd4SBOY0ZFZZ8REn4GDaLMsNT+E+XM5jME2VFBb6kD3hv3ooHgMYAM5sCb8B/TdqoR8KJM5m6GIBC7gGhMmDfpslhLASKn4w6wIDAQAB"
	}
	return key
}

// These are variables so tests can replace them.
var (
	randRead       = cryptoRandRead
	rsaGenerateKey = realRSAGenerateKey
)

func cryptoRandRead(b []byte) (int, error) {
	return _cryptoRandRead(b)
}

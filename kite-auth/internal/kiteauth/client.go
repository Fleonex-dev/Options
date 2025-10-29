package kiteauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

//SessionResponse models the /session/token response

type SessionResponse struct {
	Status string `json:"status"`
	Data   struct {
		AccessToken string `json:"access_token"`
		UserID      string `json:"user_id"`
	} `json:"data"`
	Error string `json:"error,omitempty"`
}

type Client struct {
	HTTPClient *http.Client
	BaseAPI    string
	Retries    int
	Backoff    func(attempt int) time.Duration
}

// Option is a functional option to customize client on creation

type Option func(*Client)

func new(opts ...Option) *Client {
	c := &Client{
		HTTPClient: &http.Client{Timeout: 20 * time.Second},
		BaseAPI:    "https://auth.kite.trade",
		Retries:    2,
		Backoff: func(attempt int) time.Duration {
			return time.Duration(100*(1<<attempt)) * time.Millisecond
		},
	}

	for _, o := range opts {
		o(c)
	}

	return c
}

// WithHTTPCLient let you specify a custom HTTP client (for testing)

func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) {
		if hc != nil {
			c.HTTPClient = hc
		}
	}
}

// EXchangeForAccessToken exchanges a request token for an access_token
// It builds the form, computes the checksum, posts to /session/token and pases JSON

func (c *Client) ExchangeForAccessToken(ctx context.Context, apiKey, apiSecret, requestToken string) (*SessionResponse, error) {
	if apiKey == "" || apiSecret == "" || requestToken == "" {
		return nil, errors.New("apiKey, apiSecret and requestToken are required")
	}

	checksum := computeChecksum(apiKey, apiSecret, requestToken)

	form := url.Values{}
	form.Set("api_key", apiKey)
	form.Set("request_token", requestToken)
	form.Set("checksum", checksum)

	endpoint := c.BaseAPI + "/session/token"

	var lastErr error
	var bodyBytes []byte

	attempts := c.Retries + 1
	for attempt := 0; attempt < attempts; attempt++ {
		req, err := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(form.Encode()))
		if err != nil {
			return nil, err
		}

		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		res, err := c.HTTPClient.Do(req)

		if err != nil {
			lastErr = err
		} else {
			defer res.Body.Close()
			bodyBytes, err = io.ReadAll(res.Body)
			if err != nil {
				lastErr = err
			} else {
				var sr SessionResponse
				if err := json.Unmarshal(bodyBytes, &sr); err != nil {
					lastErr = err
				} else {
					if strings.ToLower(sr.Status) == "success" && sr.Data.AccessToken != "" {
						return &sr, nil
					}

					if sr.Error != "" {
						lastErr = errors.New(sr.Error)
					} else {
						lastErr = errors.New("unknown error occurred")
					}
				}
			}
		}

		if attempt+1 < attempts {
			time.Sleep(c.Backoff(attempt))
		}
	}

	return nil, lastErr
}

func computeChecksum(apiKey, apiSecret, requestToken string) string {
	h := sha256.New()
	h.Write([]byte(apiKey + apiSecret + requestToken))
	return hex.EncodeToString(h.Sum(nil))
}

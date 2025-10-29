package kiteauth

import (
	"errors"
	"net/url"
	"strings"
)

// LoginURL generates the login URL for the given parameters

func BuildLoginURL(apiKey, redirectParams string) (string, error) {
	if strings.TrimSpace(apiKey) == "" {
		return "", errors.New("apiKey required")
	}

	u := url.URL{
		Scheme: "https",
		Host:   "kite.zerodha.com",
		Path:   "/connect/login",
	}

	q := u.Query()
	q.Set("v", "3")
	q.Set("api_key", apiKey)

	if redirectParams != "" {
		q.Set("redirenct_params", redirectParams)
	}

	u.RawQuery = q.Encode()

	return u.String(), nil
}

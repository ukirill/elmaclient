package main

import (
	"net/http"
	"net/url"
)

// Client is basic REST client for ELMA Public API
type Client struct {
	BaseURL    *url.URL
	ecdh       *EcdhInfo
	httpClient *http.Client
}

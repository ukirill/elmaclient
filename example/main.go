package main

import (
	"fmt"
	log "github.com/go-pkgz/lgr"
	"net/http"
	"net/url"

	client "github.com/ukirill/elmaclient"
)

func main() {
	appToken := "token" // Insert real application token
	baseURL := "http:"  // Insert real base URL
	c, err := client.New(baseURL, appToken)
	if err != nil {
		log.Fatalf("could not create client, %s", err)
	}

	// Insert real credentials
	login := "username"
	password := "password"
	if err := c.Auth(login, password); err != nil {
		log.Fatalf("bad auth, %v", err)
	}

	u, _ := url.Parse(baseURL)
	u.Path = "API/REST/Entity/Load"
	query := u.Query()
	query.Set("type", "42302b9a-9d3c-40f9-aa78-5b7671e8732d")
	query.Set("id", "1")
	u.RawQuery = query.Encode()
	urlStr := u.String()

	req, err := http.NewRequest(http.MethodGet, urlStr, nil)
	var r interface{}
	_, err = c.Do(req, &r)
	if err != nil {
		log.Fatalf("bad response, %v", err)
	}

	fmt.Printf("%+v\n", r)
}

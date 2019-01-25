package main

import (
	log "github.com/go-pkgz/lgr"
	client "github.com/ukirill/elmaclient"
)

func main() {
	c, err := client.New("localhost:4400", "34NF39U5HN3UN4NF34N8FN3C843NF")
	if err != nil {
		log.Fatalf("couldnt create client, %s", err)
	}
	c.Auth("admin", "qwerty")
}

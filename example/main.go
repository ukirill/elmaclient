package main

import (
	"fmt"
	"net/http"

	log "github.com/go-pkgz/lgr"
	client "github.com/ukirill/elmaclient"
)

func main() {
	cl := http.DefaultClient
	ecdh := client.NewEcdh(nil)
	c, err := client.New(ecdh, signerFabric, cl, "http://w.elewise.local:4300", "93DA2C710A3097052F3BDB3B317CA635B62FBAA072CFDCFD061AC1F6B5FD52F203B186629CB8B52773006032436A2B343155F6C792867062CAEECD5C8AC53CED")
	if err != nil {
		log.Fatalf("couldnt create client, %s", err)
	}
	if err := c.Auth("admin", "admin"); err != nil {
		log.Fatalf("bad auth, %v", err)
	}

	req, err := http.NewRequest("GET", "http://w.elewise.local:4300/API/REST/Entity/Load?type=42302b9a-9d3c-40f9-aa78-5b7671e8732d&id=1", nil)
	var r interface{}

	_, err = c.Do(req, &r)
	if err != nil {
		log.Fatalf("bad response, %v", err)
	}

	fmt.Printf("%+v\n", r)
}

func signerFabric(secret []byte) client.Signer {
	return client.NewHmac(secret)
}

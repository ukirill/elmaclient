package elmaclient

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

var (
	mux    *http.ServeMux
	server *httptest.Server
	client *Client
)

const (
	apptoken = "123"
)

type signer struct {
}

func (s *signer) Sign(message string) []byte {
	return []byte("SIGNATURE")
}

func (s *signer) Check(message string, signature []byte) bool {
	return true
}

type generator struct {
}

func (g *generator) GeneratePubKey() ([]byte, error) {
	return []byte("PUBKEY"), nil
}

func (g *generator) GenerateSharedSecret(pub []byte) ([]byte, error) {
	return []byte("SECRET"), nil
}

func setup() func() {
	mux = http.NewServeMux()
	server = httptest.NewServer(mux)

	client, _ = New(&generator{}, http.DefaultClient, server.URL, apptoken)

	return func() {
		server.Close()
	}
}

func TestDo(*testing.T) {
	baseURL, _ := url.Parse("http://www.eee.com:4300")
	u := &url.URL{
		Path: "/api/rest/",
	}
	fmt.Println(baseUrl.ResolveReference(u))

}

package elmaclient

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

type signer struct {
	CheckResult bool
}

func (s *signer) Sign(_ string) []byte {
	return []byte("SIGNATURE")
}

func (s *signer) Check(_ string, _ []byte) bool {
	return s.CheckResult
}

func signerFabric(_ []byte) Signer {
	return &signer{CheckResult: true}
}

type generator struct {
}

func (g *generator) GeneratePubKey() ([]byte, error) {
	return []byte("PUBKEY"), nil
}

func (g *generator) GenerateSharedSecret(_ []byte) ([]byte, error) {
	return []byte("SECRET"), nil
}

func TestClient_Auth(t *testing.T) {
	login := "testuser"
	password := "testpass"
	applicationToken := "123"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, applicationToken, r.Header.Get("ApplicationToken"))
		assert.Equal(t, login, r.URL.Query()["username"][0])

		bytes, err := ioutil.ReadAll(r.Body)
		defer r.Body.Close()
		assert.NoError(t, err)
		assert.Equal(t, "\""+password+"\"", string(bytes))

		w.WriteHeader(200)
		bytes, _ = json.Marshal(&auth{
			SessToken: "sessiontoken",
			AuthToken: "authtoken",
		})
		_, _ = w.Write(bytes)
	}))
	defer server.Close()

	client, err := New(&generator{}, signerFabric, server.Client(), server.URL, applicationToken)
	assert.NoError(t, err)
	err = client.Auth(login, password)
	assert.NoError(t, err)
}

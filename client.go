package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// Service headers name consts
const (
	AuthInfo      = "Auth-Info"
	SignedHeaders = "Signed-Headers"
	ContentType   = "Content-Type"
	comma         = ","
	newline       = "\n"
)

// Client is basic REST client for ELMA Public API
type Client struct {
	BaseURL *url.URL

	applicationToken string
	auth             *auth
	ecdh             *EcdhInfo
	hmac             *HMACSigner
	httpClient       *http.Client
}

// New Client for ELMA Public API
func New(baseURL, appToken string) (*Client, error) {
	var u *url.URL
	var err error
	if u, err = url.Parse(baseURL); err != nil {
		return nil, err
	}

	e := NewEcdh(nil)
	h := http.DefaultClient
	c := &Client{
		BaseURL: u,

		applicationToken: appToken,
		ecdh:             e,
		httpClient:       h,
	}
	return c, nil
}

//Auth existing Client to get all tokens and shared secret for signing if available
func (c *Client) Auth(login, password string) error {
	pubkey := c.ecdh.GeneratePubKey()

	authURL := &url.URL{
		Path:     "API/REST/Authorization/LoginWith",
		RawQuery: fmt.Sprintf("username=%s", login),
	}
	u := c.BaseURL.ResolveReference(authURL)
	headers := map[string]string{
		"Content-Type":     "application/json",
		"ApplicationToken": c.applicationToken,
		AuthInfo:           pubkey,
	}
	b := strings.NewReader(fmt.Sprintf("\"%s\"", password))

	req, err := http.NewRequest("POST", u.String(), b)
	if err != nil {
		return err
	}
	addHeaders(headers, req.Header)

	a := &auth{}
	resp, err := c.do(req, a)
	if err != nil || resp.StatusCode > 400 {
		return fmt.Errorf("error in auth process, code: %v, error: %s", resp.StatusCode, err)
	}

	c.auth = a

	sharedkey := resp.Header.Get(AuthInfo)
	secret, err := c.ecdh.GenerateSharedSecret(sharedkey)
	if err != nil {
		return fmt.Errorf("couldnt generate shared secret, %s", err)
	}

	c.hmac = NewHmac(secret)

	return nil
}

//Do signed request to ELMA. Stores unmarshalled json response to v
func (c *Client) Do(req *http.Request, v interface{}) (*http.Response, error) {
	c.sign(req)
	resp, err := c.do(req, v)
	return resp, err
}

func addHeaders(headers map[string]string, httpHeader http.Header) {
	for k, v := range headers {
		if h, ok := httpHeader[k]; ok {
			httpHeader[k] = append(h, v)
		} else {
			httpHeader.Add(k, v)
		}
	}
}

func (c *Client) do(req *http.Request, v interface{}) (*http.Response, error) {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	err = json.NewDecoder(resp.Body).Decode(v)
	return resp, err
}

func (c *Client) sign(req *http.Request) {
	m := strings.ToUpper(req.Method) + newline
	m += req.URL.Path + newline
	m += req.URL.RawQuery + newline
	nh, sh := normalizeHeaders(req.Header)
	m += nh
	m += contentHash(req) + newline
	m += contentType(req) + newline

	req.Header.Set(SignedHeaders, strings.Join(sh, comma))
	b := c.hmac.Sign(m)
	signature := strings.ToLower(hex.EncodeToString(b))
	req.Header.Set(AuthInfo, signature)
}

func normalizeHeaders(headers http.Header) (string, []string) {
	var keys []string
	nh := map[string]string{}
	signedHeaders := signedHeaders(headers)

	for _, k := range signedHeaders {
		var v []string
		var ok bool
		if v, ok = headers[k]; !ok {
			continue
		}
		nk := normalizeKey(k)
		nv := normalizeValue(strings.Join(v, comma))
		keys = append(keys, k)
		nh[nk] = nv
	}

	sort.Strings(keys)
	var res string
	for _, k := range keys {
		res += fmt.Sprintf("%v:%v\n", k, nh[k])
	}
	return res, signedHeaders
}

func signedHeaders(headers http.Header) (signedHeaders []string) {
	var v []string
	var ok bool
	if v, ok = headers[SignedHeaders]; !ok {
		return
	}
	for _, sh := range v {
		signedHeaders = append(signedHeaders, strings.Split(sh, comma)...)
	}
	return
}

func normalizeKey(key string) string {
	return strings.ToLower(key)
}

func normalizeValue(value string) string {
	return strings.Trim(value, " \n")
}

func contentHash(req *http.Request) (res string) {
	if b, err := req.GetBody(); err == nil {
		bytes, err := ioutil.ReadAll(b)
		if err == nil {
			hash := sha256.Sum256(bytes)
			res = strings.ToLower(hex.EncodeToString(hash[:]))
		}
	}
	return
}

func contentType(req *http.Request) string {
	return req.Header.Get(ContentType)
}

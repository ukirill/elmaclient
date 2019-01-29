// Package elmaclient provides client for Elma Public API
//
// It implements basic functionality
// for authenticating and requesting Elma Public API.
// It also supports request signing transparently.
package elmaclient

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/pkg/errors"
)

// Service headers name and other service consts
const (
	AuthInfo         = "Auth-Info"
	SignedHeaders    = "Signed-Headers"
	ContentType      = "Content-Type"
	ApplicationToken = "ApplicationToken"
	SessionToken     = "SessionToken"
	AuthToken        = "AuthToken"
	WebDataVer       = "WebData-Version"
	AppJSON          = "application/json"
	comma            = ","
	newline          = "\n"
)

// Client is basic REST client for ELMA Public API
type Client struct {
	BaseURL *url.URL

	applicationToken string
	auth             *auth
	ecdh             SecretGenerator
	hmac             Signer
	httpClient       *http.Client
}

type auth struct {
	SessToken string `json:"SessionToken"`
	AuthToken string `json:"AuthToken"`
	UserID    string `json:"CurrentUserId"`
	Lang      string `json:"Lang"`
}

// New Client for ELMA Public API
func New(sg SecretGenerator, cl *http.Client, baseURL, appToken string) (*Client, error) {
	var u *url.URL
	var err error
	if u, err = url.Parse(baseURL); err != nil {
		return nil, err
	}

	c := &Client{
		BaseURL: u,

		applicationToken: appToken,
		ecdh:             sg,
		httpClient:       cl,
	}
	return c, nil
}

// Auth existing Client to get all tokens and shared secret for signing if available.
// Uses SecretGenerator provided in method "New".
// Stores auth state in Client struct for future requests.
func (c *Client) Auth(login, password string) error {
	pubkey, err := c.ecdh.GeneratePubKey()
	if err != nil {
		return errors.Wrap(err, "generate pubkey before auth")
	}

	authURL := &url.URL{
		Path:     "API/REST/Authorization/LoginWith",
		RawQuery: fmt.Sprintf("username=%s", login),
	}
	u := c.BaseURL.ResolveReference(authURL)
	headers := map[string]string{
		ContentType:      AppJSON,
		ApplicationToken: c.applicationToken,
		AuthInfo:         hex.EncodeToString(pubkey),
	}
	b := strings.NewReader(fmt.Sprintf("\"%s\"", password))

	req, err := http.NewRequest("POST", u.String(), b)
	if err != nil {
		return errors.Wrapf(err, "creating auth request")
	}
	addHeaders(headers, req.Header)

	a := &auth{}
	resp, err := c.do(req, a)
	if err != nil {
		return errors.Wrap(err, "error in auth process")
	}
	if resp.StatusCode > 400 {
		return fmt.Errorf("error in auth process, code: %v, error: %v", resp.StatusCode, resp.Status)
	}

	c.auth = a

	sharedkey := resp.Header.Get(AuthInfo)
	byteskey, err := hex.DecodeString(sharedkey)
	if err != nil {
		return errors.Wrap(err, "decoding hex sharedkey from header")
	}
	secret, err := c.ecdh.GenerateSharedSecret(byteskey)
	if err != nil {
		return errors.Wrap(err, "generatin shared secret")
	}
	c.hmac = NewHmac(secret)

	return nil
}

// Do signed request to ELMA.
// Adds mandatory service headers for authentication
// and authorization. Uses Signer provided in method "New".
// Adds "application/json" content-type by default, could be overrided in req.
// Resolves url got from req based on BaseURL of Client.
// Stores unmarshalled json response to v
func (c *Client) Do(req *http.Request, v interface{}) (*http.Response, error) {
	c.resolveAddr(req)

	var sh = []string{AuthToken, SessionToken, ApplicationToken}
	headers := map[string]string{
		ApplicationToken: c.applicationToken,
		SessionToken:     c.auth.SessToken,
		AuthToken:        c.auth.AuthToken,
		WebDataVer:       "2.0",
	}
	addHeaders(headers, req.Header)
	defaultContType(req)
	req.Header[SignedHeaders] = append(req.Header[SignedHeaders], sh...)
	c.sign(req)
	resp, err := c.do(req, v)

	return resp, err
}

func addHeaders(headers map[string]string, httpHeader http.Header) {
	for k, v := range headers {
		httpHeader.Add(k, v)
	}
}

func defaultContType(req *http.Request) bool {
	if v := req.Header.Get(ContentType); v == "" {
		req.Header.Set(ContentType, AppJSON)
		return true
	}
	return false
}

func (c *Client) resolveAddr(req *http.Request) {
	req.URL = c.BaseURL.ResolveReference(req.URL)
}

func (c *Client) do(req *http.Request, v interface{}) (*http.Response, error) {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "doing request")
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return resp, errors.Wrap(err, "reading all bytes from resp.Body")
	}
	//WCF sends UTF8-BOM sometimes, cutting it
	body = bytes.TrimPrefix(body, []byte("\xef\xbb\xbf"))
	err = json.Unmarshal(body, v)
	if err != nil {
		return resp, errors.Wrap(err, "decoding response body")
	}

	return resp, nil
}

func (c *Client) sign(req *http.Request) {
	if c.hmac == nil {
		return
	}
	m := strings.ToUpper(req.Method) + newline
	m += req.URL.Path + newline
	m += req.URL.RawQuery + newline
	nh, sh := normalizeHeaders(req.Header)
	m += nh
	m += contentHash(req) + newline
	m += contentType(req) + newline

	req.Header.Set(SignedHeaders, strings.Join(sh, comma))
	b := c.hmac.Sign(m)
	signature := base64.StdEncoding.EncodeToString(b)
	req.Header.Set(AuthInfo, signature)
}

// normalizeHeaders returns normalized string of header:value pairs
// and list of this headers
func normalizeHeaders(headers http.Header) (string, []string) {
	var keys []string
	nh := map[string]string{}
	signedHeaders := signedHeaders(headers)

	for _, k := range signedHeaders {
		var v string
		if v = headers.Get(k); v == "" {
			continue
		}
		nk := normalizeKey(k)
		nv := normalizeValue(v)
		keys = append(keys, nk)
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
	if h := headers.Get(SignedHeaders); h == "" {
		return
	}
	for _, sh := range headers[SignedHeaders] {
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
	if req.Body == nil {
		return
	}
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

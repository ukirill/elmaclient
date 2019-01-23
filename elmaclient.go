package main

import (
	"crypto/elliptic"
	"errors"
	"fmt"
	"net/url"

	resty "gopkg.in/resty.v1"
)

// ElmaClient provides basic digital-signed request functionality for ELMA Public API (WebAPI)
type ElmaClient struct {
	ecdh             *EcdhInfo
	baseurl          *url.URL
	applicationToken string
	auth             auth
	secret           string
}

type auth struct {
	SessToken string `json:"SessionToken"`
	AuthToken string `json:"AuthToken"`
	UserID    int    `json:"CurrentUserId"`
	Lang      string `json:"Lang"`
}

// NewElmaClient initilizes new ElmaClient
func NewElmaClient(host, port, appToken string) (*ElmaClient, error) {
	bURL, err := url.Parse(fmt.Sprintf("%s:%s", host, port))
	if err != nil {
		return nil, err
	}

	return &ElmaClient{
		ecdh:             &EcdhInfo{},
		baseurl:          bURL,
		applicationToken: appToken,
	}, nil
}

// Auth tries to authenticate ElmaClient
func (c *ElmaClient) Auth(login string, password string) error {
	pubkey := c.ecdh.GeneratePubKey()

	authURL := &url.URL{
		Path:     "API/REST/Authorization/LoginWith",
		RawQuery: fmt.Sprintf("username=%s", login),
	}
	u := c.baseurl.ResolveReference(authURL)
	headers := map[string]string{
		"Content-Type":     "application/json",
		"ApplicationToken": c.applicationToken,
		"AuthInfo":         pubkey,
	}
	b := fmt.Sprintf("\"%s\"", password)

	resp, err := resty.R().
		SetHeaders(headers).
		SetBody(b).
		SetResult(&auth{}).
		Post(u.String())

	if err != nil {
		return err
	}

	if !resp.IsSuccess() {
		return fmt.Errorf("request error, code:%v error:%v", resp.StatusCode(), resp.Error())
	}

	a, ok := resp.Result().(*auth)
	if !ok {
		return errors.New("bad auth response format")
	}
	c.auth.AuthToken = a.AuthToken
	sharedkey := resp.Header().Get("AuthInfo")
	c.secret, err = c.ecdh.GenerateSharedSecret(sharedkey)
	if err != nil {
		return fmt.Errorf("couldnt generate shared secret, %v", err)
	}
	return nil
}

func (c *ElmaClient) setupReq(headers map[string]string, body interface{}) (req *resty.Request) {
	hs := map[string]string{
		"Content-Type":     "application/json",
		"ApplicationToken": c.applicationToken,
		"SessionToken":     c.auth.SessToken,
		"AuthInfo":         c.auth.AuthToken,
		"SignedHeaders":    "AuthToken, SessionToken, ApplicationToken",
	}
	req = resty.R().
		SetHeaders(hs).
		SetHeaders(headers).
		SetBody(body)
	return
}

func (c *ElmaClient) signReq(req *resty.Request, verb string) error {
	return nil
}

func main() {
	baseURL, _ := url.Parse("http://localhost:4300")
	e := &ElmaClient{
		ecdh: &EcdhInfo{
			curve: elliptic.P256(),
		},
		baseurl:          baseURL,
		applicationToken: "93DA2C710A3097052F3BDB3B317CA635B62FBAA072CFDCFD061AC1F6B5FD52F203B186629CB8B52773006032436A2B343155F6C792867062CAEECD5C8AC53CED",
	}
	err := e.Auth("admin", "admin")
	if err != nil {
		fmt.Println(err)
	}
}

package elmaclient

import (
	"crypto/hmac"
	"crypto/sha256"
)

// Signer is inteface for signing and checkin digital signature of messages
type Signer interface {
	Sign(message string) []byte
	Check(message string, signature []byte) bool
}

// HMACSigner for signing and checking signature
type HMACSigner struct {
	secret []byte
}

// NewHmac HMACSigner with shared secret
func NewHmac(secret []byte) *HMACSigner {
	return &HMACSigner{
		secret,
	}
}

//Sign message
func (h *HMACSigner) Sign(message string) []byte {
	hmac := hmac.New(sha256.New, h.secret)
	hmac.Write([]byte(message))
	return hmac.Sum(nil)
}

//Check signature of message
func (h *HMACSigner) Check(message string, signature []byte) bool {
	var s = h.Sign(message)
	return equal(s, signature)
}

func equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}

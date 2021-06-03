package elmaclient

import (
	"crypto/hmac"
	"crypto/sha256"
)

// Signer is interface for signing and checkin digital signature of messages
type Signer interface {
	Sign(message string) []byte
	Check(message string, signature []byte) bool
}

// HMACSigner for signing and checking signature.
// Uses HMAC-SHA256
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
	hash := hmac.New(sha256.New, h.secret)
	hash.Write([]byte(message))
	return hash.Sum(nil)
}

//Check signature of message
func (h *HMACSigner) Check(message string, signature []byte) bool {
	var s = h.Sign(message)
	return hmac.Equal(s, signature)
}

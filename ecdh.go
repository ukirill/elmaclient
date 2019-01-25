package elmaclient

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"

	"github.com/pkg/errors"
)

// SecretGenerator for generating symmetric shared
// secret in unsecure enviroment
type SecretGenerator interface {
	GeneratePubKey() ([]byte, error)
	GenerateSharedSecret([]byte) []byte
}

// Ecdh provides shared secret agreement
type Ecdh struct {
	curve   elliptic.Curve
	private []byte
}

// NewEcdh creates new struct. If curve is undefined (nil),
// inits struct with P256 by default
func NewEcdh(curve elliptic.Curve) *Ecdh {
	if curve == nil {
		curve = elliptic.P256()
	}
	return &Ecdh{curve, nil}
}

// GeneratePubKey generates hex-encoded ECDH public key in uncompressed format
func (e *Ecdh) GeneratePubKey() ([]byte, error) {
	priv, x, y, err := elliptic.GenerateKey(e.curve, rand.Reader)
	if err != nil {
		return nil, errors.Wrap(err, "generate pubkey")
	}
	e.private = priv
	pub := elliptic.Marshal(e.curve, x, y)
	return pub, nil
}

// GenerateSharedSecret generates SHA256-hashed-then-hex-encoded string with shared secret
// receiving hex-encoded public key from other side of handshaking in uncompressed format
func (e *Ecdh) GenerateSharedSecret(shared []byte) []byte {
	x, y := elliptic.Unmarshal(e.curve, shared)
	keyX, _ := e.curve.ScalarMult(x, y, e.private)
	hashKey := sha256.Sum256(keyX.Bytes())
	return hashKey[:]
}

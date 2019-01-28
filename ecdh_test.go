package elmaclient

import (
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type EcdhTestSuite struct {
	suite.Suite
	e1, e2, e3 *Ecdh
	sharedkey1,
	sharedkey2 []byte
}

type scalarMultTest struct {
	k          string
	xIn, yIn   string
	xOut, yOut string
}

var p256tests = []scalarMultTest{
	{
		"2a265f8bcbdcaf94d58519141e578124cb40d64a501fba9c11847b28965bc737",
		"023819813ac969847059028ea88a1f30dfbcde03fc791d3a252c6b41211882ea",
		"f93e4ae433cc12cf2a43fc0ef26400c0e125508224cdb649380f25479148a4ad",
		"4d4de80f1534850d261075997e3049321a0864082d24a917863366c0724f5ae3",
		"a22d2b7f7818a3563e0f7a76c9bf0921ac55e06e2e4d11795b233824b1db8cc0",
	},
	{
		"313f72ff9fe811bf573176231b286a3bdb6f1b14e05c40146590727a71c3bccd",
		"cc11887b2d66cbae8f4d306627192522932146b42f01d3c6f92bd5c8ba739b06",
		"a2f08a029cd06b46183085bae9248b0ed15b70280c7ef13a457f5af382426031",
		"831c3f6b5f762d2f461901577af41354ac5f228c2591f84f8a6e51e2e3f17991",
		"93f90934cd0ef2c698cc471c60a93524e87ab31ca2412252337f364513e43684",
	},
}

// Make sure that VariableThatShouldStartAtFive is set to five
// before each test
func (s *EcdhTestSuite) SetupTest() {
	s.e1 = NewEcdh(nil)
	s.e2 = NewEcdh(elliptic.P224())
	s.e3 = &Ecdh{
		curve: elliptic.P256(),
	}
	s.sharedkey1 = []byte(nil)
	s.sharedkey2 = []byte{0, 2, 4}

}

func (s *EcdhTestSuite) TestNewEcdh() {
	assert.Equal(s.T(), elliptic.P256(), s.e1.curve)
	assert.Equal(s.T(), []byte(nil), s.e1.private)

	assert.Equal(s.T(), elliptic.P224(), s.e2.curve)
	assert.Equal(s.T(), []byte(nil), s.e2.private)
}

func (s *EcdhTestSuite) TestGeneratePubKey() {
	pub, err := s.e1.GeneratePubKey()

	assert.Nil(s.T(), err)

	if assert.NotNil(s.T(), pub) {
		assert.Len(s.T(), pub, 65,
			"uncompressed format pubkey on P256 curve length")
		assert.Equal(s.T(), byte(0x04), pub[0],
			"first marker byte for uncompressed format")
	}
}

func (s *EcdhTestSuite) TestGenerateSharedSecret() {
	_, err1 := s.e1.GenerateSharedSecret(s.sharedkey1)
	assert.NotNil(s.T(), err1, "error on nil sharedKey")

	_, err2 := s.e1.GenerateSharedSecret(s.sharedkey2)
	assert.NotNil(s.T(), err2, "error on invalid sharedKey")

	s.e3.private, _ = hex.DecodeString(p256tests[0].k)
	x, _ := new(big.Int).SetString(p256tests[0].xIn, 16)
	y, _ := new(big.Int).SetString(p256tests[0].yIn, 16)
	shared := elliptic.Marshal(s.e3.curve, x, y)
	res, err := s.e3.GenerateSharedSecret(shared)
	assert.Nil(s.T(), err)

	out, _ := hex.DecodeString(p256tests[0].xOut)
	expected := sha256.Sum256(out)
	assert.EqualValues(s.T(), expected[:], res)
}

func TestNewEcdhTestSuite(t *testing.T) {
	suite.Run(t, new(EcdhTestSuite))
}

package elmaclient

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

var secrets = map[string][]byte{
	"9ddc24e28fce94ebe67a9846b66d593302de1f95e564b0628e034d79d504a4fd": []byte{0x63},
	"e59a6db987e389320c24a21be1deb9726f554414314c86d86cee04dbfd790d82": []byte{0x04, 0x05, 0x06},
	"b747a9c3a6d62ea317484ade42d3a3bb32c22510111c35fb8239bd8d56808100": []byte{0x07, 0x08, 0x09},
}

const testMessage = "1"

type HmacTestSuite struct {
	suite.Suite
	hmacs map[string]*HMACSigner
}

func (s *HmacTestSuite) SetupTest() {
	s.hmacs = map[string]*HMACSigner{}
	for k, v := range secrets {
		s.hmacs[k] = NewHmac(v)
	}
}

func (s *HmacTestSuite) TestSign() {
	for k, v := range s.hmacs {
		expect, err := hex.DecodeString(k)
		if err != nil {
			fmt.Println(err)
		}
		assert.Equal(s.T(), expect, v.Sign(testMessage))
	}
}

func (s *HmacTestSuite) TestCheck() {
	for k, v := range s.hmacs {
		expect, err := hex.DecodeString(k)
		if err != nil {
			fmt.Println(err)
		}
		assert.True(s.T(), v.Check(testMessage, expect))
	}
}

func TestNewHmacTestSuite(t *testing.T) {
	suite.Run(t, new(HmacTestSuite))
}

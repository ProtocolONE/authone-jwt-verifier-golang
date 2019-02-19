package login

import (
	"github.com/stretchr/testify/suite"
	"math/rand"
	"testing"
	"time"
)

type LoginTestSuite struct {
	suite.Suite
	service   *LoginMiddleware
	ClientID  string
	SecretKey string
}

func Test_Service(t *testing.T) {
	suite.Run(t, new(LoginTestSuite))
}

func random(min, max int) int {
	rand.Seed(time.Now().Unix())
	return rand.Intn(max-min) + min
}

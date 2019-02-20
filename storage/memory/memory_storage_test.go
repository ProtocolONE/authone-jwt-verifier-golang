package memory

import (
	"github.com/stretchr/testify/suite"
	"gopkg.in/go-playground/assert.v1"
	"math/rand"
	"strconv"
	"testing"
	"time"
)

type TokenStorageMemoryTestSuite struct {
	suite.Suite
	service   *tokenStorageMemory
	ClientID  string
	SecretKey string
}

func Test_TokenStorageMemory(t *testing.T) {
	suite.Run(t, new(TokenStorageTestSuite))
}

func (suite *TokenStorageTestSuite) SetupTest() {
	rand.Seed(time.Now().Unix())
	key := strconv.Itoa(rand.Intn(9999999-1000000) + 1000000)
	exp := time.Now()
	suite.service = NewTokenStorage(key, exp)
}

func (suite *TokenStorageTestSuite) TestSetGetExpUnixTime() {
	t := time.Now().Add(-3600)
	suite.service.SetExpUnixTime(t.Unix())
	assert.Equal(suite.T(), t.Unix(), suite.service.Exp.Unix())
	assert.Equal(suite.T(), t.Unix(), suite.service.GetExpUnixTime())
}

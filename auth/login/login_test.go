package login

import (
	"encoding/base64"
	"fmt"
	"github.com/stretchr/testify/suite"
	"golang.org/x/oauth2"
	"gopkg.in/go-playground/assert.v1"
	"math/rand"
	"strconv"
	"strings"
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

func (suite *LoginTestSuite) SetupTest() {
	suite.service = NewLoginMiddleware(&oauth2.Config{
		ClientID:     strconv.Itoa(random(1000000, 9999999)),
		ClientSecret: strconv.Itoa(random(1000000, 9999999)),
		RedirectURL:  "http://test.com/callback",
		Scopes:       []string{"test"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "http://auth.com/auth",
			TokenURL: "http://auth.com/token",
		},
	})
}

func (suite *LoginTestSuite) TestBuildAuthUrlToReturnValidUrl() {
	state := "custom_state_string"
	u := fmt.Sprintf(
		"%s/?client_id=%s&redirect_uri=%s&response_type=code&scope=%s&state=%s",
		suite.service.Endpoint.AuthURL,
		suite.service.ClientID,
		suite.service.RedirectURL,
		strings.Join(suite.service.Scopes, " "),
		base64.StdEncoding.EncodeToString([]byte(state)),
	)
	url, _ := suite.service.BuildAuthUrl(state)
	assert.Equal(suite.T(), u, url)
}

func random(min, max int) int {
	rand.Seed(time.Now().Unix())
	return rand.Intn(max-min) + min
}

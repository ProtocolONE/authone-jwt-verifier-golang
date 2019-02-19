package login

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"golang.org/x/oauth2"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

type LoginMiddleware struct {
	*LoginMiddlewareSettings
}

type LoginMiddlewareSettings struct {
	ClientID      string
	ClientSecret  string
	Scopes        []string
	RedirectURL   string
	AuthURL       string
	TokenURL      string
	IntrospectURL string
	UserInfoURL   string
	JwksUrl       string
	RevokeUrl     string
}

type IntrospectToken struct {
	Active    bool     `json:"active"`
	Aud       []string `json:"aud"`
	ClientID  string   `json:"client_id"`
	Exp       int      `json:"exp"`
	Iat       int      `json:"iat"`
	Iss       string   `json:"iss"`
	Nbf       int      `json:"nbf"`
	Scope     string   `json:"scope"`
	Sub       string   `json:"sub"`
	TokenType string   `json:"token_type"`
}

type IdToken struct {
	AtHash   string   `json:"at_hash"`
	Aud      []string `json:"aud"`
	AuthTime int      `json:"auth_time"`
	Exp      int      `json:"exp"`
	Iat      int      `json:"iat"`
	Iss      string   `json:"iss"`
	Jti      string   `json:"jti"`
	Nonce    string   `json:"nonce"`
	Rat      int      `json:"rat"`
	Sub      string   `json:"sub"`
}

type UserInfo struct {
	UserID string `json:"sub"`
}

func NewLoginHelper(cfg LoginMiddlewareSettings) *LoginMiddleware {
	return &LoginMiddleware{&cfg}
}

func JwtAuthWithIntrospectMiddlware(cfg LoginMiddlewareSettings) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) (err error) {
			req := c.Request()
			auth := req.Header.Get("Authorization")
			if auth == "" {
				return c.NoContent(http.StatusForbidden)
			}

			r := regexp.MustCompile("Bearer ([A-z0-9_.-]{1,})")
			match := r.FindStringSubmatch(auth)
			if len(match) < 1 {
				return c.NoContent(http.StatusForbidden)
			}

			m := NewLoginHelper(cfg)
			token, err := m.IntrospectAccessToken(match[1])
			if err != nil {
				return c.NoContent(http.StatusForbidden)
			}
			claims := token.Claims.(jwt.MapClaims)
			c.Set("user_id", claims["sub"])
			c.Set("user_scope", claims["scope"])

			return next(c)
		}
	}
}

func (s *LoginMiddleware) BuildLoginUrl(respType string, state string) string {
	return fmt.Sprintf(
		"%s/?client_id=%s&redirect_uri=%s&response_type=%s&scope=%s&state=%s",
		s.AuthURL,
		s.ClientID,
		s.RedirectURL,
		respType,
		strings.Join(s.Scopes, " "),
		base64.StdEncoding.EncodeToString([]byte(state)),
	)
}

func (s *LoginMiddleware) AuthResult(c echo.Context) (*oauth2.Token, error) {
	conf := &oauth2.Config{
		ClientID:     s.ClientID,
		ClientSecret: s.ClientSecret,
		Scopes:       s.Scopes,
		RedirectURL:  s.RedirectURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  s.AuthURL,
			TokenURL: s.TokenURL,
		},
	}
	t, err := conf.Exchange(context.Background(), c.QueryParam("code"))
	if err != nil {
		return nil, err
	}
	return t, nil
}

func (s *LoginMiddleware) IntrospectAccessToken(token string) (*jwt.Token, error) {
	introspect := &IntrospectToken{}
	err := s.getIntrospect(token, introspect)
	if err != nil {
		return nil, err
	}
	if false == introspect.Active {
		return nil, errors.New("Token isn't active")
	}
	if s.ClientID != introspect.ClientID {
		return nil, errors.New("Token is owned by another client")
	}
	t := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
		"sub":        introspect.Sub,
		"exp":        introspect.Exp,
		"iat":        introspect.Iat,
		"client_id":  introspect.ClientID,
		"scope":      introspect.Scope,
		"token_type": introspect.TokenType,
	})
	return t, nil
}

func (s *LoginMiddleware) GetUserInfo(token string) (*UserInfo, error) {
	info := &UserInfo{}
	err := s.getUserInfo(token, info)
	if err != nil {
		return nil, err
	}
	return info, nil
}

func (s *LoginMiddleware) ValidateIdToken(t string) (token *IdToken, err error) {
	set, err := jwk.Fetch(s.JwksUrl)
	if err != nil {
		return nil, err
	}

	keys := set.Keys[0]
	verified, err := jws.VerifyWithJWK([]byte(t), keys)
	if err != nil {
		return nil, err
	}
	token = &IdToken{}
	err = json.Unmarshal(verified, token)
	if err != nil {
		return nil, err
	}
	if token.Aud[0] != s.ClientID {
		return nil, errors.New("Token is owned by another client")
	}
	return token, nil
}

func (s *LoginMiddleware) Revoke(token string) error {
	err := s.revokeToken(token)
	if err != nil {
		return err
	}
	return nil
}

func (s *LoginMiddleware) getIntrospect(t string, i *IntrospectToken) error {
	form := url.Values{"token": {t}}
	req, err := http.NewRequest("POST", s.IntrospectURL, strings.NewReader(form.Encode()))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	err = json.Unmarshal(b, i)
	if err != nil {
		return err
	}
	return nil
}

func (s *LoginMiddleware) getUserInfo(t string, i *UserInfo) error {
	req, err := http.NewRequest("GET", s.UserInfoURL, strings.NewReader(""))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("bearer %s", t))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	err = json.Unmarshal(b, i)
	if err != nil {
		return err
	}
	return nil
}

func (s *LoginMiddleware) revokeToken(t string) error {
	form := url.Values{"token": {t}}
	req, err := http.NewRequest("POST", s.RevokeUrl, strings.NewReader(form.Encode()))
	req.Header.Set("Accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

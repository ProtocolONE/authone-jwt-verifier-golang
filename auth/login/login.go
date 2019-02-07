package login

import (
	"context"
	"encoding/base64"
	"fmt"
	"github.com/labstack/echo"
	"golang.org/x/oauth2"
	"strings"
)

type LoginMiddleware struct {
	*oauth2.Config
}

func NewLoginMiddleware(cfg *oauth2.Config) *LoginMiddleware {
	return &LoginMiddleware{cfg}
}

func (s *LoginMiddleware) AuthResult(c echo.Context) (*oauth2.Token, error) {
	t, err := s.Exchange(context.Background(), c.QueryParam("code"))
	if err != nil {
		return nil, err
	}
	return t, nil
}

func (s *LoginMiddleware) BuildAuthUrl(state string) (string, error) {
	return fmt.Sprintf(
		"%s/?client_id=%s&redirect_uri=%s&response_type=code&scope=%s&state=%s",
		s.Endpoint.AuthURL,
		s.ClientID,
		s.RedirectURL,
		strings.Join(s.Scopes, " "),
		base64.StdEncoding.EncodeToString([]byte(state)),
	), nil
}

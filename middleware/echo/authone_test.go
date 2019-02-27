package middleware

import (
	"github.com/ProtocolONE/authone-jwt-verifier-golang"
	_ "github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo"
	_ "github.com/lestrrat-go/jwx/jwt"
	"github.com/stretchr/testify/assert"
	_ "github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthOneJwtWithConfig(t *testing.T) {
	e := echo.New()
	url := "http://localhost"

	conf := jwtverifier.Config{
		ClientID:     "CLIENT_ID",
		ClientSecret: "CLIENT_SECRET",
		RedirectURL:  "REDIRECT_URL",
		Scopes:       []string{"scope"},
		Issuer:       url,
	}
	handler := func(c echo.Context) error {
		return c.String(http.StatusOK, "test")
	}

	for _, tc := range []struct {
		expErrCode int // 0 for Success
		config     jwtverifier.Config
		hdrAuth    string
		info       string
	}{
		{
			expErrCode: http.StatusBadRequest,
			info:       ErrorAuthHeaderNotExists,
		},
		{
			hdrAuth:    "Bearer" + " token",
			expErrCode: http.StatusBadRequest,
			info:       ErrorAuthHeaderInvalid,
		},
		{
			hdrAuth:    "Bearer" + " eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVC",
			expErrCode: http.StatusUnauthorized,
			info:       ErrorAuthFailed,
		},
	} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		res := httptest.NewRecorder()
		req.Header.Set(echo.HeaderAuthorization, tc.hdrAuth)
		c := e.NewContext(req, res)

		if tc.expErrCode != 0 {
			jwtv := jwtverifier.NewJwtVerifier(conf)
			h := AuthOneJwtWithConfig(jwtv)(handler)
			he := h(c).(*echo.HTTPError)
			assert.Equal(t, tc.expErrCode, he.Code, tc.info)
			continue
		}

		jwtv := jwtverifier.NewJwtVerifier(tc.config)
		h := AuthOneJwtWithConfig(jwtv)(handler)
		if assert.NoError(t, h(c), tc.info) {
			user := c.Get("user").(*jwtverifier.UserInfo)
			assert.Equal(t, user.UserID, "1234567890")
		}
	}

}

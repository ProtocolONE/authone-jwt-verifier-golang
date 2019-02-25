package middleware

import (
	"github.com/ProtocolONE/authone-jwt-verifier-golang"
	"github.com/labstack/echo"
	"net/http"
	"regexp"
)

const (
	ErrorAuthHeaderNotExists = "Authorization header does not exists"
	ErrorAuthHeaderInvalid   = "Invalid authorization header"
	ErrorAuthFailed          = "Unable to authenticate user"
)

func AuthOneJwtWithConfig(cfg *jwtverifier.JwtVerifier) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) (err error) {
			req := c.Request()
			auth := req.Header.Get("Authorization")
			if auth == "" {
				return &echo.HTTPError{
					Code:    http.StatusBadRequest,
					Message: ErrorAuthHeaderNotExists,
				}
			}

			r := regexp.MustCompile("Bearer ([A-z0-9_.-]{10,})")
			match := r.FindStringSubmatch(auth)
			if len(match) < 1 {
				return &echo.HTTPError{
					Code:    http.StatusBadRequest,
					Message: ErrorAuthHeaderInvalid,
				}
			}

			token, err := cfg.Introspect(c.Request().Context(), match[1])
			if err != nil {
				return &echo.HTTPError{
					Code:    http.StatusUnauthorized,
					Message: ErrorAuthFailed,
				}
			}

			c.Set("user", &jwtverifier.UserInfo{UserID: token.Sub})
			return next(c)
		}
	}
}

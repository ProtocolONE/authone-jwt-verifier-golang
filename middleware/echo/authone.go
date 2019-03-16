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
			userInfo, err := introspectToken(c, cfg)
			if err != nil {
				return err
			}

			c.Set("user", userInfo)
			return next(c)
		}
	}
}

func AuthOneJwtCallableWithConfig(cfg *jwtverifier.JwtVerifier, f func(*jwtverifier.UserInfo)) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) (err error) {
			userInfo, err := introspectToken(c, cfg)
			if err != nil {
				return err
			}

			f(userInfo)
			return next(c)
		}
	}
}

func introspectToken(c echo.Context, cfg *jwtverifier.JwtVerifier) (*jwtverifier.UserInfo, error) {
	req := c.Request()
	auth := req.Header.Get("Authorization")
	if auth == "" {
		return nil, &echo.HTTPError{
			Code:    http.StatusBadRequest,
			Message: ErrorAuthHeaderNotExists,
		}
	}

	r := regexp.MustCompile("Bearer ([A-z0-9_.-]{10,})")
	match := r.FindStringSubmatch(auth)
	if len(match) < 1 {
		return nil, &echo.HTTPError{
			Code:    http.StatusBadRequest,
			Message: ErrorAuthHeaderInvalid,
		}
	}

	token, err := cfg.Introspect(c.Request().Context(), match[1])
	if err != nil {
		return nil, &echo.HTTPError{
			Code:    http.StatusUnauthorized,
			Message: ErrorAuthFailed,
		}
	}

	return &jwtverifier.UserInfo{UserID: token.Sub}, nil
}

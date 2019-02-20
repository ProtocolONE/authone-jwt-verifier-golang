package middleware

import (
	"github.com/ProtocolONE/go-echo-middleware"
	"github.com/labstack/echo"
	"net/http"
	"regexp"
)

func AuthOneJwtWithConfig(cfg *jwtverifier.JwtVerifier) echo.MiddlewareFunc {
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

			token, err := cfg.Introspect(c.Request().Context(), match[1])
			if err != nil {
				return c.NoContent(http.StatusForbidden)
			}
			c.Set("UserId", token.Sub)

			return next(c)
		}
	}
}

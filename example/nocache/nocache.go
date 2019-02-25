package nocache

// Ported from Goji's nocache, source:
// https://github.com/zenazn/goji/tree/master/web/middleware
import (
	"time"

	"github.com/labstack/echo"
	emw "github.com/labstack/echo/middleware"
)

type (
	NoCacheConfig struct {
		Skipper emw.Skipper
	}
)

var (
	epoch          = time.Unix(0, 0).Format(time.RFC1123)
	noCacheHeaders = map[string]string{
		"Expires":         epoch,
		"Cache-Control":   "no-cache, private, max-age=0",
		"Pragma":          "no-cache",
		"X-Accel-Expires": "0",
	}
	etagHeaders = []string{
		"ETag",
		"If-Modified-Since",
		"If-Match",
		"If-None-Match",
		"If-Range",
		"If-Unmodified-Since",
	}
	DefaultNoCacheConfig = NoCacheConfig{
		Skipper: emw.DefaultSkipper,
	}
)

func NoCache() echo.MiddlewareFunc {
	return NoCacheWithConfig(DefaultNoCacheConfig)
}

func NoCacheWithConfig(config NoCacheConfig) echo.MiddlewareFunc {
	if config.Skipper == nil {
		config.Skipper = DefaultNoCacheConfig.Skipper
	}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) (err error) {
			if config.Skipper(c) {
				return next(c)
			}
			req := c.Request()
			// Delete any ETag headers that may have been set
			for _, v := range etagHeaders {
				if req.Header.Get(v) != "" {
					req.Header.Del(v)
				}
			}

			// Set our NoCache headers
			res := c.Response()
			for k, v := range noCacheHeaders {
				res.Header().Set(k, v)
			}

			return next(c)
		}
	}
}

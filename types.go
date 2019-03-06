package jwtverifier

import (
	"fmt"
	"golang.org/x/oauth2"
	"net/http"
)

// IntrospectToken repeats the structure of the Introspect Token object described in the Hydra documentation.
//
// See more at:
// - https://www.ory.sh/docs/hydra/sdk/api#schemaoauth2tokenintrospection
// - https://www.iana.org/assignments/jwt/jwt.xhtml
type IntrospectToken struct {
	// Active is a boolean indicator of whether or not the presented token is currently active.
	// The specifics of a token's \"active\" state will vary depending on the implementation of the authorization server
	// and the information it keeps about its tokens, but a \"true\" value return for the \"active\" property will
	// generally indicate that a given token has been issued by this authorization server, has not been revoked by the
	// resource owner, and is within its given time window of validity (e.g., after its issuance time and before its
	// expiration time).
	Active bool `json:"active"`

	// Audience contains a list of the token's intended audiences.
	Aud []string `json:"aud,omitempty"`

	// ClientID is aclient identifier for the OAuth 2.0 client that requested this token.
	ClientID string `json:"client_id"`

	// Expires at is an integer timestamp, measured in the number of seconds since January 1 1970 UTC,
	// indicating when this token will expire.
	Exp int64 `json:"exp,omitempty"`

	// Extra is arbitrary data set by the session.
	Ext map[string]interface{} `json:"ext,omitempty"`

	// Issued at is an integer timestamp, measured in the number of seconds since January 1 1970 UTC, indicating when
	// this token was originally issued.
	Iat int `json:"iat,omitempty"`

	// IssuerURL is a string representing the issuer of this token
	Iss string `json:"iss,omitempty"`

	// NotBefore is an integer timestamp, measured in the number of seconds since January 1 1970 UTC, indicating when
	// this token is not to be used before.
	Nbf int `json:"nbf,omitempty"`

	// Scope is a JSON string containing a space-separated list of scopes associated with this token.
	Scope string `json:"scope"`

	// Subject of the token, as defined in JWT [RFC7519]. Usually a machine-readable identifier of the resource owner
	// who authorized this token.
	Sub string `json:"sub"`

	// TokenType is the introspected token's type, for example `access_token` or `refresh_token`.
	TokenType string `json:"token_type"`

	// Username is a human-readable identifier for the resource owner who authorized this token.
	Username string `json:"username,omitempty"`
}

// IdToken based at JWT claims.
//
// See more at:
// - https://www.iana.org/assignments/jwt/jwt.xhtml
type IdToken struct {
	AtHash   string   `json:"at_hash"`
	Aud      []string `json:"aud"`
	AuthTime int      `json:"auth_time"`
	Exp      int64    `json:"exp"`
	Iat      int      `json:"iat"`
	Iss      string   `json:"iss"`
	Jti      string   `json:"jti"`
	Nonce    string   `json:"nonce"`
	Rat      int      `json:"rat"`
	Sub      string   `json:"sub"`
}

// UserInfo based at JWT claims.
//
// See more at:
// - https://www.iana.org/assignments/jwt/jwt.xhtml
type UserInfo struct {
	UserID string `json:"sub"`
}

// Token defined structure of oauth2.Token
type Token struct {
	*oauth2.Token
}

// RetrieveError defined the structure of the error response to the oauth server
type RetrieveError struct {
	Response *http.Response
	Body     []byte
}

func (r *RetrieveError) Error() string {
	return fmt.Sprintf("oauth2: cannot fetch token: %v\nResponse: %s", r.Response.Status, r.Body)
}

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
	Active    bool     `json:"active"`
	Aud       []string `json:"aud"`
	ClientID  string   `json:"client_id"`
	Exp       int64    `json:"exp"`
	Iat       int      `json:"iat"`
	Iss       string   `json:"iss"`
	Nbf       int      `json:"nbf"`
	Scope     string   `json:"scope"`
	Sub       string   `json:"sub"`
	TokenType string   `json:"token_type"`
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

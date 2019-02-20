package jwtverifier

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ProtocolONE/go-echo-middleware/internal"
	"github.com/ProtocolONE/go-echo-middleware/storage"
	"github.com/ProtocolONE/go-echo-middleware/storage/memory"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"golang.org/x/net/context/ctxhttp"
	"golang.org/x/oauth2"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

type JwtVerifier struct {
	config  *Config
	oauth2  *oauth2.Config
	storage storage.Adapter
}

// Config describes a typical 3-legged OpenId Connect flow, with both the
// client application information and the server's endpoint URLs.
type Config struct {
	// ClientID is the application's ID.
	ClientID string

	// ClientSecret is the application's secret.
	ClientSecret string

	// RedirectURL is the URL to redirect users going through
	// the OAuth flow, after the resource owner's URLs.
	RedirectURL string

	// Scope specifies optional requested permissions.
	Scopes []string

	// Endpoint contains the resource server's token endpoint
	// URLs. These are constants specific to each server and are
	// often available via tenant-specific setting for each
	// AuthOne application.
	Endpoint Endpoint
}

// Endpoint contains the OpenID Connect 1.0 provider's authorization and token
// endpoint URLs.
type Endpoint struct {
	// The authorization code flow begins with the client directing the user to the /authorize endpoint.
	// In this request, the client indicates the permissions it needs to acquire from the user.
	// You can get the OAuth 2.0 authorization endpoint for your tenant by selecting App > Endpoints.
	//
	// Use the CreateAuthUrl method to generate a finished link containing predefined settings based on your configuration.
	AuthURL string

	// At this endpoint, clients receive identification data and access tokens in exchange for code
	// derived from authentication.
	TokenURL string

	// The token introspection endpoint is generally intended for identifier-based access tokens, which represent
	// a secure key to an authorisation stored with the Connect2id server.
	IntrospectURL string

	// The UserInfo endpoint is an OAuth 2.0 protected resource of the Connect2id server where client applications
	// can retrieve consented claims, or assertions, about the logged in end-user.
	UserInfoURL string

	// The Connect2id server publishes its public RSA keys as a JSON Web Key (JWK) set.
	// This is done for the to enable clients and other parties to verify the authenticity of identity tokens
	// issued by the server.
	JwksUrl string

	// RevokeUrl is the URL to revoke access tokens or refresh tokens
	// to notify the OpenID Connect Provider that an issued token is
	// no longer needed and must be revoked. The revocation endpoint
	// can revoke a token that was obtained through OpenID Connect or
	// OAuth authentication.
	RevokeUrl string
}

func NewJwtVerifier(config Config, options ...interface{}) *JwtVerifier {
	conf := &oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		Scopes:       config.Scopes,
		RedirectURL:  config.RedirectURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  config.Endpoint.AuthURL,
			TokenURL: config.Endpoint.TokenURL,
		},
	}

	for i := range options {
		if st, ok := options[i].(*storage.Adapter); ok {
			return &JwtVerifier{
				config:  &config,
				oauth2:  conf,
				storage: st,
			}
		}
	}

	return &JwtVerifier{
		config: &config,
		oauth2: conf,
	}
}

// Set storage adapter for the introspection token.
// See available adapters in the storage folder.
func (j *JwtVerifier) SetStorage(a storage.Adapter) {
	j.storage = a
}

// Create a URL to send the user to the initial authentication step.
func (j *JwtVerifier) CreateAuthUrl(respType string, state string) string {
	return fmt.Sprintf(
		"%s/?client_id=%s&redirect_uri=%s&response_type=%s&scope=%s&state=%s",
		j.config.Endpoint.AuthURL,
		j.config.ClientID,
		j.config.RedirectURL,
		respType,
		strings.Join(j.config.Scopes, " "),
		base64.StdEncoding.EncodeToString([]byte(state)),
	)
}

// Exchange converts an authorization code into a token.
//
// It is used after a resource provider redirects the user back
// to the Redirect URI (the URL obtained from AuthCodeURL).
//
// The provided context optionally controls which HTTP client is used. See the HTTPClient variable.
//
// The code will be in the *http.Request.FormValue("code"). Before
// calling Exchange, be sure to validate FormValue("state").
//
// Opts may include the PKCE verifier code if previously used in AuthCodeURL.
// See https://www.oauth.com/oauth2-servers/pkce/ for more info.
func (j *JwtVerifier) Exchange(ctx context.Context, code string) (*Token, error) {
	t, err := j.oauth2.Exchange(ctx, code)
	if err != nil {
		return nil, err
	}
	return &Token{t}, nil
}

// Check a token refresh or access is active or not. An active token is neither expired nor revoked.
// Uses token storage for temporary storage of tokens. If the token has expired or it has been revoked,
// the information will be deleted from the temporary storage.
func (j *JwtVerifier) Introspect(ctx context.Context, token string) (*IntrospectToken, error) {
	if introspect, _ := j.getIntrospectFromStorage(token); introspect != nil {
		return introspect, nil
	}

	introspect, err := j.getIntrospect(ctx, j.config.Endpoint.IntrospectURL, token)
	if err != nil {
		return nil, err
	}
	if false == introspect.Active {
		return nil, errors.New("token isn't active")
	}
	if j.config.ClientID != introspect.ClientID {
		return nil, errors.New("token is owned by another client")
	}
	if err := j.saveIntrospectToStorage(token, introspect); err != nil {
		return nil, err
	}
	return introspect, nil
}

// Get user information via UserInfo endpoint with uses AccessToken by authenticate header.
// The claims are packaged in a JSON object where the sub member denotes the subject (end-user) identifier.
func (j *JwtVerifier) GetUserInfo(ctx context.Context, token string) (*UserInfo, error) {
	info, err := j.getUserInfo(ctx, token, j.config.Endpoint.UserInfoURL)
	if err != nil {
		return nil, err
	}
	return info, nil
}

// Used to check the ID Token and returns its claims (as custom json object) in the event of its validity.
func (j *JwtVerifier) ValidateIdToken(ctx context.Context, token string) (*IdToken, error) {
	// UNDONE: We must use application context
	//token, err := j.
	set, err := jwk.Fetch(j.config.Endpoint.JwksUrl)
	if err != nil {
		return nil, err
	}

	keys := set.Keys[0]
	verified, err := jws.VerifyWithJWK([]byte(token), keys)
	if err != nil {
		return nil, err
	}
	t := &IdToken{}
	err = json.Unmarshal(verified, t)
	if err != nil {
		return nil, err
	}
	if t.Aud[0] != j.config.ClientID {
		return nil, errors.New("token is owned by another client")
	}
	return t, nil
}

// Use this method for invalidate the specified token and, if applicable, other tokens based on the same
// authorisation grant.
func (j *JwtVerifier) Revoke(ctx context.Context, token string) error {
	err := j.revokeToken(ctx, token, j.config.Endpoint.RevokeUrl)
	if err != nil {
		return err
	}
	return nil
}

func (j *JwtVerifier) getIntrospect(ctx context.Context, introspectURL string, token string) (*IntrospectToken, error) {
	form := url.Values{"token": {token}}
	req, err := http.NewRequest("POST", introspectURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	r, err := ctxhttp.Do(ctx, internal.ContextClient(ctx), req)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	body, err := ioutil.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("oauth2: cannot fetch token: %v", err)
	}
	if code := r.StatusCode; code < 200 || code > 299 {
		return nil, &RetrieveError{
			Response: r,
			Body:     body,
		}
	}

	var t *IntrospectToken
	if err = json.Unmarshal(body, t); err != nil {
		return nil, err
	}

	return t, nil
}

func (j *JwtVerifier) getUserInfo(ctx context.Context, t string, userInfoURL string) (*UserInfo, error) {
	req, err := http.NewRequest("GET", userInfoURL, strings.NewReader(""))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("bearer %s", t))

	r, err := ctxhttp.Do(ctx, internal.ContextClient(ctx), req)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	body, err := ioutil.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("oauth2: cannot fetch token: %v", err)
	}
	if code := r.StatusCode; code < 200 || code > 299 {
		return nil, &RetrieveError{
			Response: r,
			Body:     body,
		}
	}

	i := &UserInfo{}
	err = json.Unmarshal(body, i)
	if err != nil {
		return nil, err
	}
	return i, nil
}

func (j *JwtVerifier) revokeToken(ctx context.Context, token string, revokeUrl string) error {
	s, err := j.getTokenStorage()
	if err != nil {
		return err
	}
	if err := s.Delete(token); err != nil {
		return err
	}

	form := url.Values{"token": {token}}
	req, err := http.NewRequest("POST", revokeUrl, strings.NewReader(form.Encode()))
	req.Header.Set("Accept", "application/json")

	r, err := ctxhttp.Do(ctx, internal.ContextClient(ctx), req)
	if err != nil {
		return err
	}
	defer r.Body.Close()

	body, err := ioutil.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("oauth2: cannot fetch token: %v", err)
	}
	if code := r.StatusCode; code < 200 || code > 299 {
		return &RetrieveError{
			Response: r,
			Body:     body,
		}
	}

	return nil
}

func (j *JwtVerifier) getTokenStorage() (storage.Adapter, error) {
	if j.storage != nil {
		return j.storage, nil
	}

	var (
		maxSize      int64  = 5000
		itemsToPrune uint32 = 500
	)
	j.storage = memory.NewStogare(maxSize, itemsToPrune)
	if j.storage == nil {
		return nil, errors.New("token storage cannot be empty")
	}
	return j.storage, nil
}

func (j *JwtVerifier) getIntrospectFromStorage(token string) (*IntrospectToken, error) {
	s, err := j.getTokenStorage()
	if err != nil {
		return nil, err
	}
	t, err := s.Get(token)
	if err != nil {
		return nil, err
	}
	return t, nil
}

func (j *JwtVerifier) saveIntrospectToStorage(token string, source *IntrospectToken) error {
	s, err := j.getTokenStorage()
	if err != nil {
		return err
	}
	if err := s.Set(token, source); err != nil {
		return err
	}
	return nil
}

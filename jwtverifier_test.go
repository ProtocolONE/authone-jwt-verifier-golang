package jwtverifier

import (
	"context"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

type FakeStorageAdapter struct{}

func (a *FakeStorageAdapter) Set(token string, exp int64, introspect []byte) error {
	return nil
}
func (a *FakeStorageAdapter) Get(t string) ([]byte, error) {
	return nil, nil
}
func (a *FakeStorageAdapter) Delete(token string) error {
	return nil
}

func TestSetAdapter(t *testing.T) {
	jwt := createJwtVerifier("http://localhost")
	jwt.SetStorage(&FakeStorageAdapter{})
	if reflect.TypeOf(jwt.storage).String() != "*jwtverifier.FakeStorageAdapter" {
		t.Error("Unable to set storage adapter")
	}
}

func TestCreateAuthUrl(t *testing.T) {
	jwt := createJwtVerifier("http://localhost")
	url := jwt.CreateAuthUrl("mystate")
	expected := "http://localhost/oauth2/auth?client_id=CLIENT_ID&redirect_uri=REDIRECT_URL&response_type=code&scope=scope&state=mystate"
	if expected != url {
		t.Errorf("Invalid auth URL [%s], expected [%s]", url, expected)
	}
}

func TestCreateAuthUrl_WithOptions(t *testing.T) {
	opt := AuthUrlOption{Key: "optionkey", Value: "optionvalue"}
	jwt := createJwtVerifier("http://localhost")
	url := jwt.CreateAuthUrl("mystate", opt)
	expected := "http://localhost/oauth2/auth?client_id=CLIENT_ID&optionkey=optionvalue&redirect_uri=REDIRECT_URL&response_type=code&scope=scope&state=mystate"
	if expected != url {
		t.Errorf("Invalid auth URL [%s], expected [%s]", url, expected)
	}
}

func TestCreateAuthUrl_WithManyOptions(t *testing.T) {
	opt1 := AuthUrlOption{Key: "optionkey1", Value: "optionvalue1"}
	opt2 := AuthUrlOption{Key: "optionkey2", Value: "optionvalue2"}
	jwt := createJwtVerifier("http://localhost")
	url := jwt.CreateAuthUrl("mystate", opt1, opt2)
	expected := "http://localhost/oauth2/auth?client_id=CLIENT_ID&optionkey1=optionvalue1&optionkey2=optionvalue2&redirect_uri=REDIRECT_URL&response_type=code&scope=scope&state=mystate"
	if expected != url {
		t.Errorf("Invalid auth URL [%s], expected [%s]", url, expected)
	}
}

func TestExchangeRequest(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.String() != "/oauth2/token" {
			t.Errorf("Unexpected exchange request URL %q", r.URL)
		}
		headerAuth := r.Header.Get("Authorization")
		if want := "Basic Q0xJRU5UX0lEOkNMSUVOVF9TRUNSRVQ="; headerAuth != want {
			t.Errorf("Unexpected authorization header %q, want %q", headerAuth, want)
		}
		headerContentType := r.Header.Get("Content-Type")
		if headerContentType != "application/x-www-form-urlencoded" {
			t.Errorf("Unexpected Content-Type header %q", headerContentType)
		}
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			t.Errorf("Failed reading request body: %s.", err)
		}
		if string(body) != "code=exchange-code&grant_type=authorization_code&redirect_uri=REDIRECT_URL" {
			t.Errorf("Unexpected exchange payload; got %q", body)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token": "90d64460d14870c08c81352a05dedd3465940a7c", "scope": "user", "token_type": "bearer", "expires_in": 86400}`))
	}))
	defer ts.Close()

	jwt := createJwtVerifier(ts.URL)
	tok, err := jwt.Exchange(context.Background(), "exchange-code")
	if err != nil {
		t.Error(err)
	}
	if !tok.Valid() {
		t.Fatalf("Token invalid. Got: %#v", tok)
	}
	if tok.AccessToken != "90d64460d14870c08c81352a05dedd3465940a7c" {
		t.Errorf("Unexpected access token, %#v.", tok.AccessToken)
	}
	if tok.TokenType != "bearer" {
		t.Errorf("Unexpected token type, %#v.", tok.TokenType)
	}
	scope := tok.Extra("scope")
	if scope != "user" {
		t.Errorf("Unexpected value for scope: %v", scope)
	}
	expiresIn := tok.Extra("expires_in")
	if expiresIn != float64(86400) {
		t.Errorf("Unexpected non-numeric value for expires_in: %v", expiresIn)
	}
}

func TestExchangeRequest_BadResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"scope": "user", "token_type": "bearer"}`))
	}))
	defer ts.Close()

	jwt := createJwtVerifier(ts.URL)
	_, err := jwt.Exchange(context.Background(), "code")
	if err == nil {
		t.Error("expected error from missing access_token")
	}
}

func TestExchangeRequest_BadResponseType(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":123,  "scope": "user", "token_type": "bearer"}`))
	}))
	defer ts.Close()

	jwt := createJwtVerifier(ts.URL)
	_, err := jwt.Exchange(context.Background(), "exchange-code")
	if err == nil {
		t.Error("expected error from non-string access_token")
	}
}

func TestRevoke(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	}))
	defer ts.Close()

	jwt := createJwtVerifier(ts.URL)
	err := jwt.Revoke(context.Background(), "token")
	if err != nil {
		t.Errorf("unable to revoke token: %s", err.Error())
	}
}

func TestRevoke_Failed(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer ts.Close()

	jwt := createJwtVerifier(ts.URL)
	err := jwt.Revoke(context.Background(), "token")
	if err == nil {
		t.Error("revocation of the token should have caused an error")
	}
}

func TestGetUserInfo(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"sub":"user_id"}`))
	}))
	defer ts.Close()

	jwt := createJwtVerifier(ts.URL)
	if _, err := jwt.GetUserInfo(context.Background(), "90d64460d14870c08c81352a05dedd3465940a7c"); err != nil {
		t.Error("unable to get user info")
	}
}

func TestGetUserInfo_InvalidBearerToken(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer ts.Close()

	jwt := createJwtVerifier(ts.URL)
	if _, err := jwt.GetUserInfo(context.Background(), "token"); err == nil {
		t.Error("there must be a token verification error")
	}
}

func TestGetUserInfo_ErrorFetchResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Header.Get("Authorization"), "Bearer 90d64460d14870c08c81352a05dedd3465940a7c"; got == want {
			t.Errorf("Authorization header = %q; want %q", got, want)
		}
	}))
	defer ts.Close()

	jwt := createJwtVerifier(ts.URL)
	if _, err := jwt.GetUserInfo(context.Background(), "token"); err == nil {
		t.Error("getting user information should cause an error")
	}
}

func TestIntrospect(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"active":true,"client_id":"CLIENT_ID"}`))
	}))
	defer ts.Close()

	jwt := createJwtVerifier(ts.URL)
	if _, err := jwt.Introspect(context.Background(), "90d64460d14870c08c81352a05dedd3465940a7c"); err != nil {
		t.Error("unable to introspect token")
	}
}

func TestIntrospect_ErrorFetchResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer ts.Close()

	jwt := createJwtVerifier(ts.URL)
	if _, err := jwt.Introspect(context.Background(), "token1"); err == nil {
		t.Error("there must be a token verification error")
	}
}

func TestIntrospect_InactiveToken(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"active":false,"client_id":"CLIENT_ID"}`))
	}))
	defer ts.Close()

	jwt := createJwtVerifier(ts.URL)
	_, err := jwt.Introspect(context.Background(), "token1")
	if err == nil || err.Error() != "token isn't active" {
		t.Error("token must be a inactive")
	}
}

func TestIntrospect_AnotherClient(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"active":true,"client_id":"CLIENT_ID2"}`))
	}))
	defer ts.Close()

	jwt := createJwtVerifier(ts.URL)
	_, err := jwt.Introspect(context.Background(), "token1")
	if err == nil || err.Error() != "token is owned by another client" {
		t.Error("token must be a owner another client")
	}
}

func TestCreateLogoutUrl(t *testing.T) {
	jwt := createJwtVerifier("http://localhost")
	url := jwt.CreateLogoutUrl("http://mysite.com/")
	expected := "http://localhost/oauth2/logout?redirect_uri=http://mysite.com/"
	if expected != url {
		t.Errorf("Invalid logout URL [%s], expected [%s]", url, expected)
	}
}

func createJwtVerifier(url string) *JwtVerifier {
	return NewJwtVerifier(Config{
		ClientID:     "CLIENT_ID",
		ClientSecret: "CLIENT_SECRET",
		RedirectURL:  "REDIRECT_URL",
		Scopes:       []string{"scope"},
		Issuer:       url,
	})
}

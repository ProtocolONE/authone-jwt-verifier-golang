package main

import (
	"context"
	"fmt"
	"github.com/ProtocolONE/authone-jwt-verifier-golang"
	"github.com/ProtocolONE/authone-jwt-verifier-golang/example/nocache"
	jwt_middleware "github.com/ProtocolONE/authone-jwt-verifier-golang/middleware/echo"
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
	"github.com/labstack/gommon/log"
	"html/template"
	"io"
	"net/http"
	"net/url"
)

var (
	clientID     = "5c7fd8c50dd75d000162c69f"
	clientSecret = "TVzu97mMqsn4bRQbgS07MdIuf3TMgZHEm0fjKWWP5DvzppyTtXA8sgQtqazr91zq"
	scopes       = []string{"openid", "offline"}
	redirectURL  = "http://127.0.0.1:1323/auth/callback"
	authDomain   = "https://dev-auth1.tst.protocol.one"
	jwtv         *jwtverifier.JwtVerifier
)

type Template struct {
	templates *template.Template
}

func (t *Template) Render(w io.Writer, name string, data interface{}, ctx echo.Context) error {
	return t.templates.ExecuteTemplate(w, name, data)
}

func main() {
	t := &Template{
		templates: template.Must(template.ParseGlob("templates/*.html")),
	}
	e := echo.New()
	e.Renderer = t
	e.Logger.SetLevel(log.ERROR)
	e.Use(middleware.Logger())
	e.Use(nocache.NoCache())

	settings := jwtverifier.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes:       scopes,
		RedirectURL:  redirectURL,
		Issuer:       authDomain,
	}
	jwtv = jwtverifier.NewJwtVerifier(settings)

	// Routes
	e.GET("/", index)
	// Create state and redirect to auth endpoint
	e.GET("/authme", authMeProcess)
	// Validate auth code result
	e.GET("/auth/callback", authCallback)
	// Validate auth header
	e.GET("/private", privateZone, jwt_middleware.AuthOneJwtWithConfig(jwtv))
	// Routes
	e.GET("/some-route", someRoute)

	// Start server
	e.Logger.Fatal(e.Start(":1323"))
}

func index(c echo.Context) error {
	u, _ := url.Parse(c.Scheme() + "://" + c.Request().Host)
	return c.Render(http.StatusOK, "index.html", map[string]interface{}{
		"AuthDomain":  fmt.Sprintf("%s://%s:8080", u.Scheme, u.Hostname()),
		"clientID":    clientID,
		"redirectUri": redirectURL,
	})
}

func someRoute(c echo.Context) error {
	return c.HTML(http.StatusOK, "Some route")
}

func privateZone(c echo.Context) error {
	user := c.Get("user")
	fmt.Printf("User: %+v\n", user.(*jwtverifier.UserInfo))
	return c.HTML(http.StatusOK, "")
}

func authMeProcess(c echo.Context) error {
	options := jwtverifier.AuthUrlOption{
		Key:   "test1",
		Value: "value1",
	}
	u := jwtv.CreateAuthUrl("example_state_string", options)
	fmt.Printf("%s\n", u)
	return c.Redirect(http.StatusPermanentRedirect, u)
}

func authCallback(c echo.Context) error {
	payload := map[string]interface{}{"ClientID": clientID}
	ctx := c.Request().Context()
	t, err := jwtv.Exchange(ctx, fmt.Sprint(c.QueryParam("code")))
	if err != nil {
		c.Echo().Logger.Error("Unable to get auth token")
		payload["error"] = fmt.Sprintf("Authorization error: %s\n", err.Error())
	}
	fmt.Printf("AccessToken string: %s\n", t.AccessToken)
	fmt.Printf("RefreshToken string: %s\n", t.RefreshToken)

	introspectAccessToken, introspectRefreshToken, err := introspect(ctx, t)
	if err != nil {
		c.Echo().Logger.Error("Unable to get introspect access token")
		fmt.Print(err)
		payload["error"] = fmt.Sprintf("Unable to introspect token: %s\n", err.Error())
	} else {
		payload["introspectAccessToken"] = introspectAccessToken
		payload["introspectRefreshToken"] = introspectRefreshToken
	}

	userInfo, err := userinfo(ctx, t)
	if err != nil {
		c.Echo().Logger.Error("Unable to get user info")
		fmt.Print(err)
		payload["error"] = fmt.Sprintf("Unable to get user info: %s\n", err.Error())
	} else {
		payload["userInfo"] = userInfo
	}

	idToken, err := validateIdToken(ctx, t)
	if err != nil {
		c.Echo().Logger.Error("Unable to get validate id token")
		fmt.Print(err)
		payload["error"] = fmt.Sprintf("Unable to validate id token: %s\n", err.Error())
	} else {
		payload["idToken"] = idToken
	}

	var result = "success"
	if payload["error"] != "" {
		result = "error"
	}

	return c.Render(http.StatusOK, "callback.html", map[string]interface{}{
		"Result":  result,
		"Payload": payload,
	})
}

func introspect(c context.Context, token *jwtverifier.Token) (*jwtverifier.IntrospectToken, *jwtverifier.IntrospectToken, error) {
	at, err := jwtv.Introspect(c, token.AccessToken)
	if err != nil {
		return nil, nil, err
	}
	fmt.Printf("AccessToken string: %+v\n", token.AccessToken)
	fmt.Printf("AccessToken JWT: %+v\n", at)
	fmt.Printf("AccessToken expiry: %+v\n", at.Exp)

	rt, err := jwtv.Introspect(c, token.RefreshToken)
	if err != nil {
		return nil, nil, err
	}
	fmt.Printf("RefreshToken string: %+v\n", token.RefreshToken)
	fmt.Printf("RefreshToken JWT: %+v\n", rt)
	fmt.Printf("RefreshToken expiry: %+v\n", rt.Exp)

	return at, rt, nil
}

func userinfo(c context.Context, token *jwtverifier.Token) (*jwtverifier.UserInfo, error) {
	info, err := jwtv.GetUserInfo(c, token.AccessToken)
	if err != nil {
		return nil, err
	}
	fmt.Printf("User info: %+v\n", info)
	return info, nil
}

func validateIdToken(c context.Context, token *jwtverifier.Token) (*jwtverifier.IdToken, error) {
	id := token.Extra("id_token")
	if id == nil {
		fmt.Print("ID token is not required\n")
		return nil, nil
	}
	t, err := jwtv.ValidateIdToken(c, fmt.Sprint(id))
	if err != nil {
		return nil, err
	}
	fmt.Printf("ID token: %+v\n", t)
	return t, nil
}

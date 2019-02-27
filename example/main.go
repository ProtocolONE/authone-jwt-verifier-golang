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
	"net/http"
)

var (
	clientID     = "5c6a75094c1efd524019c5b4"
	clientSecret = "GBP29UmWmYdzkYHXMaFWetJAZovy2lM0vOw6iz8BlrHarSoYNKi7Yjgf3yZC7Jsp"
	scopes       = []string{"openid", "offline"}
	responseType = "code"
	redirectURL  = "http://127.0.0.1:1323/auth/callback"
	authDomain   = "http://localhost:8080"
	jwtv         *jwtverifier.JwtVerifier
)

func main() {
	e := echo.New()
	e.Logger.SetLevel(log.ERROR)
	e.Use(middleware.Logger())
	e.Use(nocache.NoCache())

	settings := jwtverifier.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes:       scopes,
		RedirectURL:  redirectURL,
		AuthDomain:   authDomain,
	}
	jwtv := jwtverifier.NewJwtVerifier(settings)

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
	return c.HTML(http.StatusOK, "<a href=\"/authme\">Auth me</a>")
}

func someRoute(c echo.Context) error {
	return c.HTML(http.StatusOK, "Some route")
}

func privateZone(c echo.Context) error {
	userID := c.Get("user_id")
	userScope := c.Get("user_scope")
	fmt.Printf("User ID: %+v\n", userID)
	fmt.Printf("User scope: %+v\n", userScope)
	return c.HTML(http.StatusOK, "")
}

func authMeProcess(c echo.Context) error {
	options := jwtverifier.AuthUrlOption{
		Key:   "state",
		Value: "example_state_string",
	}
	url := jwtv.CreateAuthUrl(responseType, options)
	fmt.Printf("%s\n", url)
	return c.Redirect(http.StatusPermanentRedirect, url)
}

func authCallback(c echo.Context) error {
	ctx := c.Request().Context()
	t, err := jwtv.Exchange(ctx, fmt.Sprint(c.Get("code")))
	if err != nil {
		c.Echo().Logger.Error("Unable to get auth token")
		return c.HTML(http.StatusBadRequest, "Authorization error")
	}
	fmt.Printf("AccessToken: %+v\n", t.AccessToken)

	if err := introspect(ctx, t); err != nil {
		c.Echo().Logger.Error("Unable to get introspect access token")
		fmt.Print(err)
		return nil
	}

	if err := userinfo(ctx, t); err != nil {
		c.Echo().Logger.Error("Unable to get user info")
		fmt.Print(err)
		return nil
	}

	if err := validateIdToken(ctx, t); err != nil {
		c.Echo().Logger.Error("Unable to get validate id token")
		fmt.Print(err)
		return nil
	}

	return nil
}

func introspect(c context.Context, token *jwtverifier.Token) error {
	t, err := jwtv.Introspect(c, token.AccessToken)
	if err != nil {
		return err
	}
	fmt.Printf("JWT token: %+v\n", t)
	fmt.Printf("Expiry: %+v\n", token.Expiry)
	return nil
}

func userinfo(c context.Context, token *jwtverifier.Token) error {
	info, err := jwtv.GetUserInfo(c, token.AccessToken)
	if err != nil {
		return err
	}
	fmt.Printf("User info: %+v\n", info)
	return nil
}

func validateIdToken(c context.Context, token *jwtverifier.Token) error {
	id := token.Extra("id_token")
	if id == nil {
		fmt.Print("ID token is not required\n")
		return nil
	}
	t, err := jwtv.ValidateIdToken(c, fmt.Sprint(id))
	if err != nil {
		return err
	}
	fmt.Printf("ID token: %+v\n", t)
	return nil
}

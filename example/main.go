package main

import (
	"context"
	"fmt"
	"github.com/ProtocolONE/authone-jwt-verifier-golang"
	"github.com/ProtocolONE/authone-jwt-verifier-golang/example/nocache"
	jwt_middleware "github.com/ProtocolONE/authone-jwt-verifier-golang/middleware/echo"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/labstack/gommon/log"
	"html/template"
	"io"
	"net/http"
	"time"
)

var (
	clientID          = "5cb26c6592e0d90001683757"
	clientSecret      = "eUvn3orwIhXp7jY1QLOuFO1Z1ZqSkJWJx3yLoXbwP2pJeWbcnlM3uHR5XjRz4DUF"
	scopes            = []string{"openid", "offline"}
	responseType      = "code"
	redirectUri       = "http://127.0.0.1:1323/auth/callback"
	logoutRedirectUri = "http://127.0.0.1:1323/logout_result"
	authDomain        = "https://dev-auth1.tst.protocol.one"
	jwtv              *jwtverifier.JwtVerifier
)

type payload struct {
	ClientID               string                      `json:"client_id"`
	Result                 bool                        `json:"result"`
	Error                  string                      `json:"error"`
	AccessToken            string                      `json:"access_token"`
	RefreshToken           string                      `json:"refresh_token"`
	Expire                 time.Time                   `json:"expire"`
	IntrospectAccessToken  jwtverifier.IntrospectToken `json:"introspect_access_token"`
	IntrospectRefreshToken jwtverifier.IntrospectToken `json:"introspect_refresh_token"`
	UserInfo               jwtverifier.UserInfo        `json:"user_info"`
	IdToken                jwtverifier.IdToken         `json:"id_token"`
}

type Object struct {
	Identifier string
}

type Template struct {
	templates *template.Template
}

var (
	authCookieName = "auth1_access_token"
	obj            = &Object{}
)

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
		RedirectURL:  redirectUri,
		Issuer:       authDomain,
	}
	jwtv = jwtverifier.NewJwtVerifier(settings)

	f := func(ui *jwtverifier.UserInfo) {
		obj.Identifier = string(ui.UserID)
	}

	// Main page with login|logout actions
	e.GET("/", index)
	// Create state and redirect to auth endpoint
	e.GET("/authme", authMeProcess)
	// Validate auth code result
	e.GET("/auth/callback", authCallback)
	// Check access to page by authentication header
	e.GET("/private", privateZone, jwt_middleware.AuthOneJwtWithConfig(jwtv))
	// Check access to page by authentication header with custom callable function
	e.GET("/private_callable", privateZoneCallable, jwt_middleware.AuthOneJwtCallableWithConfig(jwtv, f))
	// Page without authentication header validation
	e.GET("/some-route", someRoute)
	// Logout
	e.GET("/logout", logout)
	// Logout callback for clean local tokens, session and etc.
	e.GET("/logout_result", logoutResult)
	// Logout callback for clean local tokens, session and etc.
	e.GET("/introspect", introspectTest)

	// Start server
	e.Logger.Fatal(e.Start(":1323"))
}

func index(c echo.Context) error {
	cookie, _ := c.Request().Cookie(authCookieName)
	isAuthenticate := cookie.String() != ""

	if isAuthenticate == true {
		userInfo, err := userinfo(c.Request().Context(), cookie.Value)
		if err != nil {
			c.Echo().Logger.Error("Unable to get user info")
			fmt.Print(err)
		} else {
			fmt.Print(userInfo)
		}
	}

	return c.Render(http.StatusOK, "index.html", map[string]interface{}{
		"AuthDomain":        authDomain,
		"ClientID":          clientID,
		"RedirectUri":       redirectUri,
		"LogoutRedirectUri": logoutRedirectUri,
		"IsAuthenticate":    isAuthenticate,
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

func privateZoneCallable(c echo.Context) error {
	fmt.Printf("User: %+v\n", obj.Identifier)
	return c.HTML(http.StatusOK, "")
}

func authMeProcess(c echo.Context) error {
	options := jwtverifier.AuthUrlOption{
		Key:   "test1",
		Value: "value1",
	}
	u := jwtv.CreateAuthUrl("example_state_string", options)
	return c.Redirect(http.StatusPermanentRedirect, u)
}

func logout(c echo.Context) error {
	c.SetCookie(&http.Cookie{Name: authCookieName, Value: "", Path: "/", Expires: time.Unix(0, 0)})
	url := fmt.Sprintf("%s://%s", c.Scheme(), c.Request().Host)
	return c.Redirect(http.StatusPermanentRedirect, jwtv.CreateLogoutUrl(url))
}

func logoutResult(c echo.Context) error {
	c.SetCookie(&http.Cookie{Name: authCookieName, Value: "", Path: "/", Expires: time.Unix(0, 0)})
	return c.Render(http.StatusOK, "logout.html", map[string]interface{}{})
}

func authCallback(c echo.Context) error {
	payload := &payload{ClientID: clientID, Result: true}
	ctx := c.Request().Context()
	t, err := jwtv.Exchange(ctx, fmt.Sprint(c.QueryParam("code")))
	if err != nil {
		c.Echo().Logger.Error("Unable to get auth token")
		payload.Error = fmt.Sprintf("Authorization error: %s\n", err.Error())
	} else {
		c.SetCookie(&http.Cookie{Name: authCookieName, Value: t.AccessToken, Path: "/", Expires: t.Expiry})

		payload.AccessToken = t.AccessToken
		payload.RefreshToken = t.RefreshToken
		payload.Expire = t.Expiry
		fmt.Printf("AccessToken string: %s\n", t.AccessToken)
		fmt.Printf("RefreshToken string: %s\n", t.RefreshToken)
		fmt.Printf("Token expire: %s", t.Expiry)

		introspectAccessToken, introspectRefreshToken, err := introspect(ctx, t)
		if err != nil {
			c.Echo().Logger.Error("Unable to get introspect access token")
			fmt.Print(err)
			payload.Error = fmt.Sprintf("Unable to introspect token: %s\n", err.Error())
		} else {
			payload.IntrospectAccessToken = *introspectAccessToken
			payload.IntrospectRefreshToken = *introspectRefreshToken
		}

		userInfo, err := userinfo(ctx, t.AccessToken)
		if err != nil {
			c.Echo().Logger.Error("Unable to get user info")
			fmt.Print(err)
			payload.Error = fmt.Sprintf("Unable to get user info: %s\n", err.Error())
		} else {
			payload.UserInfo = *userInfo
		}

		idToken, err := validateIdToken(ctx, t)
		if err != nil {
			c.Echo().Logger.Error("Unable to get validate id token")
			fmt.Print(err)
			payload.Error = fmt.Sprintf("Unable to validate id token: %s\n", err.Error())
		} else {
			payload.IdToken = *idToken
		}
	}

	if payload.Error != "" {
		payload.Result = false
	}

	return c.Render(http.StatusOK, "callback.html", map[string]interface{}{
		"Result":       payload.Result,
		"Error":        payload.Error,
		"AccessToken":  payload.AccessToken,
		"RefreshToken": payload.RefreshToken,
		"Expire":       payload.Expire,
	})
}

func introspect(c context.Context, token *jwtverifier.Token) (*jwtverifier.IntrospectToken, *jwtverifier.IntrospectToken, error) {
	at, err := jwtv.Introspect(c, token.AccessToken)
	if err != nil {
		return nil, nil, err
	}
	fmt.Printf("AccessToken JWT: %+v\n", at)
	fmt.Printf("AccessToken expiry: %+v\n", at.Exp)

	rt, err := jwtv.Introspect(c, token.RefreshToken)
	if err != nil {
		return nil, nil, err
	}
	fmt.Printf("RefreshToken JWT: %+v\n", rt)
	fmt.Printf("RefreshToken expiry: %+v\n", rt.Exp)

	return at, rt, nil
}

func userinfo(c context.Context, token string) (*jwtverifier.UserInfo, error) {
	info, err := jwtv.GetUserInfo(c, token)
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
	fmt.Printf("ID token string: %+v\n", id)
	t, err := jwtv.ValidateIdToken(c, fmt.Sprint(id))
	if err != nil {
		return nil, err
	}
	fmt.Printf("ID token: %+v\n", t)
	return t, nil
}

func introspectTest(ctx echo.Context) error {
	token := ctx.QueryParam("token")
	t, err := jwtv.Introspect(ctx.Request().Context(), token)
	fmt.Println(t)
	fmt.Println(err)
	return nil
}

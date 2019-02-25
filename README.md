# go-echo-middleware

[![Build Status](https://travis-ci.org/ProtocolONE/authone-jwt-verifier-golang.svg?branch=master)](https://travis-ci.org/ProtocolONE/authone-jwt-verifier-golang) [![codecov](https://codecov.io/gh/ProtocolONE/authone-jwt-verifier-golang/branch/master/graph/badge.svg)](https://codecov.io/gh/ProtocolONE/authone-jwt-verifier-golang) [![Go Report Card](https://goreportcard.com/badge/github.com/ProtocolONE/authone-jwt-verifier-golang)](https://goreportcard.com/report/github.com/ProtocolONE/authone-jwt-verifier-golang)

# Overview

This component contains helper methods for working with authentication in ProtocolOne projects. Also, based on these 
methods, middleware is implemented to verify authentication in the Echo framework.

# Installation

```
go get -u github.com/ProtocolONE/authone-jwt-verifier-golang
```

# Usage 

The complete example of usage can be found in the demo application located in the [example directory](/example). This library was built to simplify authorization process and converting opaque oauth2 access tokens to Jwt tokens and manage they lifecycle. To get it running at its most basic form, all you need to provide is the the following information:

- **Client ID** - The unique ID of application in the AuthOne Developer Console.
- **RedirectURL** - The authorization server will redirect the user back to the application with either an authorization code or access token in the URL.
- **Endpoint** - The set of endpoints of authorization server to manage introspection, authorization, revoke and get user info operations.

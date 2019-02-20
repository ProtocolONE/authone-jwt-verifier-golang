package storage

import "github.com/ProtocolONE/go-echo-middleware"

// Adapter used for store and retrieve encrypted tokens from oauth introspection endpoint.
type Adapter interface {
	Set(token string, introspect *jwtverifier.IntrospectToken) error
	Get(token string) (*jwtverifier.IntrospectToken, error)
	Delete(token string) error
}

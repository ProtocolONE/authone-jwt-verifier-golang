package storage

import (
	"github.com/ProtocolONE/authone-jwt-verifier-golang/internal"
)

// Adapter used for store and retrieve encrypted tokens from oauth introspection endpoint.
type Adapter interface {
	Set(token string, introspect *internal.IntrospectToken) error
	Get(token string) (*internal.IntrospectToken, error)
	Delete(token string) error
}

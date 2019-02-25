package storage

// Adapter used for store and retrieve encrypted tokens from oauth introspection endpoint.
type Adapter interface {
	Set(token string, expire int64, introspect []byte) error
	Get(token string) ([]byte, error)
	Delete(token string) error
}

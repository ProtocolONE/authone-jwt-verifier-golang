package memory

import (
	"errors"
	"github.com/ProtocolONE/authone-jwt-verifier-golang/storage"
	lru "github.com/hashicorp/golang-lru"
	"time"
)

const (
	ErrorTokenNotExists = "token not exists"
	ErrorTokenIsExpired = "token is expired"
	MaxSize             = 5000
)

type entry struct {
	value    []byte
	duration time.Duration
}

type tokenStorageMemory struct {
	cache *lru.Cache
}

func NewStorage(maxSize int) storage.Adapter {
	l, _ := lru.New(maxSize)
	return tokenStorageMemory{
		cache: l,
	}
}

func (tsm tokenStorageMemory) Set(token string, expire int64, introspect []byte) error {
	e := &entry{
		value:    introspect,
		duration: time.Unix(expire, 0).Sub(time.Now()),
	}
	tsm.cache.Add(token, e)
	return nil
}

func (tsm tokenStorageMemory) Get(token string) ([]byte, error) {
	if e, ok := tsm.cache.Get(token); ok {
		entry := e.(*entry)
		exp := time.Now().Add(entry.duration)
		if exp.Before(time.Now()) {
			_ = tsm.Delete(token)
			return nil, errors.New(ErrorTokenIsExpired)
		}
		return entry.value, nil
	}
	return nil, errors.New(ErrorTokenNotExists)
}

func (tsm tokenStorageMemory) Delete(token string) error {
	tsm.cache.Remove(token)
	return nil
}

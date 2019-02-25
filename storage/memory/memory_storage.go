package memory

import (
	"errors"
	"fmt"
	"github.com/ProtocolONE/authone-jwt-verifier-golang/storage"
	"github.com/karlseguin/ccache"
	"time"
)

const (
	ErrorTokenNotExists = "token not exists"
	ErrorTokenIsExpired = "token is expired"
	MaxSize             = 5000
	PruneLimit          = 500
	PromoteLimit        = 3
)

type tokenStorageMemory struct {
	cache *ccache.Cache
}

func NewStorage(maxSize int64, pruneLimit uint32, promoteLimit int32) storage.Adapter {
	conf := ccache.Configure()
	conf.MaxSize(maxSize)
	conf.ItemsToPrune(pruneLimit)
	conf.GetsPerPromote(promoteLimit)

	return tokenStorageMemory{
		cache: ccache.New(conf),
	}
}

func (tsm tokenStorageMemory) Set(token string, expire int64, introspect []byte) error {
	duration := time.Unix(expire, 0).Sub(time.Now())
	tsm.cache.Set(token, introspect, duration)
	return nil
}

func (tsm tokenStorageMemory) Get(token string) ([]byte, error) {
	item := tsm.cache.Get(token)
	if item == nil {
		return nil, errors.New(ErrorTokenNotExists)
	}
	if item.Expired() {
		_ = tsm.Delete(token)
		return nil, errors.New(ErrorTokenIsExpired)
	}
	v := fmt.Sprintf("%s", item.Value())
	return []byte(v), nil
}

func (tsm tokenStorageMemory) Delete(token string) error {
	if tsm.cache.Delete(token) == false {
		return fmt.Errorf("unable to delete token [%s] from cache", token)
	}

	return nil
}

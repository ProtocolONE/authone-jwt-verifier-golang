package memory

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ProtocolONE/go-echo-middleware"
	"github.com/ProtocolONE/go-echo-middleware/storage"
	"github.com/karlseguin/ccache"
	"time"
)

type tokenStorageMemory struct {
	cache *ccache.Cache
	key   string
}

func NewStogare(maxSize int64, itemsToPrune uint32) storage.Adapter {
	return tokenStorageMemory{
		cache: ccache.New(ccache.Configure().MaxSize(int64(maxSize)).ItemsToPrune(itemsToPrune)),
		key:   "a_t_s_%s",
	}
}

func (tsm *tokenStorageMemory) buildKey(t string) string {
	return fmt.Sprintf(tsm.key, t)
}

func (tsm tokenStorageMemory) Set(token string, introspect *jwtverifier.IntrospectToken) error {
	duration := time.Since(time.Unix(introspect.Exp, 0))
	b, err := json.Marshal(introspect)
	if err != nil {
		return err
	}
	tsm.cache.Set(tsm.buildKey(token), b, duration)
	return nil
}

func (tsm tokenStorageMemory) Get(token string) (*jwtverifier.IntrospectToken, error) {
	item := tsm.cache.Get(tsm.buildKey(token))
	if item == nil {
		return nil, errors.New("token not exists")
	}
	if item.Expired() {
		_ = tsm.Delete(token)
		return nil, errors.New("token is expired")
	}
	it := jwtverifier.IntrospectToken{}
	if err := json.Unmarshal(item.Value().([]byte), it); err != nil {
		return nil, err
	}
	return &it, nil
}

func (tsm tokenStorageMemory) Delete(token string) error {
	tsm.cache.Delete(tsm.buildKey(token))
	return nil
}

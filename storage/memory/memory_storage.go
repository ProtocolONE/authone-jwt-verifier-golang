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

// Create memory storage with options:
// maxSize - the maximum number size to store in the cache (default: 5000)
// itemsToPrune - the number of items to prune when we hit MaxSize (default: 500)
// getsPerPromote - the number of times an item is fetched before we promote it (default: 3)
//
// More information at https://github.com/karlseguin/ccache
func NewStorage(options map[string]interface{}) storage.Adapter {
	conf := ccache.Configure()
	var (
		maxSize        int64  = 5000
		itemsToPrune   uint32 = 100
		getsPerPromote int32  = 3
	)
	if val, ok := options["maxSize"]; ok {
		maxSize = val.(int64)
	}
	if val, ok := options["itemsToPrune"]; ok {
		itemsToPrune = val.(uint32)
	}
	if val, ok := options["getsPerPromote"]; ok {
		getsPerPromote = val.(int32)
	}
	conf.MaxSize(maxSize)
	conf.ItemsToPrune(itemsToPrune)
	conf.GetsPerPromote(getsPerPromote)
	return tokenStorageMemory{
		cache: ccache.New(conf),
		key:   "a_t_s:%s",
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

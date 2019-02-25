package memory

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ProtocolONE/authone-jwt-verifier-golang/internal"
	"github.com/ProtocolONE/authone-jwt-verifier-golang/storage"
	"github.com/karlseguin/ccache"
	"time"
)

const (
	OptionMaxSize        = "maxSize"
	OptionItemsToPrune   = "itemsToPrune"
	OptionGetsPerPromote = "getsPerPromote"

	ErrorTokenNotExists = "token not exists"
	ErrorTokenIsExpired = "token is expired"
)

type tokenStorageMemory struct {
	cache *ccache.Cache
	key   string
}

// Create memory storage with options:
// maxSize(int64) - the maximum number size to store in the cache (default: 5000)
// itemsToPrune(uint32) - the number of items to prune when we hit MaxSize (default: 500)
// getsPerPromote(int32) - the number of times an item is fetched before we promote it (default: 3)
//
// More information at https://github.com/karlseguin/ccache
func NewStorage(options map[string]interface{}) storage.Adapter {
	conf := ccache.Configure()
	var (
		maxSize        int64  = 5000
		itemsToPrune   uint32 = 100
		getsPerPromote int32  = 3
	)
	if val, ok := options[OptionMaxSize]; ok {
		maxSize = val.(int64)
	}
	if val, ok := options[OptionItemsToPrune]; ok {
		itemsToPrune = val.(uint32)
	}
	if val, ok := options[OptionGetsPerPromote]; ok {
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

func (tsm tokenStorageMemory) Set(token string, introspect *internal.IntrospectToken) error {
	duration := time.Unix(introspect.Exp, 0).Sub(time.Now())
	b, err := json.Marshal(introspect)
	if err != nil {
		return err
	}
	tsm.cache.Set(tsm.buildKey(token), b, duration)
	return nil
}

func (tsm tokenStorageMemory) Get(token string) (*internal.IntrospectToken, error) {
	item := tsm.cache.Get(tsm.buildKey(token))
	if item == nil {
		return nil, errors.New(ErrorTokenNotExists)
	}
	if item.Expired() {
		_ = tsm.Delete(token)
		return nil, errors.New(ErrorTokenIsExpired)
	}
	it := &internal.IntrospectToken{}
	if err := json.Unmarshal(item.Value().([]byte), it); err != nil {
		return nil, err
	}
	return it, nil
}

func (tsm tokenStorageMemory) Delete(token string) error {
	tsm.cache.Delete(tsm.buildKey(token))
	return nil
}

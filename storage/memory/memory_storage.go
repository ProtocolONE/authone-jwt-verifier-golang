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

// Config defines configuration of storage
//
// More information at https://github.com/karlseguin/ccache
type Config struct {
	// MaxSize defines maximum number size to store in the cache (default: 5000)
	MaxSize int64

	// ItemsToPrune defines number of items to prune when we hit MaxSize (default: 500)
	ItemsToPrune uint32

	// GetsPerPromote defines number of times an item is fetched before we promote it (default: 3)
	GetsPerPromote int32
}

func NewStorage(conf *Config) storage.Adapter {
	cconf := ccache.Configure()
	var (
		maxSize        int64  = 5000
		itemsToPrune   uint32 = 100
		getsPerPromote int32  = 3
	)
	if conf.MaxSize != 0 {
		maxSize = conf.MaxSize
	}
	if conf.ItemsToPrune != 0 {
		itemsToPrune = conf.ItemsToPrune
	}
	if conf.GetsPerPromote != 0 {
		getsPerPromote = conf.GetsPerPromote
	}

	cconf.MaxSize(maxSize)
	cconf.ItemsToPrune(itemsToPrune)
	cconf.GetsPerPromote(getsPerPromote)
	return tokenStorageMemory{
		cache: ccache.New(cconf),
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

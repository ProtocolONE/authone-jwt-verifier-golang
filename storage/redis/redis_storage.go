package redis

import (
	"errors"
	"fmt"
	"github.com/ProtocolONE/authone-jwt-verifier-golang/storage"
	"github.com/go-redis/redis"
	"time"
)

const (
	ErrorTokenNotExists = "token not exists"
)

type redisStorage struct {
	redis *redis.Client
	key   string
}

func NewStorage(client *redis.Client, options ...interface{}) (storage.Adapter, error) {
	key := "jwt:%s"
	if len(options) > 0 {
		switch options[0].(type) {
		case string:
			key = options[0].(string)
		default:
			panic("Invalid options type for namespace")
		}
	}

	return redisStorage{redis: client, key: key}, nil
}

func (tsr *redisStorage) buildKey(t string) string {
	return fmt.Sprintf(tsr.key, t)
}

func (tsr redisStorage) Set(token string, expire int64, introspect []byte) error {
	duration := time.Unix(expire, 0).Sub(time.Now())
	if err := tsr.redis.Set(tsr.buildKey(token), introspect, duration); err.Err() != nil {
		return err.Err()
	}
	return nil
}

func (tsr redisStorage) Get(token string) ([]byte, error) {
	res := tsr.redis.Get(tsr.buildKey(token))
	if res.Err() != nil {
		return nil, errors.New(ErrorTokenNotExists)
	}
	b, err := res.Bytes()
	if err != nil {
		return nil, err
	}
	return b, err
}

func (tsr redisStorage) Delete(token string) error {
	err := tsr.redis.Del(tsr.buildKey(token))
	return err.Err()
}

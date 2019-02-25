package redis

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ProtocolONE/authone-jwt-verifier-golang/internal"
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

func NewStorage(c *redis.Client) storage.Adapter {
	return redisStorage{redis: c, key: "a_t_s:%s"}
}

func (tsr *redisStorage) buildKey(t string) string {
	return fmt.Sprintf(tsr.key, t)
}

func (tsr redisStorage) Set(token string, introspect *internal.IntrospectToken) error {
	duration := time.Unix(introspect.Exp, 0).Sub(time.Now())
	b, err := json.Marshal(introspect)
	if err != nil {
		return err
	}
	err2 := tsr.redis.Set(tsr.buildKey(token), b, duration)
	return err2.Err()
}

func (tsr redisStorage) Get(token string) (*internal.IntrospectToken, error) {
	res := tsr.redis.Get(tsr.buildKey(token))
	if res.Err() != nil {
		return nil, errors.New(ErrorTokenNotExists)
	}
	b, _ := res.Bytes()
	it := &internal.IntrospectToken{}
	err := json.Unmarshal(b, it)
	return it, err
}

func (tsr redisStorage) Delete(token string) error {
	err := tsr.redis.Del(tsr.buildKey(token))
	return err.Err()
}

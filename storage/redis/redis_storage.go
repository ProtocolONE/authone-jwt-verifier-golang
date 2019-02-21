package redis

import (
	"encoding/json"
	"fmt"
	"github.com/ProtocolONE/go-echo-middleware"
	"github.com/ProtocolONE/go-echo-middleware/storage"
	"github.com/go-redis/redis"
	"time"
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

func (tsr redisStorage) Set(token string, introspect *jwtverifier.IntrospectToken) error {
	duration := time.Since(time.Unix(introspect.Exp, 0))
	b, err := json.Marshal(introspect)
	if err != nil {
		return err
	}
	if err := tsr.redis.Set(tsr.buildKey(token), b, duration); err.Err() != nil {
		return err.Err()
	}
	return nil
}

func (tsr redisStorage) Get(token string) (*jwtverifier.IntrospectToken, error) {
	res := tsr.redis.Get(tsr.buildKey(token))
	if res.Err() != nil {
		return nil, res.Err()
	}
	b, err := res.Bytes()
	if err != nil {
		return nil, err
	}
	it := jwtverifier.IntrospectToken{}
	if err := json.Unmarshal(b, it); err != nil {
		return nil, err
	}
	return &it, nil
}

func (tsr redisStorage) Delete(token string) error {
	if err := tsr.redis.Del(tsr.buildKey(token)); err.Err() != nil {
		return err.Err()
	}
	return nil
}

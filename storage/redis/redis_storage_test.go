package redis

import (
	"fmt"
	"github.com/ProtocolONE/authone-jwt-verifier-golang/internal"
	"github.com/ProtocolONE/authone-jwt-verifier-golang/storage"
	"github.com/go-redis/redis"
	"testing"
	"time"
)

func TestSetAndGetToken(t *testing.T) {
	st := createStorage()
	tName := fmt.Sprintf("%d", time.Now().UnixNano())
	token := &internal.IntrospectToken{
		Sub: tName,
		Exp: time.Now().Add(5 * time.Second).Unix(),
	}
	if err := st.Set(tName, token); err != nil {
		t.Log("Unable to add token")
	}

	tok, err := st.Get(tName)
	if err != nil {
		t.Log("Unable to get token")
	}
	if token.Sub != tok.Sub {
		t.Errorf("Expected %s token, but %s token was received.", token.Sub, tok.Sub)
	}
}

func TestExpireToken(t *testing.T) {
	st := createStorage()
	tName := fmt.Sprintf("%d", time.Now().UnixNano())
	token := &internal.IntrospectToken{
		Sub: tName,
		Exp: time.Now().Add(time.Second).Unix(),
	}
	if err := st.Set(tName, token); err != nil {
		t.Error("Unable to add token")
	}

	time.Sleep(time.Second * 1)
	tss, err := st.Get(tName)
	if err == nil {
		fmt.Printf("tok: %+v\n", tss)
		t.Error("An expired token should not be received")
		return
	}
	if err.Error() != ErrorTokenNotExists {
		t.Errorf("Invalid error status [%s], must be [%s]", err.Error(), ErrorTokenNotExists)
		return
	}
}

func TestGetUnExistsToken(t *testing.T) {
	st := createStorage()
	tName := "unexiststoken"
	_, err := st.Get(tName)
	if err == nil {
		t.Error("Non-existent token should not be received")
		return
	}
	if err.Error() != ErrorTokenNotExists {
		t.Errorf("Invalid error status [%s], must be [%s]", err.Error(), ErrorTokenNotExists)
		return
	}
}

func TestCreateClientWithoutRedis(t *testing.T) {
	if _, err := NewStorage(&Config{}); err == nil {
		t.Error("Creating a store without redis should return an error")
	}
}

func TestRedeclareStorageKey(t *testing.T) {
	st1 := createStorage()
	tName := fmt.Sprintf("%d", time.Now().UnixNano())
	token := &internal.IntrospectToken{
		Sub: tName,
		Exp: time.Now().Add(60 * time.Second).Unix(),
	}
	st1.Set(tName, token)

	conf := &Config{
		Client: redis.NewClient(&redis.Options{
			Addr: "localhost:6379",
		}),
		Key: tName + ":%s",
	}
	st2, _ := NewStorage(conf)
	tok, _ := st2.Get(tName)
	if tok != nil {
		t.Log("Token should not be returned, it is on a different key")
	}
}

func createStorage() storage.Adapter {
	conf := &Config{
		Client: redis.NewClient(&redis.Options{
			Addr: "localhost:6379",
		}),
	}
	st, _ := NewStorage(conf)
	return st
}

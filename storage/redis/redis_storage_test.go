package redis

import (
	"fmt"
	"github.com/ProtocolONE/authone-jwt-verifier-golang/storage"
	"github.com/go-redis/redis"
	"testing"
	"time"
)

func TestSetAndGetToken(t *testing.T) {
	st := createStorage()
	tName := fmt.Sprintf("%d", time.Now().UnixNano())
	exp := time.Now().Add(5 * time.Second).Unix()
	token := []byte("token" + tName)
	if err := st.Set(tName, exp, token); err != nil {
		t.Logf("Unable to add token to the redis: %s", err.Error())
	}

	tok, err := st.Get(tName)
	if err != nil {
		t.Logf("Unable to get token from the redis: %s", err.Error())
	}
	if string(token) != string(tok) {
		t.Errorf("Expected %s token, but %s token was received.", string(token), string(tok))
	}
}

func TestExpireToken(t *testing.T) {
	st := createStorage()
	tName := fmt.Sprintf("%d", time.Now().UnixNano())
	exp := time.Now().Add(time.Second).Unix()
	token := []byte(tName)
	if err := st.Set(tName, exp, token); err != nil {
		t.Error("Unable to add token to the redis")
	}

	time.Sleep(time.Second * 1)
	_, err := st.Get(tName)
	if err == nil {
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

func TestRedeclareStorageKey(t *testing.T) {
	st1 := createStorage()
	tName := fmt.Sprintf("%d", time.Now().UnixNano())
	exp := time.Now().Add(60 * time.Second).Unix()
	token := []byte(tName)
	st1.Set(tName, exp, token)

	st2, _ := NewStorage(redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	}), tName+":%s")
	tok, _ := st2.Get(tName)
	if tok != nil {
		t.Log("Token should not be returned, it is on a different key")
	}
}

func createStorage() storage.Adapter {
	client := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})
	st, _ := NewStorage(client)
	return st
}

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

func createStorage() storage.Adapter {
	return NewStorage(redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	}))
}

package memory

import (
	"fmt"
	"github.com/ProtocolONE/authone-jwt-verifier-golang/internal"
	"github.com/ProtocolONE/authone-jwt-verifier-golang/storage"
	"testing"
	"time"
)

func TestSetAndGetToken(t *testing.T) {
	st := createStorage(1, 1)
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
	st := createStorage(1, 1)
	tName := fmt.Sprintf("%d", time.Now().UnixNano())
	token := &internal.IntrospectToken{
		Sub: tName,
		Exp: time.Now().Add(time.Second).Unix() - 1,
	}
	if err := st.Set(tName, token); err != nil {
		t.Log("Unable to add token")
	}

	_, err := st.Get(tName)
	if err == nil {
		t.Error("An expired token should not be received")
		return
	}
	if err.Error() != ErrorTokenIsExpired {
		t.Errorf("Invalid error status [%s], must be [%s]", err.Error(), ErrorTokenIsExpired)
		return
	}
}

func TestGetUnExistsToken(t *testing.T) {
	st := createStorage(1, 1)
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

func TestDeleteToken(t *testing.T) {
	st := createStorage(1, 1)
	tName := fmt.Sprintf("%d", time.Now().UnixNano())
	token := &internal.IntrospectToken{
		Sub: tName,
		Exp: time.Now().Add(5 * time.Second).Unix(),
	}
	if err := st.Set(tName, token); err != nil {
		t.Log("Unable to add token")
	}
	if err := st.Delete(tName); err != nil {
		t.Log("Unable to delete token")
	}

	if _, err := st.Get(tName); err.Error() != ErrorTokenNotExists {
		t.Error("Token has not been deleted")
	}
}

func createStorage(maxSize int, itemsToPrune int) storage.Adapter {
	conf := &Config{
		MaxSize:      int64(maxSize),
		ItemsToPrune: uint32(itemsToPrune),
	}
	return NewStorage(conf)
}

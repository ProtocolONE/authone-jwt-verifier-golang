package memory

import (
	"fmt"
	"github.com/ProtocolONE/authone-jwt-verifier-golang/storage"
	"testing"
	"time"
)

func TestSetAndGetToken(t *testing.T) {
	st := createStorage(1)
	tName := fmt.Sprintf("%d", time.Now().UnixNano())
	exp := time.Now().Add(5 * time.Second).Unix()
	token := []byte(tName)
	if err := st.Set(tName, exp, token); err != nil {
		t.Log("Unable to add token to the memory")
	}

	tok, err := st.Get(tName)
	if err != nil {
		t.Log("Unable to get token from the memory")
	}
	if string(token) != string(tok) {
		t.Errorf("Expected %s token, but %s token was received.", string(token), string(tok))
	}
}

func TestExpireToken(t *testing.T) {
	st := createStorage(1)
	tName := fmt.Sprintf("%d", time.Now().UnixNano())
	exp := time.Now().Add(time.Second).Unix() + 2
	token := []byte(tName)
	if err := st.Set(tName, exp, token); err != nil {
		t.Log("Unable to add token to the memory")
	}

	time.Sleep(3 * time.Second)

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
	st := createStorage(1)
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
	st := createStorage(1)
	tName := fmt.Sprintf("%d", time.Now().UnixNano())
	exp := time.Now().Add(5 * time.Second).Unix()
	token := []byte(tName)
	if err := st.Set(tName, exp, token); err != nil {
		t.Log("Unable to add token to the memory")
	}
	if err := st.Delete(tName); err != nil {
		t.Log("Unable to delete token from the memory")
	}

	if _, err := st.Get(tName); err.Error() != ErrorTokenNotExists {
		t.Error("Token has not been deleted from the memory")
	}
}

func createStorage(maxSize int) storage.Adapter {
	return NewStorage(maxSize)
}

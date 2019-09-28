package cipher

import (
	"encoding/hex"
	"testing"
)

func TestGenKey(t *testing.T) {
	password := "hello"
	keyLen := 32
	key := GenKey(password, keyLen)
	if len(key) != keyLen {
		t.Error("长度不一致")
	}
	t.Log(key)
	t.Log(hex.EncodeToString(key))
}

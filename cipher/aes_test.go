package cipher

import (
	"encoding/hex"
	"testing"
)

var password = "hello"

func TestNewAESCrypto(t *testing.T) {
	c, err := NewAESCrypto(password, 16)
	if err != nil {
		t.Errorf("运行 NewAESCrypto 失败: %v", err)
	}
	if c.key == nil {
		t.Error("key 是空的")
	}
	if c.block == nil {
		t.Error("block 是空的")
	}
}

func TestAESCrypto_EncodeData(t *testing.T) {
	c, _ := NewAESCrypto(password, 16)
	plaintext := []byte("hello world")
	ciphertext, err := c.EncodeData((plaintext))
	if err != nil {
		t.Errorf("AESCrypto 加密时发生错误: %v", err)
	}
	if len(ciphertext) != len(plaintext) {
		t.Error("加密后的大小不对")
	}
	t.Log(hex.EncodeToString(ciphertext))
}

func TestNewAESCrypto_DecodeData(t *testing.T) {
	c, _ := NewAESCrypto(password, 16)
	ciphertext, _ := hex.DecodeString("12516deaf8a06cc4ff9072fb84938e87b557c29d8017274406f7f5")
	c.Remoteiv = ciphertext[:16]
	plaintext, err := c.DecodeData(ciphertext[16:])
	if err != nil {
		t.Errorf("AESCrypto 解密时发生错误: %v", err)
	}
	source := "hello world"
	if string(plaintext) != source {
		t.Errorf("解密后的结果不正确, 解密结果为 %s, 应该是 %s", string(plaintext), source)
	}
	t.Log(string(plaintext))
}

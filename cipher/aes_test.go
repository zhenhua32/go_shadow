package cipher

import (
	"crypto/aes"
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
	if len(ciphertext) != len(plaintext)+aes.BlockSize {
		t.Error("加密后的大小不对")
	}
	// 12516deaf8a06cc4ff9072fb84938e87b557c29d8017274406f7f5
	t.Log(hex.EncodeToString(ciphertext))
}

func TestNewAESCrypto_DecodeData(t *testing.T) {
	c, _ := NewAESCrypto(password, 16)
	ciphertext, _ := hex.DecodeString("12516deaf8a06cc4ff9072fb84938e87b557c29d8017274406f7f5")
	plaintext, err := c.DecodeData(ciphertext)
	if err != nil {
		t.Errorf("AESCrypto 解密时发生错误: %v", err)
	}
	source := "hello world"
	if string(plaintext) != source {
		t.Errorf("解密后的结果不正确, 解密结果为 %s, 应该是 %s", string(plaintext), source)
	}
	t.Log(string(plaintext))
}

func TestTT(t *testing.T) {
	password = "hellotheworld"
	c, _ := NewAESCrypto(password, 32)
	ciphertext, _ := hex.DecodeString("786e72f5b670fdc33616792cfcf59d091781b0a6e91b6dd360012824fd75f6d57a35fc9c3d1c53d392c2748b90a837bb8763288e43aada4329c560905e2fa11b")
	plaintext, err := c.DecodeData(ciphertext)
	if err != nil {
		t.Errorf("AESCrypto 解密时发生错误: %v", err)
	}
	source := "hello world"
	if string(plaintext) != source {
		t.Errorf("解密后的结果不正确, 解密结果为 %s, 应该是 %s", string(plaintext), source)
	}
	t.Errorf("%v", plaintext)
}

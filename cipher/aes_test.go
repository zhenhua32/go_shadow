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
	t.Error(hex.EncodeToString(append(c.Localiv, ciphertext...)))
}

func TestNewAESCrypto_DecodeData(t *testing.T) {
	c, _ := NewAESCrypto(password, 16)
	ciphertext, _ := hex.DecodeString("8d3a88c1428c60e1040728fc82206dcb363f49e5e992e2f30ab442")
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

func TestTT(t *testing.T) {
	password = "hellotheworld"
	c, _ := NewAESCrypto(password, 32)
	ciphertext := []byte{121, 221}
	iv := []byte{0xc, 0x16, 0xe6, 0xb0, 0xff, 0x4f, 0xb1, 0x5a, 0x55, 0x60, 0x7b, 0x3, 0x38, 0x27, 0xe3, 0xd7}
	c.Remoteiv = iv
	c.DecodeData(ciphertext[:1])
	plaintext, err := c.DecodeData(ciphertext[1:])
	if err != nil {
		t.Errorf("AESCrypto 解密时发生错误: %v", err)
	}
	t.Error(plaintext)
}

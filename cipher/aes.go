package cipher

import (
	"crypto/aes"
	gocipher "crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

// AESCrypto 是 AES加密实现, 暂时是 CFB
type AESCrypto struct {
	key      []byte          // key 是从密码中生成 derived key
	block    gocipher.Block  // block 是 cipher.Block, 块加密
	Localiv  []byte          // Localiv 本地用于加密的 iv
	Remoteiv []byte          // Remoteiv, 来自客户端, 用于解密
	dec      gocipher.Stream // 解码流
	enc      gocipher.Stream // 加密流
}

// NewAESCrypto 创建一个新的 AESCrypto
// keylen 16, 24, or 32 bytes to select AES-128, AES-192, or AES-256.
func NewAESCrypto(password string, keylen int) (*AESCrypto, error) {
	key := GenKey(password, keylen)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// 获取 iv 和 enc
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	enc := gocipher.NewCFBEncrypter(block, iv)

	return &AESCrypto{
		key:     key,
		block:   block,
		Localiv: iv,
		enc:     enc,
	}, nil
}

// EncodeData 使用 cfb 加密, 返回的数据不包括 iv
func (c *AESCrypto) EncodeData(plaintext []byte) ([]byte, error) {
	ciphertext := make([]byte, len(plaintext))
	c.enc.XORKeyStream(ciphertext, plaintext)
	return ciphertext, nil
}

// DecodeData 使用 cfb 解密, ciphertext 不包括 iv
func (c *AESCrypto) DecodeData(ciphertext []byte) ([]byte, error) {
	if c.Remoteiv == nil {
		return nil, errors.New("没有设置 Remoteiv")
	}
	if c.dec == nil {
		c.dec = gocipher.NewCFBDecrypter(c.block, c.Remoteiv)
	}

	plaintext := make([]byte, len(ciphertext))
	c.dec.XORKeyStream(plaintext, ciphertext)
	return plaintext, nil
}

// SetRemoteiv 设置 Remoteiv
func (c *AESCrypto) SetRemoteiv(iv []byte) {
	c.Remoteiv = iv
}

// GetLocaliv 返回 Localiv
func (c *AESCrypto) GetLocaliv() []byte {
	return c.Localiv
}

// AESSupportMethods 返回支持的加密方法
func AESSupportMethods() []string {
	return []string{"aes-128-cfb", "aes-192-cfb", "aes-256-cfb"}
}

// IsAESSupported 判断某种加密方法是否支持, 对支持的方法返回 keylen
func IsAESSupported(method string) (bool, int) {
	switch method {
	case "aes-128-cfb":
		return true, 16
	case "aes-192-cfb":
		return true, 24
	case "aes-256-cfb":
		return true, 32
	default:
		return false, 0
	}
}

package cipher

import (
	"crypto/aes"
	gocipher "crypto/cipher"

	"golang.org/x/crypto/scrypt"
)

type AESCrypto struct {
	key   []byte
	block gocipher.Block
}

// NewAESCrypto 创建一个新的 AESCrypto
// keylen 16, 24, or 32 bytes to select AES-128, AES-192, or AES-256.
func NewAESCrypto(password string, keylen int) *AESCrypto {
	key, _ := GenKey(password, keylen)
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	return &AESCrypto{
		key:   key,
		block: block,
	}

}

// GenKey 从密码中生成 derived key
func GenKey(password string, keylen int) ([]byte, error) {
	dk, err := scrypt.Key([]byte(password), []byte("fake"), 32768, 8, 1, keylen)
	return dk, err
}

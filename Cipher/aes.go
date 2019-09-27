package cipher

import (
	"crypto/aes"
	gocipher "crypto/cipher"
	"crypto/rand"
	"errors"
	"io"

	"golang.org/x/crypto/scrypt"
)

// AESCrypto 是 AES加密实现, 暂时是 CFB
type AESCrypto struct {
	key   []byte         // key 是从密码中生成 derived key
	block gocipher.Block // block 是 cipher.Block, 块加密
}

// NewAESCrypto 创建一个新的 AESCrypto
// keylen 16, 24, or 32 bytes to select AES-128, AES-192, or AES-256.
func NewAESCrypto(password string, keylen int) (*AESCrypto, error) {
	key, err := GenKey(password, keylen)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return &AESCrypto{
		key:   key,
		block: block,
	}, nil
}

// GenKey 从密码中生成 derived key
func GenKey(password string, keylen int) ([]byte, error) {
	dk, err := scrypt.Key([]byte(password), []byte("fake"), 32768, 8, 1, keylen)
	return dk, err
}

// EncodeData 使用 cfb 加密
func (c *AESCrypto) EncodeData(data []byte) ([]byte, error) {
	ciphertext := make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]
	// 随机填充 iv
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	stream := gocipher.NewCFBEncrypter(c.block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], data)
	return ciphertext, nil
}

// DecodeData 使用 cfb 解密
func (c *AESCrypto) DecodeData(data []byte) ([]byte, error) {
	if len(data) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	iv := data[:aes.BlockSize]
	ciphertext := data[aes.BlockSize:]
	plaintext := make([]byte, len(ciphertext))

	stream := gocipher.NewCFBDecrypter(c.block, iv)
	stream.XORKeyStream(plaintext, ciphertext) // in-place work
	return plaintext, nil
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

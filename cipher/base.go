package cipher

import "golang.org/x/crypto/scrypt"

// Crypto 接口定义了数据加解密的方式
type Crypto interface {
	// 加密数据
	EncodeData(data []byte) ([]byte, error)
	// 解密数据
	DecodeData(data []byte) ([]byte, error)
	SetRemoteiv(iv []byte)
}

// NewCrypto 根据 method 返回不同的加密方式
func NewCrypto(method string, password string) (Crypto, error) {
	isAES, keylen := IsAESSupported(method)
	switch {
	case isAES:
		return NewAESCrypto(password, keylen)
	default:
		return NewNoneCrypto(), nil
	}
}

// GenKey 从密码中生成 derived key
func GenKey(password string, keylen int) ([]byte, error) {
	dk, err := scrypt.Key([]byte(password), []byte("fake"), 32768, 8, 1, keylen)
	return dk, err
}

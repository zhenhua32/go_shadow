package cipher

// Crypto 接口定义了数据加解密的方式
type Crypto interface {
	// 加密数据
	EncodeData(data []byte) ([]byte, error)
	// 解密数据
	DecodeData(data []byte) ([]byte, error)
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

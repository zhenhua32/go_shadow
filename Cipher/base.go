package cipher

// Crypto 接口定义了数据加解密的方式
type Crypto interface {
	// 加密数据
	EncodeData(data []byte) ([]byte, error)
	// 解密数据
	DecodeData(data []byte) ([]byte, error)
}

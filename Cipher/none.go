package cipher

// NoneCrypto 实现了 Crypto 接口, 通过不对数据进行任何处理
type NoneCrypto struct {
}

func NewNoneCrypto() *NoneCrypto {
	return &NoneCrypto{}
}

func (c *NoneCrypto) EncodeData(data []byte) ([]byte, error) {
	return data, nil
}

func (c *NoneCrypto) DecodeData(data []byte) ([]byte, error) {
	return data, nil
}

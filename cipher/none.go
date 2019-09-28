package cipher

// NoneCrypto 实现了 Crypto 接口, 通过不对数据进行任何处理
type NoneCrypto struct {
}

// NewNoneCrypto 不加密数据
func NewNoneCrypto() *NoneCrypto {
	return &NoneCrypto{}
}

// EncodeData 加密数据, 实际上原样返回
func (c *NoneCrypto) EncodeData(data []byte) ([]byte, error) {
	return data, nil
}

// DecodeData 解密数据, 实际上原样返回
func (c *NoneCrypto) DecodeData(data []byte) ([]byte, error) {
	return data, nil
}

// SetRemoteiv 设置 iv
func (c *NoneCrypto) SetRemoteiv(iv []byte) {
}

// GetLocaliv 返回 iv
func (c *NoneCrypto) GetLocaliv() []byte {
	return nil
}

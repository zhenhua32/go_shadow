package cipher

import "crypto/md5"

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

func md5sum(d []byte) []byte {
	h := md5.New()
	h.Write(d)
	return h.Sum(nil)
}

// GenKey 从密码中生成 derived key,  EVP_BytesToKey.
// doc: https://www.openssl.org/docs/manmaster/man3/EVP_BytesToKey.html
func GenKey(password string, keyLen int) []byte {
	// dk, err := scrypt.Key([]byte(password), []byte("fake"), 32768, 8, 1, keylen)
	// return dk, err
	const md5Len = 16

	cnt := (keyLen-1)/md5Len + 1 // 循环次数
	m := make([]byte, cnt*md5Len)
	copy(m, md5sum([]byte(password))) // 第一次

	// Repeatedly call md5 until bytes generated is enough.
	// Each call to md5 uses data: prev md5 sum + password.
	d := make([]byte, md5Len+len(password))
	start := 0
	for i := 1; i < cnt; i++ { // 注意, 从 1 开始
		start += md5Len
		copy(d, m[start-md5Len:start]) // 前半部分, md5 sum
		copy(d[md5Len:], password)     // 后半部分, password
		copy(m[start:], md5sum(d))     // 复制到
	}
	return m[:keyLen]
}

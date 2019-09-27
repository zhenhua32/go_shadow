package model

import (
	"encoding/binary"
	"io"
	"net"
	"strconv"

	"github.com/sirupsen/logrus"
	"tzh.com/shadow/cipher"
)

// TCPServer 创建一个 TCP 服务器
type TCPServer struct {
	crypto  cipher.Crypto // 加密方式
	laddr   *net.TCPAddr  // 本地地址, 类似 :8080
	bufSize int           // 缓存大小, 字节
}

// NewTCPServer 新建一个 TCP 服务端
func NewTCPServer(port int, method string, password string) *TCPServer {
	laddr, err := net.ResolveTCPAddr("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		logrus.Errorln("创建 TCP 服务端时发生地址解析错误: ", err)
		return nil
	}
	crypto, err := cipher.NewCrypto(method, password)
	if err != nil {
		logrus.Errorln("创建 TCP 服务端时发生加密方式错误: ", err)
		return nil
	}
	return &TCPServer{
		crypto:  crypto,
		laddr:   laddr,
		bufSize: 1024,
	}
}

// Listen 监听本地端口
func (s *TCPServer) Listen() error {
	listener, err := net.ListenTCP("tcp", s.laddr)
	if err != nil {
		return err
	}

	for {
		// 监听每一个连接
		conn, err := listener.AcceptTCP()
		if err != nil {
			logrus.Errorln("处理连接时遇到错误: ", err)
			continue
		}
		go s.handle(conn)
	}
}

// handle 处理每一个连接
func (s *TCPServer) handle(conn *net.TCPConn) {
	defer conn.Close()

	// 1(addrType) + 1(lenByte) + 255(max length address) + 2(port) + 10(hmac-sha1)
	source := make([]byte, 269)
	if _, err := io.ReadFull(conn, source[:1]); err != nil {
		return
	}
	logrus.Infof("读到的数据 source: %v", source)

	buf, err := s.crypto.DecodeData(source)
	if err != nil {
		return
	}
	logrus.Infof("读到的数据, 解密后: %v", buf)
	logrus.Infof("读到的数据, 解密后 字符串形式: %v", string(buf))
	/*
			shadowsocks UDP 请求 (加密前)
		+------+----------+----------+----------+
		| ATYP | DST.ADDR | DST.PORT |   DATA   |
		+------+----------+----------+----------+
		|  1   | Variable |    2     | Variable |
		+------+----------+----------+----------+
		shadowsocks UDP 响应 (加密前)
		+------+----------+----------+----------+
		| ATYP | DST.ADDR | DST.PORT |   DATA   |
		+------+----------+----------+----------+
		|  1   | Variable |    2     | Variable |
		+------+----------+----------+----------+
		shadowsocks UDP 请求和响应 (加密后)
		+-------+--------------+
		|   IV  |    PAYLOAD   |
		+-------+--------------+
		| Fixed |   Variable   |
		+-------+--------------+
	*/

	// 判断地址类型
	var dstIP []byte
	var dstPort []byte
	var headerLen int
	logrus.Infof("第一个字节是 %v", buf[0])
	switch buf[0] {
	case 0x01: // IPV4
		dstIP = buf[1 : 1+net.IPv4len]
		dstPort = buf[1+net.IPv4len : 1+net.IPv4len+2]
		headerLen = 1 + net.IPv4len + 2
	case 0x03: // DOMAINNAME
		addrlen := int(buf[1])
		ipaddr, err := net.ResolveIPAddr("ip", string(buf[2:2+addrlen]))
		if err != nil {
			return
		}
		dstIP = ipaddr.IP
		headerLen = 2 + addrlen + 2
	case 0x04: // IPV6
		dstIP = buf[1 : 1+net.IPv6len]
		dstPort = buf[1+net.IPv6len : 1+net.IPv6len+2]
		headerLen = 1 + net.IPv6len + 2
	default:
		logrus.Info("没有解析成功")
		return
	}
	logrus.Infof("排除头部后剩余的数据: %v", buf[headerLen:])
	dstAddr := &net.TCPAddr{
		IP:   dstIP,
		Port: int(binary.BigEndian.Uint16(dstPort)),
	}
	// 连接远程网站
	dstServer, err := net.DialTCP("tcp", nil, dstAddr)
	if err != nil {
		return
	}

	defer dstServer.Close()

	// 用户 -> s -> 远程网站
	go func() {
		err := s.DecodeCopy(dstServer, conn)
		if err != nil {
			conn.Close()
			dstServer.Close()
		}
	}()
	// 远程网站 -> s -> 用户
	s.EncodeCopy(conn, dstServer)
}

// EncodeCopy 从 src 中读取数据, 并加密写入 dst
func (s *TCPServer) EncodeCopy(dst, src *net.TCPConn) error {
	buf := make([]byte, s.bufSize)
	for {
		// 读取
		readCount, errRead := src.Read(buf)
		if errRead != nil {
			if errRead == io.EOF {
				return nil
			}
			return errRead
		}
		if readCount <= 0 {
			continue
		}
		// 加密
		data, err := s.crypto.EncodeData(buf[0:readCount])
		if err != nil {
			return err
		}
		// 写入
		writeCount, errWrite := dst.Write(data)
		if errWrite != nil {
			return errWrite
		}
		if readCount != writeCount {
			return io.ErrShortWrite
		}
	}
}

// DecodeCopy 从 src 中读取加密数据, 并解密后写入 dst
func (s *TCPServer) DecodeCopy(dst, src *net.TCPConn) error {
	buf := make([]byte, s.bufSize)
	for {
		// 读取
		readCount, errRead := src.Read(buf)
		if errRead != nil {
			if errRead == io.EOF {
				return nil
			}
			return errRead
		}
		if readCount <= 0 {
			continue
		}
		// 解密
		data, err := s.crypto.DecodeData(buf[0:readCount])
		if err != nil {
			return err
		}
		// 写入
		writeCount, errWrite := dst.Write(data)
		if errWrite != nil {
			return errWrite
		}
		if readCount != writeCount {
			return io.ErrShortWrite
		}
	}
}

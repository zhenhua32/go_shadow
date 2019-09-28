package model

import (
	"encoding/json"
	"io/ioutil"

	"github.com/sirupsen/logrus"
)

// User 定义用户结构
type User struct {
	ID         uint64 `json:"id"`
	Port       int    `json:"port"`
	Password   string `json:"password"`
	CipherType string `json:"cipher_type"`
	Enable     bool   `json:"enable"`
	SpeedLimit uint64 `json:"speed_limit"`
	Transfer   uint64 `json:"transfer"`
}

// InitServer 初始化服务器
func (u *User) InitServer() *TCPServer {
	return NewTCPServer(u.Port, u.CipherType, u.Password)
}

// StartServer 启动服务器
func (u *User) StartServer() {
	logrus.Infof("用户信息 %+v", u)
	logrus.Infof("用户 %v 启动服务器在 %v 端口, 使用 %v 加密", u.ID, u.Port, u.CipherType)
	server := NewTCPServer(u.Port, u.CipherType, u.Password)
	server.Listen()
}

// Users 定义用户数组, 主要是为了 json
type Users struct {
	Users []User `json:"users"`
}

// LoadUsersFromJSON 从 json 文件中读取数据
func LoadUsersFromJSON(filename string) (*Users, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	users := Users{
		Users: make([]User, 64),
	}
	if err := json.Unmarshal(data, &users); err != nil {
		return nil, err
	}
	return &users, nil
}

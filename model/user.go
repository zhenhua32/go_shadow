package model

import (
	"encoding/json"
	"io/ioutil"
)

// User 定义用户结构
type User struct {
	ID         uint64 `json:"id"`
	Port       int    `json:"port"`
	Password   string `json:"password"`
	CipherType string `json:"cipher_type"`
	Enable     bool   `json:"enable"`
	SpeedLimit uint64 `json:"speed_limit"`
}

// InitServer 初始化服务器
func (u *User) InitServer() {

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

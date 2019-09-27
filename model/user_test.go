package model

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"testing"
)

func TestLoadUsersFromJSON(t *testing.T) {
	f, err := ioutil.TempFile("", "users")
	defer os.Remove(f.Name())
	user := User{
		ID:         1,
		Port:       1920,
		Password:   "hello",
		CipherType: "aes-256-cfb",
		Enable:     true,
		SpeedLimit: 0,
		Transfer:   0,
	}
	u := Users{
		Users: []User{user},
	}
	data, _ := json.Marshal(u)
	f.Write(data)

	filename := f.Name()
	users, err := LoadUsersFromJSON(filename)
	if err != nil {
		t.Errorf("LoadUsersFromJSON 发生错误: %v", err)
	}
	if len(users.Users) != 1 {
		t.Error("读取的用户数量不正确")
	}
}

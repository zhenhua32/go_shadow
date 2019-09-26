package model

type User struct {
	ID         uint64 `json:"id"`
	Port       int    `json:"port"`
	Password   string `json:"password"`
	CipherType string `json:"cipher_type"`
	Enable     bool   `json:"enable"`
	SpeedLimit uint64 `json:"speed_limit"`
}

func (u *User) InitServer() {

}

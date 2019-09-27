package main

import "tzh.com/shadow/model"

func main() {
	users, err := model.LoadUsersFromJSON("./userconfigs.json")
	if err != nil {
		panic(err)
	}

	for _, user := range users.Users {
		user.StartServer()
	}
}

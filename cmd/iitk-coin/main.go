package main

import (
	"fmt"
	"net/http"

	handle "github.com/rahulv73039/iitk-coin/http"

	//  to use this package execute -->>go get github.com/mattn/go-sqlite3 in command line
	_ "github.com/mattn/go-sqlite3"
)

func main() {

	http.HandleFunc("/login", handle.Login)
	http.HandleFunc("/signup", handle.Signup)
	http.HandleFunc("/secretpage", handle.SecretPage)

	http.ListenAndServe(":8080", nil)
	fmt.Println("server running")
}

package main

import (
	"fmt"
	"net/http"

	handle "github.com/rahulv73039/iitk-coin/http"

	//  to use this package execute -->>go get github.com/mattn/go-sqlite3 in command line
	_ "github.com/mattn/go-sqlite3"
)

func main() {
	// db, err := sql.Open("sqlite3", "history.db")
	// if err != nil {
	// 	panic(err)
	// }
	// defer db.Close()
	// query, err := db.Prepare("CREATE TABLE IF NOT EXISTS history (fromroll INTEGER  NOT NULL,toroll INTEGER NOT NULL,coin INTEGER UNSIGNED check(coin >=0) ,date TEXT,remark TEXT )")
	// if err != nil {
	// 	panic(err)
	// }
	// query.Exec()
	http.HandleFunc("/login", handle.Login)
	http.HandleFunc("/signup", handle.Signup)
	http.HandleFunc("/secretpage", handle.SecretPage)
	http.HandleFunc("/balance", handle.SecretPage) // Get request
	http.HandleFunc("/transfer", handle.TransferCoin)
	http.HandleFunc("/award", handle.SecretPage)
	http.HandleFunc("/redeem", handle.SecretPage)
	http.HandleFunc("/additem", handle.AddItem)
	fmt.Println("server running")
	http.ListenAndServe(":8080", nil)

}

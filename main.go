package main

import (
	"database/sql"
	"os"

	//  to use this package execute -->>go get github.com/mattn/go-sqlite3 in command line
	_ "github.com/mattn/go-sqlite3"
)

type dictionary map[string]interface{}

func addUserData(data []dictionary) {
	db, err := sql.Open("sqlite3", "./data/data.db")
	if err != nil {
		panic(err)
	}
	defer db.Close()
	query, err := db.Prepare("CREATE TABLE IF NOT EXISTS user (rollno INTEGER PRIMARY KEY NOT NULL, name TEXT NOT NULL)")
	if err != nil {
		panic(err)
	}
	query.Exec()
	query, err = db.Prepare("INSERT INTO user (rollno, name) VALUES (?, ?)")
	if err != nil {
		panic(err)
	}
	for _, elem := range data {

		query.Exec(elem["rollno"], elem["name"])
	}
}
func main() {
	dummy_data := []dictionary{
		{"rollno": 1, "name": "IITK"},
		{"rollno": 2, "name": "IITB"},
		{"rollno": 3, "name": "IITD"},
		{"rollno": 4, "name": "IITKGP"},
	}

	// make data directory if not exists
	os.MkdirAll("./data", 0755)
	// Creates database file
	os.Create("./data/data.db")
	addUserData(dummy_data)

}

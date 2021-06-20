// File: main.go
package handle

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
)

type Person struct {
	Name     string
	Rollno   int
	Password string
}
type LoginCred struct {
	Rollno   int
	Password string
}
type Claims struct {
	Rollno int
	jwt.StandardClaims
}
type TransferCred struct {
	Fromrollno int
	Torollno   int
	Coin       int
}

func hashAndSalt(pwd []byte) string {

	hash, err := bcrypt.GenerateFromPassword(pwd, bcrypt.MinCost)
	if err != nil {
		log.Println(err)
	}
	return string(hash)
}
func UserExists(rollno int) bool {
	db, err := sql.Open("sqlite3", "data.db")
	if err != nil {
		panic(err)
	}
	defer db.Close()
	row := db.QueryRow("select rollno from user where rollno= ?", rollno)

	temp := ""
	row.Scan(&temp)
	if temp != "" {

		return true
	}
	return false

}

// func LoginUser(data LoginCred) {

// }
func SignUpUser(data Person) {
	db, err := sql.Open("sqlite3", "data.db")
	if err != nil {
		panic(err)
	}
	defer db.Close()
	query, err := db.Prepare("CREATE TABLE IF NOT EXISTS user (rollno INTEGER PRIMARY KEY NOT NULL, name TEXT NOT NULL,password TEXT NOT NULL,coin INTEGER UNSIGNED check(coin >=0 ))")
	if err != nil {
		panic(err)
	}
	query.Exec()
	query, err = db.Prepare("INSERT INTO user (rollno, name, password,coin) VALUES (?, ?, ?,?)")
	if err != nil {
		panic(err)
	}
	query.Exec(data.Rollno, data.Name, data.Password, 10)
}

var jwtkey = []byte("secret_key_for_token")

func Login(w http.ResponseWriter, r *http.Request) {

	var p LoginCred

	err := json.NewDecoder(r.Body).Decode(&p)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// check := UserExists(p.Rollno)
	// if check == false {
	// 	panic("Signup first")
	// }
	db, err := sql.Open("sqlite3", "data.db")
	if err != nil {
		panic(err)
	}
	defer db.Close()
	query := db.QueryRow("SELECT password FROM user WHERE rollno=$1", p.Rollno)
	if err != nil {
		panic(err)
	}
	storedCreds := &LoginCred{}
	err = query.Scan(&storedCreds.Password)
	if err != nil {
		// If an entry with the username does not exist, send an "Unauthorized"(401) status
		if err == sql.ErrNoRows {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// If the error is of any other type, send a 500 status
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if err = bcrypt.CompareHashAndPassword([]byte(storedCreds.Password), []byte(p.Password)); err != nil {
		// If the two passwords don't match, return a 401 status
		w.WriteHeader(http.StatusUnauthorized)
	}
	expirationTime := time.Now().Add(time.Minute * 5)
	claims := &Claims{
		Rollno: p.Rollno,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtkey)
	// log.Println(tokenString)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	// w.Write([]byte(tokenString))
	//  not necessary  for now
	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expirationTime,
	})
}
func Signup(w http.ResponseWriter, r *http.Request) {

	var p Person

	err := json.NewDecoder(r.Body).Decode(&p)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// log.Println(p.Rollno)
	var check = UserExists(p.Rollno)
	if check == true {
		panic("User Already Exist")

	}
	hashp := hashAndSalt([]byte(p.Password))
	// log.Println(hashp)
	p.Password = hashp
	SignUpUser(p)
}

// can be accesed only if token is valid
func SecretPage(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	tokenStr := cookie.Value
	claims := &Claims{}
	tkn, err := jwt.ParseWithClaims(tokenStr, claims,
		func(t *jwt.Token) (interface{}, error) {
			return jwtkey, nil
		})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
	}
	if !tkn.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	fmt.Fprintf(w, "%d logged in", claims.Rollno)
}

func TransferCoin(w http.ResponseWriter, r *http.Request) {

	var p TransferCred
	var mutex = &sync.Mutex{}
	mutex.Lock()
	err := json.NewDecoder(r.Body).Decode(&p)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	db, err := sql.Open("sqlite3", "data.db")
	if err != nil {
		panic(err)
	}
	// defer db.Close()'
	if p.Coin <= 0 {
		panic("invalid Transaction")
	}
	if !UserExists(p.Torollno) {
		panic("reciever does not exist")
	}
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		log.Fatal(err)
		return
	}

	ra, err := tx.ExecContext(ctx, "UPDATE user SET coin=coin-$1 WHERE rollno=$2 AND coin - $1>=0", p.Coin, p.Fromrollno)
	if err != nil {
		tx.Rollback()
		return
	}
	rAffect, err := ra.RowsAffected()

	if err != nil || rAffect == 0 {
		tx.Rollback()
		return
	}

	_, err = tx.ExecContext(ctx, "UPDATE user SET coin=coin+$1 WHERE rollno=$2", p.Coin, p.Torollno)
	if err != nil {
		tx.Rollback()
		return
	}
	err = tx.Commit()
	mutex.Unlock()
	if err != nil {
		log.Fatal(err)
	}

}
func CheckBalance(w http.ResponseWriter, r *http.Request) {
	var p struct{ Rollno int }

	err := json.NewDecoder(r.Body).Decode(&p)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// fmt.Println(p.Rollno)
	db, err := sql.Open("sqlite3", "data.db")
	if err != nil {
		panic(err)
	}
	defer db.Close()
	query := db.QueryRow("SELECT coin FROM user WHERE rollno=$1", p.Rollno)
	if err != nil {
		panic(err)
	}
	var storedCoins struct {
		Rollno int
		Coins  int
	}

	err = query.Scan(&storedCoins.Coins)

	if err != nil {
		// If an entry with the username does not exist, send an "Unauthorized"(401) status
		if err == sql.ErrNoRows {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// If the error is of any other type, send a 500 status
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	fmt.Fprintf(w, "%d has %d coins", p.Rollno, storedCoins.Coins)

}
func AwardCoin(w http.ResponseWriter, r *http.Request) {
	var p struct {
		Rollno int
		Award  int
	}

	err := json.NewDecoder(r.Body).Decode(&p)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	db, err := sql.Open("sqlite3", "data.db")
	if err != nil {
		panic(err)
	}
	// defer db.Close()
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		log.Fatal(err)
		return
	}

	_, err = tx.ExecContext(ctx, "UPDATE user SET coin=coin+$1 WHERE rollno=$2", p.Award, p.Rollno)
	if err != nil {
		tx.Rollback()
		return
	}
	err = tx.Commit()
	if err != nil {
		log.Fatal(err)
	}
}

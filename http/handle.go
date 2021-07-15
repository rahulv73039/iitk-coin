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

var mutex = &sync.Mutex{}
var jwtkey = []byte("secret_key_for_token")

type Person struct {
	Name     string
	Rollno   int
	Password string
	Batch    string
	Admin    bool
}
type RedeemCred struct {
	RollNo int
	Name   string
	ItemId int
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
type PendReq struct {
	RedeemId int
	RollNo   int
	ItemId   int
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
func AddHistory(Fromrollno int, Torollno int, coin int, Datetime string, remark string) {
	db, err := sql.Open("sqlite3", "history.db")
	if err != nil {
		panic(err)
	}
	defer db.Close()
	query, err := db.Prepare("CREATE TABLE IF NOT EXISTS hist (fromroll INTEGER  NOT NULL,toroll INTEGER NOT NULL,coin INTEGER UNSIGNED check(coin >=0) ,date TEXT,remark TEXT )")
	if err != nil {
		panic(err)
	}
	query.Exec()
	query, err = db.Prepare("INSERT INTO hist (fromroll,toroll,coin ,date,remark) VALUES ( ?, ?,?,?,?)")
	if err != nil {
		panic(err)
	}
	// query.Exec()
	query.Exec(Fromrollno, Torollno, coin, Datetime, remark)
	// fmt.Println(Fromrollno, Torollno, coin, Datetime, remark)

}
func SignUpUser(data Person) {
	db, err := sql.Open("sqlite3", "data.db")
	if err != nil {
		panic(err)
	}
	defer db.Close()
	query, err := db.Prepare("CREATE TABLE IF NOT EXISTS user (rollno INTEGER PRIMARY KEY NOT NULL, name TEXT NOT NULL,password TEXT NOT NULL,coin INTEGER UNSIGNED check(coin >=0 ) ,  batch TEXT NOT NULL , admin BOOLEAN)")
	if err != nil {
		panic(err)
	}
	query.Exec()
	query, err = db.Prepare("INSERT INTO user (rollno, name, password,coin,batch,admin) VALUES (?, ?, ?,?,?,?)")
	if err != nil {
		panic(err)
	}
	query.Exec(data.Rollno, data.Name, data.Password, 10, data.Batch, data.Admin)
	// fmt.Println(data.Admin)
}

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
	// fmt.Println(p.Admin, " - ")
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
	switch r.URL.Path {
	case "/balance":
		CheckBalance(w, r)
	case "/award":
		AwardCoin(w, r)
	case "/redeem":
		RedeemCoin(w, r)
	}

}

func TransferCoin(w http.ResponseWriter, r *http.Request) {

	var p TransferCred

	mutex.Lock()
	err := json.NewDecoder(r.Body).Decode(&p)
	if err != nil {
		mutex.Unlock()
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	db, err := sql.Open("sqlite3", "data.db")
	if err != nil {
		mutex.Unlock()
		panic(err)
	}
	// defer db.Close()'
	if !UserExists(p.Torollno) {
		mutex.Unlock()
		panic("reciever does not exist")
	}
	db1, err := sql.Open("sqlite3", "history.db")
	if err != nil {
		mutex.Unlock()
		panic(err)
	}
	var rew_hist struct {
		fromroll_rew int
		toroll_rew   int
	}
	// to check if students has participated in events by counting no of rewards they get
	query := db1.QueryRow("SELECT COUNT(*) FROM hist WHERE toroll IN($1) AND remark IN ('reward')  ", p.Fromrollno)

	err = query.Scan(&rew_hist.fromroll_rew)
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
	query = db1.QueryRow("SELECT  COUNT(*) FROM hist WHERE toroll IN($1) AND remark IN ('reward')  ", p.Torollno)

	err = query.Scan(&rew_hist.toroll_rew)
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
	// fmt.Println(rew_hist.fromroll_rew, "-----", rew_hist.toroll_rew)
	if rew_hist.fromroll_rew == 0 || rew_hist.toroll_rew == 0 {
		panic("participate in events to transfer money")
	}
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		mutex.Unlock()
		log.Fatal(err)
		return
	}

	query = db.QueryRow("SELECT batch FROM user WHERE rollno=$1", p.Fromrollno)
	if err != nil {
		panic(err)
	}
	var storedCoins struct {
		FromBatch string
		ToBatch   string
	}

	err = query.Scan(&storedCoins.FromBatch)

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

	query = db.QueryRow("SELECT batch FROM user WHERE rollno=$1", p.Torollno)
	err = query.Scan(&storedCoins.ToBatch)

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

	ra, err := tx.ExecContext(ctx, "UPDATE user SET coin=coin-$1 WHERE rollno=$2 AND coin - $1>=0", p.Coin, p.Fromrollno)
	if err != nil {
		mutex.Unlock()
		tx.Rollback()
		return
	}
	rAffect, err := ra.RowsAffected()

	if err != nil || rAffect == 0 {
		mutex.Unlock()
		tx.Rollback()
		return
	}
	if storedCoins.FromBatch == storedCoins.ToBatch {
		p.Coin = (p.Coin * 98) / 100
	} else {
		p.Coin = (p.Coin * 67) / 100
	}

	_, err = tx.ExecContext(ctx, "UPDATE user SET coin=coin+$1 WHERE rollno=$2", p.Coin, p.Torollno)
	if err != nil {
		mutex.Unlock()
		tx.Rollback()
		return
	}
	err = tx.Commit()
	mutex.Unlock()
	AddHistory(p.Fromrollno, p.Torollno, p.Coin, time.Now().Format("2006.01.02 15:04:05"), "transfer")
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
	defer db.Close()
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		log.Fatal(err)
		return
	}

	// if err != nil {
	// 	// If an entry with the username does not exist, send an "Unauthorized"(401) status
	// 	if err == sql.ErrNoRows {
	// 		w.WriteHeader(http.StatusUnauthorized)
	// 		return
	// 	}
	// 	// If the error is of any other type, send a 500 status
	// 	w.WriteHeader(http.StatusInternalServerError)
	// 	return
	// }

	_, err = tx.ExecContext(ctx, "UPDATE user SET coin=coin+$1 WHERE rollno=$2", p.Award, p.Rollno)
	if err != nil {
		tx.Rollback()
		return
	}
	err = tx.Commit()
	if err != nil {
		log.Fatal(err)
	}
	AddHistory(0, p.Rollno, p.Award, time.Now().Format("2006.01.02 15:04:05"), "reward")

}
func CheckCoin(RollNo int) int {
	db, err := sql.Open("sqlite3", "data.db")
	if err != nil {
		panic(err)
	}
	defer db.Close()
	query := db.QueryRow("SELECT coin FROM user WHERE rollno=$1", RollNo)
	if err != nil {
		panic(err)
	}
	var storedCoins struct {
		Coins int
	}

	err = query.Scan(&storedCoins.Coins)

	if err != nil {
		// If an entry with the username does not exist, send an "Unauthorized"(401) status
		if err == sql.ErrNoRows {
			panic(err)
		}
		// If the error is of any other type, send a 500 status
		panic(err)
	}
	return storedCoins.Coins
}
func ItemPrice(ItemId int) int {
	db, err := sql.Open("sqlite3", "item.db")
	if err != nil {
		panic(err)
	}
	defer db.Close()
	query := db.QueryRow("SELECT coin FROM item WHERE itemid=$1", ItemId)
	if err != nil {
		panic(err)
	}
	var itemCoins struct {
		Coins int
	}

	err = query.Scan(&itemCoins.Coins)

	if err != nil {
		// If an entry with the username does not exist, send an "Unauthorized"(401) status
		if err == sql.ErrNoRows {
			panic(err)
		}
		// If the error is of any other type, send a 500 status
		panic(err)
	}
	return itemCoins.Coins
}
func RedeemCoin(w http.ResponseWriter, r *http.Request) {

	var p RedeemCred

	err := json.NewDecoder(r.Body).Decode(&p)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	db, err := sql.Open("sqlite3", "redeem.db")
	if err != nil {
		panic(err)
	}
	defer db.Close()
	query, err := db.Prepare("CREATE TABLE IF NOT EXISTS redeem (redeemid INTEGER PRIMARY KEY NOT NULL AUTODeeeINCREMENT,rollno INTEGER NOT NULL, name TEXT NOT NULL,itemid INTEGER, status TEXT)")
	if err != nil {
		panic(err)
	}
	query.Exec()
	//check if user is applicable to redeem that prize
	if ItemPrice(p.ItemId) > CheckCoin(p.RollNo) {
		panic("not enough coin")
	}
	query, err = db.Prepare("INSERT INTO redeem (rollno, name, itemid,status) VALUES (?, ?, ?,?)")
	if err != nil {
		panic(err)
	}
	query.Exec(p.RollNo, p.Name, p.ItemId, "pending")

}
func RejectRedeem(w http.ResponseWriter, r *http.Request) {
	var p struct {
		RedeemId int
	}
	err := json.NewDecoder(r.Body).Decode(&p)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	db, err := sql.Open("sqlite3", "redeem.db")
	if err != nil {
		panic(err)
	}
	defer db.Close()
	_, err = db.Exec("UPDATE redeem SET status='rejected' WHERE redeemid=$1", p.RedeemId)
	if err != nil {
		panic(err)
	}

}
func ApproveRedeem(w http.ResponseWriter, r *http.Request) {
	var p struct {
		RedeemId int
	}
	err := json.NewDecoder(r.Body).Decode(&p)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	db, err := sql.Open("sqlite3", "redeem.db")
	if err != nil {
		panic(err)
	}
	defer db.Close()
	var storedCreds struct {
		RollNo int
		ItemId int
	}
	query := db.QueryRow("SELECT rollno FROM redeem WHERE redeemid=$1", p.RedeemId)
	err = query.Scan(&storedCreds.RollNo)

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

	query = db.QueryRow("SELECT itemid FROM redeem WHERE redeemid=$1", p.RedeemId)
	err = query.Scan(&storedCreds.ItemId)

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
	if CheckCoin(storedCreds.RollNo) < ItemPrice(storedCreds.ItemId) {
		panic(err)
	}
	db1, err := sql.Open("sqlite3", "data.db")
	if err != nil {
		panic(err)
	}
	defer db1.Close()
	ctx := context.Background()
	tx, err := db1.BeginTx(ctx, nil)
	if err != nil {
		log.Fatal(err)
		return
	}
	_, err = tx.ExecContext(ctx, "UPDATE user SET coin=coin-$1 WHERE rollno=$2", ItemPrice(storedCreds.ItemId), storedCreds.RollNo)
	if err != nil {
		tx.Rollback()
		return
	}
	err = tx.Commit()
	if err != nil {
		log.Fatal(err)
	}
	db2, err := sql.Open("sqlite3", "redeem.db")
	if err != nil {
		panic(err)
	}
	defer db2.Close()
	_, err = db.Exec("UPDATE redeem SET status='Approved' WHERE redeemid=$1", p.RedeemId)
	if err != nil {
		panic(err)
	}

}
func PendRedeemReq(w http.ResponseWriter, r *http.Request) {
	db, err := sql.Open("sqlite3", "redeem.db")
	if err != nil {
		panic(err)
	}
	defer db.Close()
	rows, err := db.Query("SELECT redeemid,rollno,itemid FROM redeem WHERE status='pending'")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer rows.Close()
	var PendingRequests []*PendReq
	for rows.Next() {
		c := new(PendReq)
		err := rows.Scan(&c.RedeemId, &c.RollNo, &c.ItemId)
		if err != nil {
			fmt.Println(err)
			return
		}
		PendingRequests = append(PendingRequests, c)
	}
	if err := rows.Err(); err != nil {
		fmt.Println(err)
		return
	}

	if err := json.NewEncoder(w).Encode(PendingRequests); err != nil {
		fmt.Println(err)
	}

}
func AddItem(w http.ResponseWriter, r *http.Request) {
	var p struct {
		ItemName  int
		ItemPrice int
	}
	err := json.NewDecoder(r.Body).Decode(&p)
	if err != nil {
		panic(err)
	}
	db, err := sql.Open("sqlite3", "item.db")
	if err != nil {
		panic(err)
	}
	defer db.Close()
	query, err := db.Prepare("CREATE TABLE IF NOT EXISTS item (itemid INTEGER PRIMARY KEY NOT NULL AUTOINCREMENT,itemname TEXT, coin INTEGER)")
	if err != nil {
		panic(err)
	}
	query.Exec()
	query, err = db.Prepare("INSERT INTO ITEM (itemname, coin) VALUES(?,?) ")
	if err != nil {
		panic(err)
	}
	query.Exec(p.ItemName, p.ItemPrice)

}

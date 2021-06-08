package myapp

type User struct {
	name     string
	rollno   int
	password string
}
type UserService interface {
	User(rollno int, password string)
	CreateUser(u *User) error
}

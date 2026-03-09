package main

import "errors"

func getUser() (string, error) {
	return "admin", errors.New("database connection failed")
}

func vulnerable() {
	// SOURCE: Function returns multiple values
	user, err := getUser()

	// SANITIZER ATTEMPT: We check the error...
	if err != nil {
		println("Warning: ", err)
		// BUG: We forgot to type 'return' here! This is a Fail-Open vulnerability.
	}

	// SINK: We use the user variable even though an error occurred!
	println("Access granted to:", user)
}

func main() {
	vulnerable()
}
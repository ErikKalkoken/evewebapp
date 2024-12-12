package model

import "golang.org/x/oauth2"

type User struct {
	ID    int
	Name  string
	Token oauth2.TokenSource
}

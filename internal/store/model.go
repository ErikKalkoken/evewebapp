package store

import "golang.org/x/oauth2"

type User struct {
	ID    int
	Name  string
	Token oauth2.TokenSource
}

type UserStore struct {
	data map[int]*User
}

func NewUserStore() *UserStore {
	s := &UserStore{
		data: make(map[int]*User),
	}
	return s
}

func (s *UserStore) Get(id int) *User {
	return s.data[id]
}

func (s *UserStore) Save(id int, name string, token oauth2.TokenSource) {
	u := &User{
		ID:    id,
		Name:  name,
		Token: token,
	}
	s.data[id] = u
}

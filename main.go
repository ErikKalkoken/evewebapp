package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
)

const (
	address      = "127.0.0.1:8000"
	callbackPath = "/sso/callback"
)

func main() {
	clientID := os.Getenv("EVE_SSO_CLIENT_ID")
	clientSecret := os.Getenv("EVE_SSO_CLIENT_SECRET")
	sessionKey := os.Getenv("SESSION_KEY")
	if clientID == "" || clientSecret == "" || sessionKey == "" {
		log.Fatal("SSO client ID and/or client secret not defined")
	}
	callbackURL := "http://" + address + callbackPath
	a := newApp(clientID, clientSecret, callbackURL, sessionKey)

	http.HandleFunc("/", a.index)
	http.HandleFunc("/sso/start", a.ssoStart)
	http.HandleFunc(callbackPath, a.ssoCallback)
	http.HandleFunc("/show-medals", a.showMedals)

	fmt.Printf("Running on http://%s\n", address)
	log.Fatal(http.ListenAndServe(address, nil))
}

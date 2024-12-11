package main

import (
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/joho/godotenv"
)

const (
	address      = "127.0.0.1:8000"
	callbackPath = "/sso/callback"
)

func main() {
	godotenv.Load() // reading from .env file is optional
	clientID := os.Getenv("EVE_CLIENT_ID")
	clientSecret := os.Getenv("EVE_CLIENT_SECRET")
	sessionKey := os.Getenv("SESSION_KEY")
	if clientID == "" || clientSecret == "" || sessionKey == "" {
		log.Fatal("SSO client ID, client secret or session key not defined")
	}
	callbackURL := "http://" + address + callbackPath
	a := newApp(clientID, clientSecret, callbackURL, sessionKey)

	http.HandleFunc("/", a.makeHandler(a.index))
	http.HandleFunc("/sso/start", a.makeHandler(a.ssoStart))
	http.HandleFunc(callbackPath, a.makeHandler(a.ssoCallback))
	http.HandleFunc("/show-medals", a.makeHandler(a.showMedals))

	go func() {
		slog.Info("Running", "address", "http://"+address)
		if err := http.ListenAndServe(address, nil); err != nil {
			log.Fatal("server aborted", "error", err)
		}
	}()

	// Ensure graceful shutdown
	sc := make(chan os.Signal, 1)
	signal.Notify(sc, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)
	<-sc
	slog.Info("shutdown complete")
}

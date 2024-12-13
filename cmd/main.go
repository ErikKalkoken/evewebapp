package main

import (
	"example/evewebapp/internal/app"
	"example/evewebapp/internal/store"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/joho/godotenv"
)

func main() {
	godotenv.Load() // reading from .env file is optional
	clientID := os.Getenv("EVE_CLIENT_ID")
	clientSecret := os.Getenv("EVE_CLIENT_SECRET")
	redirectURL := os.Getenv("EVE_REDIRECT_URL")
	sessionKey := os.Getenv("EVE_SESSION_KEY")
	if clientID == "" || clientSecret == "" || sessionKey == "" {
		log.Fatal("client ID, client secret, redirect URL or session key not defined")
	}
	userStore := store.NewUserStore()
	httpClient := &http.Client{Timeout: 5 * time.Second}
	server := app.New(clientID, clientSecret, redirectURL, sessionKey, userStore, httpClient)
	if err := server.Start(); err != nil {
		log.Fatal(err)
	}
}

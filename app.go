package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"

	"github.com/antihax/goesi"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
)

const (
	sessionName = "default"
)

type app struct {
	oauth     oauth2.Config
	esiClient *goesi.APIClient
	store     *sessions.CookieStore

	tokenSource   oauth2.TokenSource
	characterID   int
	characterName string
}

func newApp(clientID, clientSecret, callbackURL, sessionKey string) *app {
	a := &app{
		oauth: oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Scopes:       []string{"esi-characters.read_medals.v1"},
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://login.eveonline.com/v2/oauth/authorize",
				TokenURL: "https://login.eveonline.com/v2/oauth/token",
			},
			RedirectURL: callbackURL,
		},
		store:     sessions.NewCookieStore([]byte(sessionKey)),
		esiClient: goesi.NewAPIClient(http.DefaultClient, "info@example.com"),
	}
	return a
}

func (a *app) index(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, `<a href="/sso/start">Login</a>`)
}

func (a *app) ssoStart(w http.ResponseWriter, r *http.Request) {
	// Generate a random state string
	b := make([]byte, 16)
	rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b)
	// Store state in session
	session, _ := a.store.Get(r, sessionName)
	session.Values["state"] = state
	err := session.Save(r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Redirect to auth URL
	url := a.oauth.AuthCodeURL(state, oauth2.AccessTypeOffline)
	http.Redirect(w, r, url, 302)
}

func (a *app) ssoCallback(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	// get our code and state
	code := r.FormValue("code")
	state := r.FormValue("state")

	// Verify the state matches our randomly generated string from earlier.
	session, _ := a.store.Get(r, sessionName)
	if session.Values["state"] != state {
		http.Error(w, "invalid state", http.StatusInternalServerError)
		return
	}

	// Exchange the code for an Access and Refresh token.
	tok, err := a.oauth.Exchange(ctx, code)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// validate token
	token, err := validateJWT(ctx, tok.AccessToken)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Verify the token & extract character details
	a.characterID, a.characterName, err = extractCharacter(token)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	a.tokenSource = a.oauth.TokenSource(ctx, tok)
	http.Redirect(w, r, "/show-medals", 302)
}

func (a *app) showMedals(w http.ResponseWriter, r *http.Request) {
	ctx := context.WithValue(context.Background(), goesi.ContextOAuth2, a.tokenSource)
	medals, _, err := a.esiClient.ESI.CharacterApi.GetCharactersCharacterIdMedals(ctx, int32(a.characterID), nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fmt.Fprintf(w, "Medals for %s\n\n", a.characterName)
	if len(medals) == 0 {
		fmt.Fprintln(w, "No medals")
	} else {
		for _, m := range medals {
			fmt.Fprintf(w, "%s\n", m.Title)
		}
	}
}

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
	sessionName       = "default"
	oauthAuthorizeURL = "https://login.eveonline.com/v2/oauth/authorize"
	oauthTokenURL     = "https://login.eveonline.com/v2/oauth/token"
	userAgent         = "my-web-server info@example.com"
)

var oauthScopes = []string{"esi-characters.read_medals.v1"}

type app struct {
	oauth     oauth2.Config
	esiClient *goesi.APIClient
	store     *sessions.CookieStore

	tokens     map[int]oauth2.TokenSource
	characters map[int]string
}

func newApp(clientID, clientSecret, callbackURL, sessionKey string) *app {
	a := &app{
		oauth: oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Scopes:       oauthScopes,
			Endpoint: oauth2.Endpoint{
				AuthURL:  oauthAuthorizeURL,
				TokenURL: oauthTokenURL,
			},
			RedirectURL: callbackURL,
		},
		store:      sessions.NewCookieStore([]byte(sessionKey)),
		esiClient:  goesi.NewAPIClient(http.DefaultClient, userAgent),
		tokens:     make(map[int]oauth2.TokenSource),
		characters: make(map[int]string),
	}
	return a
}

// makeHandler decorates our handlers with the current session.
func (a *app) makeHandler(fn func(http.ResponseWriter, *http.Request, *sessions.Session)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, _ := a.store.Get(r, sessionName)
		fn(w, r, session)
	}
}

func (a *app) index(w http.ResponseWriter, r *http.Request, s *sessions.Session) {
	fmt.Fprint(w, `<a href="/sso/start">Login</a>`)
}

func (a *app) ssoStart(w http.ResponseWriter, r *http.Request, s *sessions.Session) {
	// Generate a random state string
	b := make([]byte, 16)
	rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b)
	// Store state in session
	s.Values["state"] = state
	if err := s.Save(r, w); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Redirect to auth URL
	url := a.oauth.AuthCodeURL(state, oauth2.AccessTypeOffline)
	http.Redirect(w, r, url, 302)
}

func (a *app) ssoCallback(w http.ResponseWriter, r *http.Request, s *sessions.Session) {
	ctx := context.Background()

	// get our code and state
	code := r.FormValue("code")
	state := r.FormValue("state")

	// Verify the state matches our randomly generated string from earlier.
	if s.Values["state"] != state {
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
	characterID, characterName, err := extractCharacter(token)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	a.characters[characterID] = characterName
	a.tokens[characterID] = a.oauth.TokenSource(ctx, tok)
	s.Values["characterID"] = characterID
	if err := s.Save(r, w); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/show-medals", 302)
}

func (a *app) showMedals(w http.ResponseWriter, r *http.Request, s *sessions.Session) {
	characterID, ok := s.Values["characterID"].(int)
	if !ok {
		http.Error(w, "not logged in", http.StatusUnauthorized)
		return
	}
	token, ok := a.tokens[characterID]
	if !ok {
		http.Error(w, "token not found", http.StatusInternalServerError)
		return
	}
	ctx := context.WithValue(context.Background(), goesi.ContextOAuth2, token)
	medals, _, err := a.esiClient.ESI.CharacterApi.GetCharactersCharacterIdMedals(ctx, int32(characterID), nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fmt.Fprintf(w, "Medals for %s\n\n", a.characters[characterID])
	if len(medals) == 0 {
		fmt.Fprintln(w, "No medals")
	} else {
		for _, m := range medals {
			fmt.Fprintf(w, "%s\n", m.Title)
		}
	}
}

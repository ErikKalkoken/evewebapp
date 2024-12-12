package handler

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"example/evewebapp/components"
	"example/evewebapp/model"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/antihax/goesi"
	"github.com/antihax/goesi/esi"
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

type Handler struct {
	oauth     oauth2.Config
	esiClient *goesi.APIClient
	store     *sessions.CookieStore

	users map[int]*model.User
}

func NewHandler(clientID, clientSecret, callbackURL, sessionKey string) (*Handler, error) {
	a := &Handler{
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
		store:     sessions.NewCookieStore([]byte(sessionKey)),
		esiClient: goesi.NewAPIClient(http.DefaultClient, userAgent),
		users:     make(map[int]*model.User),
	}
	return a, nil
}

func (a *Handler) RootHandler() http.Handler {
	router := http.NewServeMux()
	router.HandleFunc("/", a.makeHandler(a.home))
	router.HandleFunc("/sso/start", a.makeHandler(a.ssoStart))
	router.HandleFunc("/sso/callback", a.makeHandler(a.ssoCallback))
	router.HandleFunc("/sso/logout", a.makeHandler(a.ssoLogout))
	router.HandleFunc("/medals", a.makeHandler(a.showMedals))
	return router
}

// makeHandler converts our custom handlers so we can add sessions and handle errors better.
func (a *Handler) makeHandler(fn func(http.ResponseWriter, *http.Request, *sessions.Session) (int, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s, _ := a.store.Get(r, sessionName)
		status, err := fn(w, r, s)
		if err != nil {
			slog.Error("request failed", "error", err)
			http.Error(w, err.Error(), status)
		} else {
			slog.Info("request", "status", status, "path", r.URL.Path)
		}
	}
}

func (a *Handler) home(w http.ResponseWriter, r *http.Request, s *sessions.Session) (int, error) {
	user := a.currentUser(s)
	err := components.Home(user).Render(context.Background(), w)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	return http.StatusOK, nil
}

func (a *Handler) currentUser(s *sessions.Session) *model.User {
	x, ok := s.Values["characterID"]
	if !ok {
		return nil
	}
	id, ok := x.(int)
	if !ok {
		return nil
	}
	user, ok := a.users[id]
	if !ok {
		return nil
	}
	return user
}

func (a *Handler) ssoStart(w http.ResponseWriter, r *http.Request, s *sessions.Session) (int, error) {
	// Generate a random state string
	b := make([]byte, 16)
	rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b)
	// Store state in session
	s.Values["state"] = state
	if err := s.Save(r, w); err != nil {
		return http.StatusInternalServerError, err
	}
	// Redirect to auth URL
	url := a.oauth.AuthCodeURL(state, oauth2.AccessTypeOffline)
	http.Redirect(w, r, url, http.StatusFound)
	return http.StatusFound, nil
}

func (a *Handler) ssoCallback(w http.ResponseWriter, r *http.Request, s *sessions.Session) (int, error) {
	ctx := context.Background()

	// get our code and state
	code := r.FormValue("code")
	state := r.FormValue("state")

	// Verify the state matches our randomly generated string from earlier.
	if s.Values["state"] != state {
		return http.StatusUnauthorized, fmt.Errorf("invalid state")
	}

	// Exchange the code for an Access and Refresh token.
	tok, err := a.oauth.Exchange(ctx, code)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	// validate token
	token, err := validateJWT(ctx, tok.AccessToken)
	if err != nil {
		return http.StatusUnauthorized, err
	}

	// Verify the token & extract character details
	characterID, characterName, err := extractCharacter(token)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	u := &model.User{ID: characterID, Name: characterName, Token: a.oauth.TokenSource(ctx, tok)}
	a.users[characterID] = u
	s.Values["characterID"] = characterID
	if err := s.Save(r, w); err != nil {
		return http.StatusInternalServerError, err
	}
	http.Redirect(w, r, "/medals", http.StatusFound)
	return http.StatusFound, nil
}

func (a *Handler) ssoLogout(w http.ResponseWriter, r *http.Request, s *sessions.Session) (int, error) {
	s.Values["characterID"] = 0
	if err := s.Save(r, w); err != nil {
		return http.StatusInternalServerError, err
	}
	http.Redirect(w, r, "/", 302)
	return http.StatusFound, nil
}

func (a *Handler) showMedals(w http.ResponseWriter, r *http.Request, s *sessions.Session) (int, error) {
	user := a.currentUser(s)
	var err error
	var medals []esi.GetCharactersCharacterIdMedals200Ok
	if user != nil {
		ctx := context.WithValue(context.Background(), goesi.ContextOAuth2, user.Token)
		medals, _, err = a.esiClient.ESI.CharacterApi.GetCharactersCharacterIdMedals(ctx, int32(user.ID), nil)
		if err != nil {
			return http.StatusInternalServerError, err
		}
	}
	if err := components.Medals(user, medals).Render(context.Background(), w); err != nil {
		return http.StatusInternalServerError, err
	}
	return http.StatusOK, nil
}

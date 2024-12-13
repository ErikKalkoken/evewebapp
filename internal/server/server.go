package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"example/evewebapp/internal/store"
	"example/evewebapp/internal/templates"
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

type Server struct {
	oauth       oauth2.Config
	esiClient   *goesi.APIClient
	cookieStore *sessions.CookieStore

	userStore *store.UserStore
}

func New(clientID, clientSecret, callbackURL, sessionKey string) (*Server, error) {
	a := &Server{
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
		cookieStore: sessions.NewCookieStore([]byte(sessionKey)),
		esiClient:   goesi.NewAPIClient(http.DefaultClient, userAgent),
		userStore:   store.NewUserStore(),
	}
	return a, nil
}

func (a *Server) RootHandler() http.Handler {
	router := http.NewServeMux()
	router.HandleFunc("/", a.makeHandler(a.home))
	router.HandleFunc("/sso/start", a.makeHandler(a.ssoStart))
	router.HandleFunc("/sso/callback", a.makeHandler(a.ssoCallback))
	router.HandleFunc("/sso/logout", a.makeHandler(a.ssoLogout))
	router.HandleFunc("/medals", a.makeHandler(a.showMedals))
	return router
}

// makeHandler converts our custom handlers so we can add sessions and handle errors better.
func (a *Server) makeHandler(fn func(http.ResponseWriter, *http.Request, *sessions.Session) (int, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s, _ := a.cookieStore.Get(r, sessionName)
		status, err := fn(w, r, s)
		if err != nil {
			slog.Error("request failed", "error", err)
			http.Error(w, err.Error(), status)
		} else {
			slog.Info("request", "status", status, "path", r.URL.Path)
		}
	}
}

func (a *Server) home(w http.ResponseWriter, r *http.Request, s *sessions.Session) (int, error) {
	user := a.currentUser(s)
	err := templates.Home(user).Render(context.Background(), w)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	return http.StatusOK, nil
}

func (a *Server) currentUser(s *sessions.Session) *store.User {
	x, ok := s.Values["characterID"]
	if !ok {
		return nil
	}
	id, ok := x.(int)
	if !ok {
		return nil
	}
	return a.userStore.Get(id)
}

func (a *Server) ssoStart(w http.ResponseWriter, r *http.Request, s *sessions.Session) (int, error) {
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

func (a *Server) ssoCallback(w http.ResponseWriter, r *http.Request, s *sessions.Session) (int, error) {
	// get our code and state
	code := r.FormValue("code")
	state := r.FormValue("state")

	// Verify the state matches our randomly generated string from earlier.
	if s.Values["state"] != state {
		return http.StatusUnauthorized, fmt.Errorf("invalid state")
	}

	// Exchange the code for an Access and Refresh token.
	tok, err := a.oauth.Exchange(r.Context(), code)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	// validate token
	token, err := validateJWT(r.Context(), tok.AccessToken)
	if err != nil {
		return http.StatusUnauthorized, err
	}

	// Verify the token & extract character details
	characterID, characterName, err := extractCharacter(token)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	a.userStore.Save(characterID, characterName, a.oauth.TokenSource(r.Context(), tok))
	s.Values["characterID"] = characterID
	if err := s.Save(r, w); err != nil {
		return http.StatusInternalServerError, err
	}
	http.Redirect(w, r, "/medals", http.StatusFound)
	return http.StatusFound, nil
}

func (a *Server) ssoLogout(w http.ResponseWriter, r *http.Request, s *sessions.Session) (int, error) {
	s.Values["characterID"] = 0
	if err := s.Save(r, w); err != nil {
		return http.StatusInternalServerError, err
	}
	http.Redirect(w, r, "/", 302)
	return http.StatusFound, nil
}

func (a *Server) showMedals(w http.ResponseWriter, r *http.Request, s *sessions.Session) (int, error) {
	user := a.currentUser(s)
	var err error
	var medals []esi.GetCharactersCharacterIdMedals200Ok
	if user != nil {
		ctx := context.WithValue(r.Context(), goesi.ContextOAuth2, user.Token)
		medals, _, err = a.esiClient.ESI.CharacterApi.GetCharactersCharacterIdMedals(ctx, int32(user.ID), nil)
		if err != nil {
			return http.StatusInternalServerError, err
		}
	}
	if err := templates.Medals(user, medals).Render(context.Background(), w); err != nil {
		return http.StatusInternalServerError, err
	}
	return http.StatusOK, nil
}

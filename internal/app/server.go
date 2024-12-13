package app

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"example/evewebapp/internal/store"
	"example/evewebapp/internal/templates"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/antihax/goesi"
	"github.com/antihax/goesi/esi"
	"github.com/gorilla/sessions"
)

const (
	address = "127.0.0.1:8000"
)

const (
	sessionName = "default"
	userAgent   = "my-web-server info@example.com"
)

var oauthScopes = []string{"esi-characters.read_medals.v1"}

type Server struct {
	cookieStore *sessions.CookieStore
	esiClient   *goesi.APIClient
	httpServer  *http.Server
	ssoAuth     *goesi.SSOAuthenticator
	userStore   *store.UserStore
}

func New(clientID, clientSecret, redirectURL, sessionKey string, userStore *store.UserStore, httpClient *http.Client) *Server {
	s := &Server{
		cookieStore: sessions.NewCookieStore([]byte(sessionKey)),
		esiClient:   goesi.NewAPIClient(httpClient, userAgent),
		ssoAuth:     goesi.NewSSOAuthenticatorV2(httpClient, clientID, clientSecret, redirectURL, oauthScopes),
		userStore:   userStore,
	}
	return s
}

func (s *Server) Start() error {
	router := http.NewServeMux()
	router.HandleFunc("/", s.makeHandler(s.home))
	router.HandleFunc("/sso/start", s.makeHandler(s.ssoStart))
	router.HandleFunc("/sso/callback", s.makeHandler(s.ssoCallback))
	router.HandleFunc("/sso/logout", s.makeHandler(s.ssoLogout))
	router.HandleFunc("/medals", s.makeHandler(s.showMedals))
	s.httpServer = &http.Server{
		Addr:    address,
		Handler: router,
	}
	go func() {
		slog.Info("Running", "address", "http://"+address)
		if err := s.httpServer.ListenAndServe(); err != nil {
			log.Fatal("server aborted", "error", err)
		}
	}()

	// Ensure graceful shutdown
	sc := make(chan os.Signal, 1)
	signal.Notify(sc, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)
	<-sc
	slog.Info("shutdown complete")
	return nil
}

// makeHandler converts our custom handlers so we can add sessions and handle errors better.
func (s *Server) makeHandler(fn func(http.ResponseWriter, *http.Request, *sessions.Session) (int, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, _ := s.cookieStore.Get(r, sessionName)
		status, err := fn(w, r, session)
		if err != nil {
			slog.Error("request failed", "error", err)
			http.Error(w, err.Error(), status)
		} else {
			slog.Info("request", "status", status, "path", r.URL.Path)
		}
	}
}

func (s *Server) home(w http.ResponseWriter, r *http.Request, session *sessions.Session) (int, error) {
	user := s.currentUser(session)
	err := templates.Home(user).Render(context.Background(), w)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	return http.StatusOK, nil
}

func (s *Server) currentUser(session *sessions.Session) *store.User {
	x, ok := session.Values["characterID"]
	if !ok {
		return nil
	}
	id, ok := x.(int)
	if !ok {
		return nil
	}
	return s.userStore.Get(id)
}

func (s *Server) ssoStart(w http.ResponseWriter, r *http.Request, session *sessions.Session) (int, error) {
	// Generate a random state string
	b := make([]byte, 16)
	rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b)
	// Store state in session
	session.Values["state"] = state
	if err := session.Save(r, w); err != nil {
		return http.StatusInternalServerError, err
	}
	// Redirect to auth URL
	url := s.ssoAuth.AuthorizeURL(state, false, oauthScopes)
	http.Redirect(w, r, url, http.StatusFound)
	return http.StatusFound, nil
}

func (s *Server) ssoCallback(w http.ResponseWriter, r *http.Request, session *sessions.Session) (int, error) {
	// get our code and state
	code := r.FormValue("code")
	state := r.FormValue("state")

	// Verify the state matches our randomly generated string from earlier.
	if session.Values["state"] != state {
		return http.StatusUnauthorized, fmt.Errorf("invalid state")
	}

	// Exchange the code for an Access and Refresh token.
	tok, err := s.ssoAuth.TokenExchange(code)
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
	s.userStore.Save(characterID, characterName, s.ssoAuth.TokenSource(tok))
	session.Values["characterID"] = characterID
	if err := session.Save(r, w); err != nil {
		return http.StatusInternalServerError, err
	}
	http.Redirect(w, r, "/medals", http.StatusFound)
	return http.StatusFound, nil
}

func (s *Server) ssoLogout(w http.ResponseWriter, r *http.Request, session *sessions.Session) (int, error) {
	session.Values["characterID"] = 0
	if err := session.Save(r, w); err != nil {
		return http.StatusInternalServerError, err
	}
	http.Redirect(w, r, "/", 302)
	return http.StatusFound, nil
}

func (s *Server) showMedals(w http.ResponseWriter, r *http.Request, session *sessions.Session) (int, error) {
	user := s.currentUser(session)
	var err error
	var medals []esi.GetCharactersCharacterIdMedals200Ok
	if user != nil {
		ctx := context.WithValue(r.Context(), goesi.ContextOAuth2, user.Token)
		medals, _, err = s.esiClient.ESI.CharacterApi.GetCharactersCharacterIdMedals(ctx, int32(user.ID), nil)
		if err != nil {
			return http.StatusInternalServerError, err
		}
	}
	if err := templates.Medals(user, medals).Render(context.Background(), w); err != nil {
		return http.StatusInternalServerError, err
	}
	return http.StatusOK, nil
}

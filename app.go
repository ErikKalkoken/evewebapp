package main

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"text/template"

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

var (
	//go:embed templates/*
	templatesFS embed.FS
)

type app struct {
	oauth     oauth2.Config
	esiClient *goesi.APIClient
	store     *sessions.CookieStore
	templates map[string]*template.Template

	tokens     map[int]oauth2.TokenSource
	characters map[int]string
}

func newApp(clientID, clientSecret, callbackURL, sessionKey string) (*app, error) {
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
		templates:  make(map[string]*template.Template),
	}
	if err := a.loadTemplates(); err != nil {
		return nil, fmt.Errorf("loading templates: %w", err)
	}
	return a, nil
}

// LoadTemplates loads and parses all html templates.
func (a *app) loadTemplates() error {
	files, err := fs.ReadDir(templatesFS, "templates")
	if err != nil {
		return err
	}
	for _, f := range files {
		if f.IsDir() {
			continue
		}
		t, err := template.ParseFS(templatesFS, "templates/"+f.Name(), "templates/base.html")
		if err != nil {
			return err
		}
		a.templates[f.Name()] = t
	}
	return nil
}

func (a *app) rootHandler() http.Handler {
	router := http.NewServeMux()
	router.HandleFunc("/", a.makeHandler(a.index))
	router.HandleFunc("/sso/start", a.makeHandler(a.ssoStart))
	router.HandleFunc(callbackPath, a.makeHandler(a.ssoCallback))
	router.HandleFunc("/show-medals", a.makeHandler(a.showMedals))
	return router
}

// makeHandler converts our custom handlers so we can add sessions and handle errors better.
func (a *app) makeHandler(fn func(http.ResponseWriter, *http.Request, *sessions.Session) (int, error)) http.HandlerFunc {
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

func (a *app) index(w http.ResponseWriter, r *http.Request, s *sessions.Session) (int, error) {
	t, ok := a.templates["index.html"]
	if !ok {
		return http.StatusInternalServerError, fmt.Errorf("index.html")
	}
	t.Execute(w, nil)
	return http.StatusOK, nil
}

func (a *app) ssoStart(w http.ResponseWriter, r *http.Request, s *sessions.Session) (int, error) {
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

func (a *app) ssoCallback(w http.ResponseWriter, r *http.Request, s *sessions.Session) (int, error) {
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
	a.characters[characterID] = characterName
	a.tokens[characterID] = a.oauth.TokenSource(ctx, tok)
	s.Values["characterID"] = characterID
	if err := s.Save(r, w); err != nil {
		return http.StatusInternalServerError, err
	}
	http.Redirect(w, r, "/show-medals", 302)
	return http.StatusFound, nil
}

func (a *app) showMedals(w http.ResponseWriter, r *http.Request, s *sessions.Session) (int, error) {
	characterID, ok := s.Values["characterID"].(int)
	if !ok {
		return http.StatusUnauthorized, fmt.Errorf("not logged int")
	}
	token, ok := a.tokens[characterID]
	if !ok {
		return http.StatusInternalServerError, fmt.Errorf("token not found")
	}
	ctx := context.WithValue(context.Background(), goesi.ContextOAuth2, token)
	medals, _, err := a.esiClient.ESI.CharacterApi.GetCharactersCharacterIdMedals(ctx, int32(characterID), nil)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	data := struct {
		Character string
		Medals    []esi.GetCharactersCharacterIdMedals200Ok
	}{
		a.characters[characterID],
		medals,
	}
	t, ok := a.templates["medals.html"]
	if !ok {
		return http.StatusInternalServerError, fmt.Errorf("medals.html")
	}
	t.Execute(w, data)
	return http.StatusOK, nil
}

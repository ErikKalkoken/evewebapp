package app

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// validateJWT validates an SSO access token and returns it's the character ID and name.
func validateJWT(ctx context.Context, accessToken string) (jwt.Token, error) {
	// fetch the JWK set
	set, err := jwk.Fetch(ctx, "https://login.eveonline.com/oauth/jwks")
	if err != nil {
		return nil, err
	}
	// validate token
	return jwt.ParseString(
		accessToken,
		jwt.WithKeySet(set),
		jwt.WithAudience("EVE Online"),
		jwt.WithValidator(jwt.ValidatorFunc(func(ctx context.Context, t jwt.Token) jwt.ValidationError {
			if x := t.Issuer(); x != "login.eveonline.com" && x != "https://login.eveonline.com" {
				return jwt.NewValidationError(fmt.Errorf("invalid issuer"))
			}
			return nil
		})),
	)
}

func extractCharacter(token jwt.Token) (int, string, error) {
	// extract character ID
	p := strings.Split(token.Subject(), ":")
	if len(p) != 3 || p[0] != "CHARACTER" || p[1] != "EVE" {
		return 0, "", fmt.Errorf("invalid subject")
	}
	id, err := strconv.Atoi(p[2])
	if err != nil {
		return 0, "", err
	}
	// extract character name
	name, _ := token.Get("name")
	return id, name.(string), nil
}

package auth

import (
	"errors"
	"strings"
)

// Scopes are the user scopes
type Scopes []string

// ToString transforms Scopes into a string separated by a ' '
func (s Scopes) ToString() string {
	return strings.Join(s, " ")
}

// Credentials data to identify an user
type Credentials struct {
	Id       string
	Password string
	Grant    string
}

const PasswordCredentials = "password_credentials"
const ClientCredentials = "client_credentials"

const GrantTypeHeader = "GRANT-TYPE"
const AuthorizationHeader = "Authorization"

// Authorizer should try to authorize an user/client using the provided credentials.
//It returns an error if something went wrong
type Authorizer func(uc Credentials) error

// ScopeProvider retrieves, from the requested scopes, the ones that are actually granted for the user
type ScopeProvider func(uc Credentials, requested Scopes) (Scopes, error)

// ClientValidator checks if the given credentials are allowed to have access to the client
type ClientValidator func(credentials Credentials, clientId string) (bool, error)

// TokenServer is an Abstraction to authorize and generate credentials for a token base auth system
type TokenServer interface {
	Authorize(credentials Credentials, scopes Scopes, aud string) (*TokenCredentials, error)
	Refresh(refreshToken string, scopes Scopes) (*TokenCredentials, error)
	AccessToken(refreshToken string, scopes Scopes) (string, error)
}

type authServer struct {
	authorizers map[string]Authorizer
	signer      TokenSigner
	sProvider   ScopeProvider
	cValidator  ClientValidator
}

// TokenCredentials access_token + refresh_token (signed)
type TokenCredentials struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// NewTokenServer retrieves a TokenServer
func NewTokenServer(authorizers map[string]Authorizer,
	signer TokenSigner, scopes ScopeProvider, clients ClientValidator) TokenServer {
	return &authServer{authorizers: authorizers,
		signer:     signer,
		sProvider:  scopes,
		cValidator: clients}
}

// Authorize attempts to authorize a requester using its credentials. And retrieves a set of TokenCredentials
// credentials: requester credentials
// scopes: requested scopes
// aud: the resource server ID the requester wants to access
func (as *authServer) Authorize(credentials Credentials, scopes Scopes, aud string) (*TokenCredentials, error) {
	authorizer, ok := as.authorizers[credentials.Grant]
	if !ok {
		return nil, InvalidGrant(errors.New("invalid grant type"))
	}
	err := authorizer(credentials)
	if err != nil {
		return nil, err
	}

	err = as.checkAudience(aud, credentials)
	if err != nil {
		return nil, err
	}

	s, err := as.sProvider(credentials, scopes)
	if err != nil {
		return nil, err
	}

	return as.createCredentials(credentials.Id, s, credentials.Grant, aud)
}

// Authorize attempts to authorize a requester using its credentials. And retrieves a set of TokenCredentials
// credentials: requester credentials
// scopes: requested scopes
// aud: the resource server ID the requester wants to access
func (as *authServer) Refresh(refreshToken string, scopes Scopes) (*TokenCredentials, error) {
	c, aud, err := as.parseRefreshToken(refreshToken)
	if err != nil {
		return nil, err
	}

	s, err := as.sProvider(*c, scopes)
	if err != nil {
		return nil, err
	}

	return as.createCredentials(c.Id, s, c.Grant, aud)
}

func (as *authServer) AccessToken(refreshToken string, scopes Scopes) (string, error) {
	c, aud, err := as.parseRefreshToken(refreshToken)
	if err != nil {
		return "", err
	}

	s, err := as.sProvider(*c, scopes)
	if err != nil {
		return "", err
	}

	return as.signer.GetAccessToken(c.Id, s, c.Grant, aud)
}

func (as *authServer) createCredentials(senderId string, scopes Scopes, grantType string, aud string) (*TokenCredentials, error) {
	accessToken, err := as.signer.GetAccessToken(senderId, scopes, grantType, aud)
	if err != nil {
		return nil, err
	}

	refreshToken, err := as.signer.GetRefreshToken(senderId, grantType, aud)
	if err != nil {
		return nil, err
	}

	return &TokenCredentials{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (as *authServer) checkAudience(aud string, credentials Credentials) error {
	audCheck, err := as.cValidator(credentials, aud)
	if err != nil {
		return Unexpected(errors.New("invalid grant type"))
	}
	if !audCheck {
		return UnknownAudience(errors.New("unknown audience provided"))
	}
	return nil
}

func (as *authServer) parseRefreshToken(token string) (*Credentials, string, error) {
	claims, err := as.signer.ParseToken(token)
	if err != nil {
		return nil, "", err
	}

	reqScope := strings.Split(claims["scope"].(string), " ")
	if !checkRefreshScope(reqScope) {
		return nil, "", InvalidToken(errors.New("missing scope"))
	}

	gType := claims["grant_type"].(string)
	aud := claims["aud"].(string)
	id := claims["sub"].(string)

	return &Credentials{Id: id, Grant: gType}, aud, nil
}

func checkRefreshScope(scopes []string) bool {
	for _, s := range scopes {
		if s == RefreshTokenScope {
			return true
		}
	}
	return false
}

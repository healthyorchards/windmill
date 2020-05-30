package auth

import (
	"errors"
	"strings"
)

type Scopes string

func (s Scopes) list() []string {
	return strings.Split(string(s), " ")
}

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

// ScopeProvider retrieves a the Scopes ro a given user
type ScopeProvider func(uc Credentials) (Scopes, error)

// ClientValidator checks if the given credentials are allowed to have access to the client
type ClientValidator func(credentials Credentials, clientId string) (bool, error)

type AuthorizationService interface {
	Authorize(credentials Credentials, scope []string, aud string) (*TokenCredentials, error)
	Refresh(credentials Credentials, scope []string, aud string) (*TokenCredentials, error)
	AccessToken(credentials Credentials, scope []string, aud string) (string, error)
}
type authorizationService struct {
	authorizers map[string]Authorizer
	signer      TokenSigner
	sProvider   ScopeProvider
	cValidator  ClientValidator
}

type TokenCredentials struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func NewAuthService(authorizers map[string]Authorizer,
	signer TokenSigner, scopes ScopeProvider, clients ClientValidator) AuthorizationService {
	return &authorizationService{authorizers: authorizers,
		signer:     signer,
		sProvider:  scopes,
		cValidator: clients}
}

func (as *authorizationService) Authorize(credentials Credentials, scope []string, aud string) (*TokenCredentials, error) {
	authorizer, ok := as.authorizers[credentials.Grant]
	if !ok {
		return nil, InvalidGrant(errors.New("invalid grant type"))
	}
	err := as.checkAudience(aud, credentials)
	if err != nil {
		return nil, err
	}
	err = authorizer(credentials)
	if err != nil {
		return nil, err
	}

	s, err := as.sProvider(credentials)
	if err != nil {
		return nil, err
	}

	return as.createCredentials(credentials.Id, getCuratedScopes(scope, s.list()), credentials.Grant, aud)
}

func (as *authorizationService) Refresh(credentials Credentials, scope []string, aud string) (*TokenCredentials, error) {
	s, err := as.sProvider(credentials)
	if err != nil {
		return nil, err
	}

	return as.createCredentials(credentials.Id, getCuratedScopes(scope, s.list()), credentials.Grant, aud)
}

func (as *authorizationService) AccessToken(credentials Credentials, scope []string, aud string) (string, error) {
	s, err := as.sProvider(credentials)
	if err != nil {
		return "", err
	}
	return as.signer.GetAccessToken(credentials.Id, getCuratedScopes(scope, s.list()), credentials.Grant, aud)
}

func (as *authorizationService) createCredentials(senderId string, scopes Scopes, grantType string, aud string) (*TokenCredentials, error) {
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

func (as *authorizationService) checkAudience(aud string, credentials Credentials) error {
	audCheck, err := as.cValidator(credentials, aud)
	if err != nil {
		return Unexpected(errors.New("invalid grant type"))
	}
	if !audCheck {
		return UnkownAud(errors.New("unknown audience provided"))
	}
	return nil
}

func getCuratedScopes(requestedScopes []string, grantedScopes []string) Scopes {
	s := map[string]bool{}
	for _, item := range grantedScopes {
		s[item] = true
	}
	var sb strings.Builder
	for _, item := range requestedScopes {
		if _, ok := s[item]; ok {
			sb.WriteString(item)
			sb.WriteString(" ")
		}
	}
	return Scopes(strings.TrimSpace(sb.String()))
}

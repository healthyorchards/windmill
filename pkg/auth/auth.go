package auth

import (
	"errors"
	"github.com/healthyorchards/windmill/pkg/auth/keys"
	"strings"
)

// Scopes is a mechanism in OAuth 2.0 to limit an application's access to a user's account.
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

// TokenCredentials access_token + refresh_token (signed)
type TokenCredentials struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// TokenServer is an Abstraction to authorize and generate credentials for a token base auth system
type TokenServer interface {
	Authorize(credentials Credentials, scopes Scopes, aud string) (*TokenCredentials, error)
	Refresh(refreshToken string, scopes Scopes) (*TokenCredentials, error)
	AccessToken(refreshToken string, scopes Scopes) (string, error)
	GetEncodedPubKey() string
}

// TokenServerConfig parameters needed to invoke NewTokenServer
type TokenServerConfig struct {
	Authorizers     map[string]Authorizer
	Signer          TokenSigner
	ScopesProvider  ScopeProvider
	ClientValidator ClientValidator
	ClaimProvider   ClaimProvider
}

type authServer struct {
	authorizers map[string]Authorizer
	signer      TokenSigner
	sProvider   ScopeProvider
	cValidator  ClientValidator
	cProvider   ClaimProvider
	pubKey      string
}

// NewTokenServer retrieves a TokenServer
func NewTokenServer(c *TokenServerConfig) (TokenServer, error) {
	cp := c.ClaimProvider
	if cp == nil {
		emtpy := []Claim{}
		cp = func(identifier string, aud string) ([]Claim, error) {
			return emtpy, nil
		}
	}
	pubKey := c.Signer.GetSigningKey()
	encodedKey, err := keys.PemEncodePublicKey(&pubKey.PublicKey)
	if err != nil {
		return nil, err
	}
	return &authServer{authorizers: c.Authorizers,
		signer:     c.Signer,
		sProvider:  c.ScopesProvider,
		cValidator: c.ClientValidator,
		cProvider:  cp,
		pubKey:     encodedKey,
	}, nil
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

// Refresh given a refresh token attempts to generate a new set of TokenCredentials
// scopes: requested scopes
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

// AccessToken given a refresh token attempts to generate ONLY a new Access Token
// scopes: requested scopes
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

// GetEncodedPubKey retrieves a pem encoded string with the pub key of the server
func (as *authServer) GetEncodedPubKey() string {
	return as.pubKey
}

func (as *authServer) createCredentials(senderId string, scopes Scopes, grantType string, aud string) (*TokenCredentials, error) {
	additionalClaims, err := as.cProvider(senderId, aud)
	if err != nil {
		return nil, err
	}

	accessToken, err := as.signer.GetAccessToken(senderId, scopes, grantType, aud, additionalClaims...)
	if err != nil {
		return nil, err
	}

	refreshToken, err := as.signer.GetRefreshToken(senderId, grantType, aud, additionalClaims...)
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

package auth

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"time"
)

// Claim to add in the token
type Claim struct {
	Key   string
	Value interface{}
}

// ClaimProvider provides additional claims for a given user and audience
type ClaimProvider func(identifier string, aud string) ([]Claim, error)

type tokenClaims struct {
	UserId    string
	Scopes    string
	Exp       time.Duration
	GrantType string
	Aud       string
}

// TokenSigner abstraction to handle token creation
type TokenSigner interface {
	GetAccessToken(userId string, scopes Scopes, grantType string, aud string, claims ...Claim) (string, error)
	GetRefreshToken(userId string, grantType string, aud string, claims ...Claim) (string, error)
	ParseToken(token string) (jwt.MapClaims, error)
	GetSigningKey() ecdsa.PrivateKey
}

type tokenSigner struct {
	privateKey           *ecdsa.PrivateKey
	accessTokenDuration  time.Duration
	refreshTokenDuration time.Duration
	externalId           string
}

// SignerConfig configuration for a new TokenSigner
type SignerConfig struct {
	SigningKey         *ecdsa.PrivateKey
	AccessTknDuration  time.Duration
	RefreshTknDuration time.Duration
	SignerIdentifier   string
}

// NewTokenSigner return an instance of TokenSigner
func NewTokenSigner(c *SignerConfig) TokenSigner {
	return &tokenSigner{
		privateKey:           c.SigningKey,
		accessTokenDuration:  c.AccessTknDuration,
		refreshTokenDuration: c.RefreshTknDuration,
		externalId:           c.SignerIdentifier}
}

const RefreshTokenScope = "auth/refresh"

// GetAccessToken generates a signed access_token
func (ts *tokenSigner) GetAccessToken(userId string, scopes Scopes, grantType string, aud string, claims ...Claim) (string, error) {
	return ts.signToken(&tokenClaims{
		UserId:    userId,
		Scopes:    scopes.ToString(),
		Exp:       ts.accessTokenDuration,
		GrantType: grantType,
		Aud:       ts.getAudience(aud)}, claims)
}

// GetRefreshToken generates a signed refresh_token
func (ts *tokenSigner) GetRefreshToken(userId string, grantType string, aud string, claims ...Claim) (string, error) {
	return ts.signToken(&tokenClaims{
		UserId:    userId,
		Scopes:    RefreshTokenScope,
		Exp:       ts.refreshTokenDuration,
		GrantType: grantType,
		Aud:       ts.getAudience(aud)}, claims)
}

// ParseToken parse and validate jwt token. Retrieves a jwt.MapClaims
func (ts *tokenSigner) ParseToken(token string) (jwt.MapClaims, error) {
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(token, claims, GetKeyFunc(&ts.privateKey.PublicKey))
	if err != nil {
		return nil, InvalidToken(err)
	}
	return claims, nil
}

// GetSigningKey retrieves the key used to sign the tokens
func (ts *tokenSigner) GetSigningKey() ecdsa.PrivateKey {
	return *ts.privateKey
}

func (ts *tokenSigner) signToken(claims *tokenClaims, additionalClaims []Claim) (string, error) {
	claimMap := jwt.MapClaims{}
	for _, c := range additionalClaims {
		claimMap[c.Key] = c.Value
	}

	claimMap["scope"] = claims.Scopes
	claimMap["sub"] = claims.UserId
	claimMap["aud"] = claims.Aud
	claimMap["iss"] = ts.externalId
	claimMap["exp"] = time.Now().Add(claims.Exp).Unix()
	claimMap["grant_type"] = claims.GrantType

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claimMap)
	ret, err := token.SignedString(ts.privateKey)
	return ret, err
}

func (ts *tokenSigner) getAudience(aud string) string {
	if len(aud) > 0 {
		return aud
	}
	return ts.externalId
}

func GetKeyFunc(pubKey *ecdsa.PublicKey) func(token *jwt.Token) (interface{}, error) {
	return func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("wrong signing method")
		}
		return pubKey, nil
	}
}

// ClaimValidation perform validation over the tokens claims
type ClaimValidation func(claims jwt.MapClaims) error

// ValidateAudience retrieves a ClaimValidation which validates that the 'aud' claim matches the identifier
func ValidateAudience(identifier string) ClaimValidation {
	return func(claims jwt.MapClaims) error {
		checkAud := claims.VerifyAudience(identifier, false)
		if !checkAud {
			return errors.New("invalid aud claim")
		}
		return nil
	}
}

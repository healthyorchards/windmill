package auth

import (
	"crypto/ecdsa"
	"github.com/dgrijalva/jwt-go"
	"time"
)

type tokenClaims struct {
	UserId    string
	Scopes    Scopes
	Exp       time.Duration
	GrantType string
	Aud       string
}

type TokenSigner interface {
	GetAccessToken(userId string, scopes Scopes, grantType string, aud string) (string, error)
	GetRefreshToken(userId string, grantType string, aud string) (string, error)
}

func NewTokenSigner(pkey *ecdsa.PrivateKey, atd time.Duration, rtd time.Duration, d string) TokenSigner {
	return &tokenSigner{
		privateKey:           pkey,
		accessTokenDuration:  atd,
		refreshTokenDuration: rtd,
		domain:               d,
	}
}

type tokenSigner struct {
	privateKey           *ecdsa.PrivateKey
	accessTokenDuration  time.Duration
	refreshTokenDuration time.Duration
	domain               string
}

const RefreshTokenScope = "auth/refresh"

func (ts *tokenSigner) GetAccessToken(userId string, scopes Scopes, grantType string, aud string) (string, error) {
	return ts.signToken(&tokenClaims{
		UserId:    userId,
		Scopes:    scopes,
		Exp:       ts.accessTokenDuration,
		GrantType: grantType,
		Aud:       ts.getAudience(aud)})
}

func (ts *tokenSigner) GetRefreshToken(userId string, grantType string, aud string) (string, error) {
	return ts.signToken(&tokenClaims{
		UserId:    userId,
		Scopes:    RefreshTokenScope,
		Exp:       ts.refreshTokenDuration,
		GrantType: grantType,
		Aud:       ts.getAudience(aud)})
}

func (ts *tokenSigner) signToken(claims *tokenClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"scope":      claims.Scopes,
		"sub":        claims.UserId,
		"aud":        claims.Aud,
		"iss":        ts.domain,
		"exp":        time.Now().Add(claims.Exp).Unix(),
		"grant_type": claims.GrantType,
	})
	ret, err := token.SignedString(ts.privateKey)
	return ret, err
}

func (ts *tokenSigner) getAudience(aud string) string {
	if len(aud) > 0 {
		return aud
	}
	return ts.domain
}

package auth

import (
	"crypto/ecdsa"
	"encoding/base64"
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/healthyorchards/windmill/pkg/auth/keys"
	"net/http"
	"regexp"
	"strings"
	"time"
)

type GinAuth interface {
	AddAuthenticationEndpoint(route gin.IRouter, relativePath string)
	AddTokenEndpoint(route gin.IRouter, relativePath string)
	AddRefreshEndpoint(route gin.IRouter, relativePath string)
	AddPubKeyEndpoint(route gin.IRouter, relativePath string)
	AddAuthProtocol(route gin.IRouter, middleware func(ctx *gin.Context))
}

type ginAuthServer struct {
	authService TokenServer
	pubKey      string
}

type GinAuthConfig struct {
	UsrAuthorizer      Authorizer
	ClientAuthorizer   Authorizer
	ScopeProvider      ScopeProvider
	ClientValidator    ClientValidator
	SigningKey         *ecdsa.PrivateKey
	AccessTknDuration  time.Duration
	RefreshTknDuration time.Duration
	AppId              string
}

func BasicGinAuth(c *GinAuthConfig) (GinAuth, error) {
	signer := NewTokenSigner(c.SigningKey, c.AccessTknDuration, c.RefreshTknDuration, c.AppId)
	authorizers := map[string]Authorizer{PasswordCredentials: c.UsrAuthorizer, ClientCredentials: c.ClientAuthorizer}
	pubKey, err := keys.PemEncodePublicKey(&c.SigningKey.PublicKey)
	if err != nil {
		return nil, err
	}
	return NewGinAuth(authorizers, signer, c.ScopeProvider, c.ClientValidator, pubKey), nil
}

func NewGinAuth(authorizers map[string]Authorizer,
	signer TokenSigner, scopes ScopeProvider, clients ClientValidator, pubKey string) GinAuth {
	return &ginAuthServer{authService: NewTokenServer(authorizers, signer, scopes, clients), pubKey: pubKey}
}

type userData []string

func (ud userData) getName() string {
	return ud[0]
}

func (ud userData) getPassword() string {
	return ud[1]
}

func getCredentials(credentials string) userData {
	return strings.Split(credentials, ":")
}

func (ah *ginAuthServer) AddAuthProtocol(route gin.IRouter, middleware func(ctx *gin.Context)) {
	route.GET("/authorize", ah.authorize)

	tknGroup := route.Group("/token")
	tknGroup.Use(middleware)
	tknGroup.GET("", WithScopes(ah.refreshToken, []string{RefreshTokenScope}))

	accessTknGroup := route.Group("/refresh")
	accessTknGroup.Use(middleware)
	accessTknGroup.GET("", WithScopes(ah.accessToken, []string{RefreshTokenScope}))

	route.GET("/public_key", ah.getPubKey)

	route.OPTIONS("/authorize", addPreflightCheckHeaders("GET"))
	route.OPTIONS("/token", addPreflightCheckHeaders("GET"))
	route.OPTIONS("/refresh", addPreflightCheckHeaders("GET"))
	route.OPTIONS("/public_key", addPreflightCheckHeaders("GET"))
}

func (ah *ginAuthServer) AddAuthenticationEndpoint(route gin.IRouter, relativePath string) {
	route.GET(relativePath, ah.authorize)
	route.OPTIONS(relativePath, addPreflightCheckHeaders("GET"))
}

func (ah *ginAuthServer) AddTokenEndpoint(route gin.IRouter, relativePath string) {
	route.GET(relativePath, WithScopes(ah.accessToken, []string{RefreshTokenScope}))
	route.OPTIONS(relativePath, addPreflightCheckHeaders("GET"))
}

func (ah *ginAuthServer) AddRefreshEndpoint(route gin.IRouter, relativePath string) {
	route.GET(relativePath, WithScopes(ah.refreshToken, []string{RefreshTokenScope}))
	route.OPTIONS(relativePath, addPreflightCheckHeaders("GET"))
}

func (ah *ginAuthServer) AddPubKeyEndpoint(route gin.IRouter, relativePath string) {
	route.GET(relativePath, ah.getPubKey)
	route.OPTIONS(relativePath, addPreflightCheckHeaders("GET"))
}

type authorizeReq struct {
	Scope string `form:"scope"`
	Aud   string `form:"aud"`
}

func (ah *ginAuthServer) authorize(ctx *gin.Context) {
	grantType := ctx.Request.Header.Get(GrantTypeHeader)
	authHeader := strings.Trim(ctx.Request.Header.Get(AuthorizationHeader), " ")
	tknRegex := regexp.MustCompile(`(?i)basic (.*)`)

	if !tknRegex.MatchString(authHeader) {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized,
			gin.H{"error": "unable to authenticate request. Invalid 'Authorization' header2"})
		return
	}

	userHash := tknRegex.FindAllStringSubmatch(authHeader, -1)[0][1]
	decodedUserHash, err := base64.StdEncoding.DecodeString(userHash)

	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	var req authorizeReq
	err = ctx.Bind(&req)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	credentials := getCredentials(string(decodedUserHash))
	scopes := strings.Split(strings.TrimSpace(req.Scope), ",")

	token, err := ah.authService.Authorize(Credentials{
		Id:       credentials.getName(),
		Password: credentials.getPassword(),
		Grant:    strings.ToLower(grantType)}, scopes, req.Aud)

	if err != nil {
		switch err.(type) {
		case InvalidGrant, InvalidUser:
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
			return
		default:
			ctx.JSON(http.StatusServiceUnavailable, gin.H{"error": "Server error"})
			return
		}
	}

	ctx.JSON(http.StatusOK, token)
}

func (ah *ginAuthServer) accessToken(ctx *gin.Context) {
	r, exists := ctx.Get(ReqAuthData)

	if !exists {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid grants"})
		return
	}

	var req authorizeReq
	err := ctx.Bind(&req)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}
	sender := r.(RequestAuthData).Sender
	grantType := r.(RequestAuthData).GrantType
	scopes := strings.Split(strings.TrimSpace(req.Scope), ",")

	aud, err := ah.extractAud(ctx)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	token, err := ah.authService.AccessToken(Credentials{sender, "", grantType}, scopes, aud)

	if err != nil {
		switch err.(type) {
		case InvalidGrant, InvalidUser:
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
			return
		default:
			ctx.JSON(http.StatusServiceUnavailable, gin.H{"error": "Server error"})
			return
		}
	}

	ctx.JSON(http.StatusOK, gin.H{"access_token": token})
}

func (ah *ginAuthServer) refreshToken(ctx *gin.Context) {
	r, exists := ctx.Get(ReqAuthData)

	if !exists {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid grants"})
		return
	}

	var req authorizeReq
	err := ctx.Bind(&req)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	sender := r.(RequestAuthData).Sender
	grantType := r.(RequestAuthData).GrantType
	scopes := strings.Split(strings.TrimSpace(req.Scope), ",")

	aud, err := ah.extractAud(ctx)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	credentials, err := ah.authService.Refresh(Credentials{sender, "", grantType}, scopes, aud)

	if err != nil {
		switch err.(type) {
		case InvalidGrant, InvalidUser:
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
			return
		default:
			ctx.JSON(http.StatusServiceUnavailable, gin.H{"error": "Server error"})
			return
		}
	}
	ctx.JSON(http.StatusOK, credentials)
}

func (ah *ginAuthServer) getPubKey(c *gin.Context) {
	c.String(http.StatusOK, ah.pubKey)
}

func (ah *ginAuthServer) extractAud(ctx *gin.Context) (string, error) {
	r, exists := ctx.Get(ReqAuthData)
	if !exists {
		return "", UnkownAud(errors.New("invalid aud claim"))
	}

	aud := r.(RequestAuthData).Aud
	if len(strings.TrimSpace(aud)) > 0 {
		return aud, nil
	}
	return "", UnkownAud(errors.New("invalid aud claim"))
}

func WithScopes(handler gin.HandlerFunc, scopes []string) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		r, exists := ctx.Get(ReqAuthData)
		if !exists {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid grants"})
			return
		}

		userScopes := r.(RequestAuthData).Scopes
		if checkScopes(userScopes, scopes) {
			handler(ctx)
			return
		}

		ctx.JSON(http.StatusForbidden, gin.H{"error": "Forbidden, no valid grant"})
		return
	}
}

func checkScopes(firstArray []string, secondArray []string) bool {
	for _, s := range firstArray {
		for _, is := range secondArray {
			if s == is {
				return true
			}
		}
	}
	return false
}

func addPreflightCheckHeaders(allowedMethods string) func(c *gin.Context) {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Methods", allowedMethods)
		c.Header("Access-Control-Allow-Headers", "*")
		c.AbortWithStatus(http.StatusNoContent)
	}
}

package auth

import (
	"crypto/ecdsa"
	"encoding/base64"
	"github.com/gin-gonic/gin"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// GinAuth is an abstraction to create a Auth server using the 'Gin' Framework
type GinAuth interface {
	// AddAuthenticationEndpoint register an endpoint in the given path to perform the authentication
	AddAuthenticationEndpoint(route gin.IRouter, relativePath string)
	// AddAccessTokenEndpoint register an endpoint in the given path to generate a new AccessToken
	AddAccessTokenEndpoint(route gin.IRouter, authMiddleware func(ctx *gin.Context), relativePath string)
	// AddRefreshEndpoint register an endpoint in the given path to refresh both the RefreshToken and the AccessToken
	AddRefreshEndpoint(route gin.IRouter, authMiddleware func(ctx *gin.Context), relativePath string)
	// AddPubKeyEndpoint register an endpoint to retrieve the
	AddPubKeyEndpoint(route gin.IRouter, relativePath string)
	// AddAuthProtocol adds all previous endpoints
	AddAuthProtocol(route gin.IRouter, middleware func(ctx *gin.Context))
}

type ginAuthServer struct {
	authService TokenServer
}

type GinAuthConfig struct {
	UsrAuthorizer      Authorizer
	ClientAuthorizer   Authorizer
	ScopeProvider      ScopeProvider
	ClientValidator    ClientValidator
	ClaimProvider      ClaimProvider
	SigningKey         *ecdsa.PrivateKey
	AccessTknDuration  time.Duration
	RefreshTknDuration time.Duration
	AppId              string
}

func BasicGinAuth(c *GinAuthConfig) (GinAuth, error) {
	signer := NewTokenSigner(&SignerConfig{
		SigningKey:         c.SigningKey,
		AccessTknDuration:  c.AccessTknDuration,
		RefreshTknDuration: c.RefreshTknDuration,
		SignerIdentifier:   c.AppId})

	authorizers := map[string]Authorizer{PasswordCredentials: c.UsrAuthorizer, ClientCredentials: c.ClientAuthorizer}
	return NewGinAuth(authorizers, c.ClaimProvider, signer, c.ScopeProvider, c.ClientValidator)
}

func NewGinAuth(authorizers map[string]Authorizer, clProv ClaimProvider,
	signer TokenSigner, scopes ScopeProvider, clients ClientValidator) (GinAuth, error) {
	tknServerConfig := &TokenServerConfig{
		Authorizers:     authorizers,
		Signer:          signer,
		ScopesProvider:  scopes,
		ClaimProvider:   clProv,
		ClientValidator: clients,
	}
	tknServer, err := NewTokenServer(tknServerConfig)
	if err != nil {
		return nil, err
	}
	return &ginAuthServer{authService: tknServer}, nil
}

type userData []string

func (ud userData) getName() string {
	return ud[0]
}

func (ud userData) getPassword() string {
	return ud[1]
}

func (ginAuth *ginAuthServer) AddAuthProtocol(route gin.IRouter, authMiddleware func(ctx *gin.Context)) {
	ginAuth.AddAuthenticationEndpoint(route, "/authorize")

	ginAuth.AddRefreshEndpoint(route, authMiddleware, "/token")

	ginAuth.AddAccessTokenEndpoint(route, authMiddleware, "/refresh")

	ginAuth.AddPubKeyEndpoint(route, "/public_key")
}

func (ginAuth *ginAuthServer) AddAuthenticationEndpoint(route gin.IRouter, relativePath string) {
	route.GET(relativePath, ginAuth.authorize)
	route.OPTIONS(relativePath, addPreflightCheckHeaders("GET"))
}

func (ginAuth *ginAuthServer) AddAccessTokenEndpoint(route gin.IRouter, authMiddleware func(ctx *gin.Context), relativePath string) {
	accessTknGroup := route.Group(relativePath)
	accessTknGroup.Use(authMiddleware)
	accessTknGroup.GET("", ginAuth.accessToken)
	route.OPTIONS(relativePath, addPreflightCheckHeaders("GET"))
}

func (ginAuth *ginAuthServer) AddRefreshEndpoint(route gin.IRouter, authMiddleware func(ctx *gin.Context), relativePath string) {
	accessTknGroup := route.Group(relativePath)
	accessTknGroup.Use(authMiddleware)
	accessTknGroup.GET("", ginAuth.refreshToken)
	route.OPTIONS(relativePath, addPreflightCheckHeaders("GET"))
}

func (ginAuth *ginAuthServer) AddPubKeyEndpoint(route gin.IRouter, relativePath string) {
	route.GET(relativePath, ginAuth.getPubKey)
	route.OPTIONS(relativePath, addPreflightCheckHeaders("GET"))
}

type authorizeReq struct {
	Scope string `form:"scope"`
	Aud   string `form:"aud"`
}

func (ginAuth *ginAuthServer) authorize(ctx *gin.Context) {
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

	token, err := ginAuth.authService.Authorize(Credentials{
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

func (ginAuth *ginAuthServer) accessToken(ctx *gin.Context) {
	var req authorizeReq
	err := ctx.Bind(&req)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	refreshToken, _ := ctx.Get(RefreshToken)
	scopes := strings.Split(strings.TrimSpace(req.Scope), ",")

	token, err := ginAuth.authService.AccessToken(refreshToken.(string), scopes)

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

func (ginAuth *ginAuthServer) refreshToken(ctx *gin.Context) {
	var req authorizeReq
	err := ctx.Bind(&req)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}
	scopes := strings.Split(strings.TrimSpace(req.Scope), ",")
	refreshToken, _ := ctx.Get(RefreshToken)

	credentials, err := ginAuth.authService.Refresh(refreshToken.(string), scopes)

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

func (ginAuth *ginAuthServer) getPubKey(c *gin.Context) {
	c.String(http.StatusOK, ginAuth.authService.GetEncodedPubKey())
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

func getCredentials(credentials string) userData {
	return strings.Split(credentials, ":")
}

func addPreflightCheckHeaders(allowedMethods string) func(c *gin.Context) {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Methods", allowedMethods)
		c.Header("Access-Control-Allow-Headers", "*")
		c.AbortWithStatus(http.StatusNoContent)
	}
}

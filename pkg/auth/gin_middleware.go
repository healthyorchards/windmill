package auth

import (
	"crypto/ecdsa"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"net/http"
	"regexp"
	"strings"
)

type RequestAuthData struct {
	Sender    string
	Scopes    []string
	GrantType string
	Aud       string
}

const ReqAuthData = "requestAuthData"
const RefreshToken = "refreshToken"

// NewBasicMiddleware retrieves a default middleware. it will validate the jwt.
// The only validation done to the claims is that the audience matches the appID
// pubKey: public key corresponding to private key used by the auth server to sign the token
// appId: resource service external identifier
func NewBasicMiddleware(pubKey func() *ecdsa.PublicKey, appId string) func(ctx *gin.Context) {
	return NewAuthMiddleware(pubKey, ValidateAudience(appId))
}

// NewAuthServerMiddleware used for AuthServer to extract the Authorization header data.
func NewAuthServerMiddleware() func(ctx *gin.Context) {
	return func(ctx *gin.Context) {
		authHeader := strings.Trim(ctx.Request.Header.Get("Authorization"), " ")
		tknRegex := regexp.MustCompile(`(?i)bearer (.*)`)
		if !tknRegex.MatchString(authHeader) {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized,
				gin.H{"error": "unable to authenticate request. Invalid 'Authorization' header"})
			return
		}
		requestToken := tknRegex.FindAllStringSubmatch(authHeader, -1)[0][1]
		ctx.Set(RefreshToken, requestToken)
		ctx.Next()
	}
}

// NewAuthMiddleware retrieves a middleware to validate the access token ton the resource server side.
// pubKey: public key corresponding to private key used by the auth server to sign the token
// validations: additional validations the user might want to perform over the tokens claims
func NewAuthMiddleware(pubKey func() *ecdsa.PublicKey, validations ...ClaimValidation) func(ctx *gin.Context) {
	return func(ctx *gin.Context) {
		authHeader := strings.Trim(ctx.Request.Header.Get("Authorization"), " ")
		tknRegex := regexp.MustCompile(`(?i)bearer (.*)`)
		if !tknRegex.MatchString(authHeader) {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized,
				gin.H{"error": "unable to authenticate request. Invalid 'Authorization' header"})
			return
		}

		accessToken := tknRegex.FindAllStringSubmatch(authHeader, -1)[0][1]

		claims := jwt.MapClaims{}
		_, err := jwt.ParseWithClaims(accessToken, claims, GetKeyFunc(pubKey()))

		if err != nil {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		for _, v := range validations {
			errClaim := v(claims)
			if errClaim != nil {
				ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
				return
			}
		}

		ctx.Set(ReqAuthData, RequestAuthData{
			Sender:    claims["sub"].(string),
			Scopes:    strings.Split(claims["scope"].(string), " "),
			GrantType: claims["grant_type"].(string),
			Aud:       claims["aud"].(string)})

		ctx.Next()
	}
}

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

func NewAuthMiddleware(pubKey *ecdsa.PublicKey, identifier string) func(ctx *gin.Context) {
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
		token, err := jwt.ParseWithClaims(accessToken, claims, GetKeyFunc(pubKey))

		if err != nil {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		checkAud := token.Claims.(jwt.MapClaims).VerifyAudience(identifier, false)
		if !checkAud {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		ctx.Set(ReqAuthData, RequestAuthData{
			Sender:    claims["sub"].(string),
			Scopes:    strings.Split(claims["scope"].(string), " "),
			GrantType: claims["grant_type"].(string),
			Aud:       claims["aud"].(string)})

		ctx.Next()
	}
}

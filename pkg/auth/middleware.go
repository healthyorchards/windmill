package auth

import (
	"crypto/ecdsa"
	"fmt"
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

func NewAuthMiddleware(pubKey *ecdsa.PublicKey) func(ctx *gin.Context) {
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
		_, err := jwt.ParseWithClaims(accessToken, claims, getKeyFunc(pubKey))

		if err != nil {
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

func getKeyFunc(pubKey *ecdsa.PublicKey) func(token *jwt.Token) (interface{}, error) {
	return func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("wrong signing method")
		}
		return pubKey, nil
	}
}

package integration

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/healthyorchards/windmill/pkg/auth"
	"github.com/healthyorchards/windmill/pkg/auth/keys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type testRouter struct {
	*gin.Engine
	T *testing.T
}

type demoUser struct {
	Name     string
	Password string
	Scopes   string
}

type inMemoryData struct {
	users map[string]demoUser
}

func (id inMemoryData) authorizeHumanUser(uc auth.Credentials) error {
	u, ok := id.users[uc.Id]
	if !ok || uc.Password != u.Password {
		return auth.InvalidUser(errors.New("i dont know this person"))
	}
	return nil
}

func (id inMemoryData) authorizeMachineUser(_ auth.Credentials) error {
	return nil
}

func (id inMemoryData) validateClient(credentials auth.Credentials, clientId string) (bool, error) {
	return "forbidden-aud" != clientId, nil
}

func (id inMemoryData) getScopes(uc auth.Credentials, rs auth.Scopes) (auth.Scopes, error) {
	if uc.Grant == auth.ClientCredentials {
		return []string{"admin"}, nil
	}
	u, ok := id.users[uc.Id]
	if !ok {
		return nil, auth.InvalidUser(errors.New("i dont know this person"))
	}

	for _, s := range rs {
		if s == u.Scopes {
			return []string{u.Scopes}, nil
		}
	}
	return []string{}, nil
}

const defaultId = "www.myd0main.com"

func initMockService(t *testing.T, users []demoUser, duration time.Duration, domain string, pk *ecdsa.PrivateKey, id string) testRouter {
	router := gin.New()
	gin.SetMode(gin.ReleaseMode)

	pubKey := func() *ecdsa.PublicKey {
		return &pk.PublicKey
	}

	authMiddleware := auth.NewAuthServerMiddleware()
	resourceMiddleware := auth.NewBasicMiddleware(pubKey, id)

	demoPath := router.Group("/demo")
	demoPath.Use(resourceMiddleware)

	data := map[string]demoUser{}
	for _, u := range users {
		data[u.Name] = u
	}

	inMemory := inMemoryData{data}
	conf := &auth.GinAuthConfig{
		UsrAuthorizer:      inMemory.authorizeHumanUser,
		ClientAuthorizer:   inMemory.authorizeMachineUser,
		ScopeProvider:      inMemory.getScopes,
		ClientValidator:    inMemory.validateClient,
		SigningKey:         pk,
		AccessTknDuration:  duration,
		RefreshTknDuration: duration,
		AppId:              domain,
	}

	a, err := auth.BasicGinAuth(conf)
	require.NoError(t, err)

	a.AddAuthProtocol(router, authMiddleware)
	demoPath.GET("/admin", auth.WithScopes(func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{"result": "you are an admin"})
	}, []string{"admin"}))

	demoPath.GET("/action", auth.WithScopes(func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{"result": "you can do the action"})
	}, []string{"action-doer"}))

	router.GET("/not-secured", func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{"result": "everyone can do this"})
	})

	return testRouter{Engine: router, T: t}
}

func TestLogin(t *testing.T) {
	users := []demoUser{{Name: "tito", Password: "puente", Scopes: "action-doer"}}
	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	t.Run("Human user can login", func(t *testing.T) {
		router := initMockService(t, users, time.Hour, "www.myd0main.com", pk, defaultId)
		resp := router.doLogin("tito", "puente", auth.PasswordCredentials, http.StatusOK, "action-doer,something", "")
		authToken, ok := resp["access_token"]
		assert.True(t, ok, "Result must contain an access token")
		aClaims := getClaims(authToken.(string), pk, t)
		//Only the user assigned scopes are returned
		assert.Equal(t, "action-doer", aClaims["scope"].(string))
		//if no aud is provided the default is the auth service
		assert.Equal(t, "www.myd0main.com", aClaims["aud"].(string))

		refresh, ok := resp["refresh_token"]
		assert.True(t, ok, "Result must contain an access token")
		rClaims := getClaims(refresh.(string), pk, t)
		assert.Equal(t, "auth/refresh", rClaims["scope"].(string))
		//if no aud is provided the default is the auth service
		assert.Equal(t, "www.myd0main.com", rClaims["aud"].(string))
	})

	t.Run("If no valid scope provided, then no scope is present", func(t *testing.T) {
		router := initMockService(t, users, time.Hour, defaultId, pk, defaultId)
		resp := router.doLogin("tito", "puente", auth.PasswordCredentials, http.StatusOK, "", "")
		authToken, _ := resp["access_token"]
		aClaims := getClaims(authToken.(string), pk, t)
		//Only the user assigned scopes are returned
		assert.Equal(t, "", aClaims["scope"].(string))

		resp = router.doLogin("tito", "puente", auth.PasswordCredentials, http.StatusOK, "something,else,read:stuff", "")
		authToken, _ = resp["access_token"]
		aClaims = getClaims(authToken.(string), pk, t)
		//Only the user assigned scopes are returned
		assert.Equal(t, "", aClaims["scope"].(string))
	})

	t.Run("User cannot get tokens for a client(audience) where them are not allowed", func(t *testing.T) {
		router := initMockService(t, users, time.Hour, "www.myd0main.com", pk, defaultId)
		resp := router.doLogin("tito", "puente", auth.PasswordCredentials, http.StatusOK, "", "other-service")
		authToken, _ := resp["access_token"]
		aClaims := getClaims(authToken.(string), pk, t)
		assert.Equal(t, "other-service", aClaims["aud"].(string))

		router.doLogin("tito", "puente", auth.PasswordCredentials, http.StatusUnauthorized, "", "forbidden-aud")
	})
	t.Run("Client Credential login", func(t *testing.T) {
		router := initMockService(t, users, time.Hour, "www.myd0main.com", pk, defaultId)
		resp := router.doLogin("tito", "puente", auth.ClientCredentials, http.StatusOK, "action-doer", "")
		authToken, ok := resp["access_token"]
		assert.True(t, ok, "Result must contain an access token")
		getClaims(authToken.(string), pk, t)

		refresh, ok := resp["refresh_token"]
		assert.True(t, ok, "Result must contain an access token")
		getClaims(refresh.(string), pk, t)
	})

	t.Run("Login should fail if user is invalid", func(t *testing.T) {
		router := initMockService(t, users, time.Hour, "www.myd0main.com", pk, defaultId)
		router.doLogin("NOT-TITO", "puente", auth.PasswordCredentials, http.StatusUnauthorized, "action-doer", "")
	})

	t.Run("Login should fail if password is invalid", func(t *testing.T) {
		router := initMockService(t, users, time.Hour, "www.myd0main.com", pk, defaultId)
		router.doLogin("tito", "NOT-puente", auth.PasswordCredentials, http.StatusUnauthorized, "action-doer", "")
	})
}

func TestGetAccessToken(t *testing.T) {
	users := []demoUser{demoUser{Name: "tito", Password: "puente", Scopes: "action-doer"}}
	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	t.Run("We should be able to get a new access token with the refresh token", func(t *testing.T) {
		router := initMockService(t, users, time.Hour, "www.myd0main.com", pk, defaultId)
		resp := router.doLogin("tito", "puente", auth.PasswordCredentials, http.StatusOK, "action-doer", "")
		accessTkn := resp["access_token"].(string)
		refresh := resp["refresh_token"].(string)

		aClaims := getClaims(accessTkn, pk, t)
		initalAud := aClaims["aud"].(string)

		secondResp := router.doNewAccessToken(refresh, auth.PasswordCredentials, http.StatusOK)
		newAccessTkn := secondResp["access_token"].(string)
		getClaims(newAccessTkn, pk, t)
		assert.NotEqual(t, accessTkn, newAccessTkn)

		c2 := getClaims(newAccessTkn, pk, t)
		a2 := c2["aud"].(string)

		assert.Equal(t, initalAud, a2)
	})

	t.Run("Same but with client credentials", func(t *testing.T) {
		router := initMockService(t, users, time.Hour, "www.myd0main.com", pk, defaultId)
		resp := router.doLogin("tito", "puente", auth.ClientCredentials, http.StatusOK, "action-doer", "")
		accessTkn := resp["access_token"].(string)
		refresh := resp["refresh_token"].(string)

		secondResp := router.doNewAccessToken(refresh, auth.ClientCredentials, http.StatusOK)
		newAccessTkn := secondResp["access_token"].(string)
		getClaims(newAccessTkn, pk, t)
		assert.NotEqual(t, accessTkn, newAccessTkn)
	})

	t.Run("Should fail if we use the access token", func(t *testing.T) {
		router := initMockService(t, users, time.Hour, "www.myd0main.com", pk, defaultId)
		resp := router.doLogin("tito", "puente", auth.ClientCredentials, http.StatusOK, "action-doer", "")
		accessTkn := resp["access_token"].(string)
		router.doNewAccessToken(accessTkn, auth.ClientCredentials, http.StatusUnauthorized)
	})
}

func TestRefreshToken(t *testing.T) {
	users := []demoUser{demoUser{Name: "tito", Password: "puente", Scopes: "action-doer"}}
	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	t.Run("We should be able to get new tokens with the refresh token", func(t *testing.T) {
		router := initMockService(t, users, time.Hour, "www.myd0main.com", pk, defaultId)
		resp := router.doLogin("tito", "puente", auth.PasswordCredentials, http.StatusOK, "action-doer", "")
		accessTkn := resp["access_token"].(string)
		refresh := resp["refresh_token"].(string)

		secondResp := router.doRefreshToken(refresh, auth.PasswordCredentials, http.StatusOK)
		newAccessTkn := secondResp["access_token"].(string)
		newRefreshTkn := secondResp["refresh_token"].(string)

		getClaims(newAccessTkn, pk, t)
		getClaims(newRefreshTkn, pk, t)

		assert.NotEqual(t, accessTkn, newAccessTkn)
		assert.NotEqual(t, refresh, newRefreshTkn)
	})

	t.Run("Same but with client credentials", func(t *testing.T) {
		router := initMockService(t, users, time.Hour, "www.myd0main.com", pk, defaultId)
		resp := router.doLogin("tito", "puente", auth.ClientCredentials, http.StatusOK, "action-doer", "")
		accessTkn := resp["access_token"].(string)
		refresh := resp["refresh_token"].(string)

		secondResp := router.doRefreshToken(refresh, auth.ClientCredentials, http.StatusOK)
		newAccessTkn := secondResp["access_token"].(string)
		newRefreshTkn := secondResp["refresh_token"].(string)

		getClaims(newAccessTkn, pk, t)
		getClaims(newRefreshTkn, pk, t)

		assert.NotEqual(t, accessTkn, newAccessTkn)
		assert.NotEqual(t, refresh, newRefreshTkn)
	})

	t.Run("Should fail if we use the access token", func(t *testing.T) {
		router := initMockService(t, users, time.Hour, "www.myd0main.com", pk, defaultId)
		resp := router.doLogin("tito", "puente", auth.ClientCredentials, http.StatusOK, "action-doer", "")
		accessTkn := resp["access_token"].(string)
		router.doRefreshToken(accessTkn, auth.ClientCredentials, http.StatusUnauthorized)
	})
}

func TestAccess(t *testing.T) {
	users := []demoUser{demoUser{Name: "tito", Password: "puente", Scopes: "action-doer"}}
	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	t.Run("We should access an endpoint if we have the right scopes", func(t *testing.T) {
		router := initMockService(t, users, time.Hour, "www.myd0main.com", pk, defaultId)
		resp := router.doLogin("tito", "puente", auth.PasswordCredentials, http.StatusOK, "action-doer", "")
		accessTkn := resp["access_token"].(string)
		router.getActionEndpoint(accessTkn, auth.PasswordCredentials, http.StatusOK)
	})

	t.Run("Same with client credentials", func(t *testing.T) {
		router := initMockService(t, users, time.Hour, "www.myd0main.com", pk, defaultId)
		resp := router.doLogin("tito", "puente", auth.ClientCredentials, http.StatusOK, "admin", "")
		accessTkn := resp["access_token"].(string)
		router.getAdminEndpoint(accessTkn, auth.ClientCredentials, http.StatusOK)
	})

	t.Run("Deny access based on scopes", func(t *testing.T) {
		router := initMockService(t, users, time.Hour, "www.myd0main.com", pk, defaultId)
		resp := router.doLogin("tito", "puente", auth.PasswordCredentials, http.StatusOK, "action-doer", "")
		accessTkn := resp["access_token"].(string)
		router.getAdminEndpoint(accessTkn, auth.PasswordCredentials, http.StatusForbidden)
	})

	t.Run("Reject access if we use refresh token", func(t *testing.T) {
		router := initMockService(t, users, time.Hour, "www.myd0main.com", pk, defaultId)
		resp := router.doLogin("tito", "puente", auth.PasswordCredentials, http.StatusOK, "action-doer", "")
		tkn := resp["refresh_token"].(string)
		router.getAdminEndpoint(tkn, auth.PasswordCredentials, http.StatusForbidden)
	})

	t.Run("Reject expired token", func(t *testing.T) {
		router := initMockService(t, users, time.Nanosecond, "www.myd0main.com", pk, defaultId)
		resp := router.doLogin("tito", "puente", auth.PasswordCredentials, http.StatusOK, "action-doer", "")
		time.Sleep(time.Second)
		tkn := resp["access_token"].(string)
		router.getAdminEndpoint(tkn, auth.PasswordCredentials, http.StatusUnauthorized)
	})

	t.Run("Reject tokens from an unkown source", func(t *testing.T) {
		router := initMockService(t, users, time.Hour, "www.myd0main.com", pk, defaultId)
		otherPk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		signer := auth.NewTokenSigner(&auth.SignerConfig{
			SigningKey:         otherPk,
			AccessTknDuration:  time.Hour,
			RefreshTknDuration: time.Hour,
			SignerIdentifier:   "www.myd0main.com"})

		tkn, err := signer.GetAccessToken("tito", []string{"action-doer"}, auth.PasswordCredentials, "aud")
		require.NoError(t, err)

		router.getAdminEndpoint(tkn, auth.PasswordCredentials, http.StatusUnauthorized)
	})

	t.Run("Reject request if no token is present", func(t *testing.T) {
		router := initMockService(t, users, time.Hour, "www.myd0main.com", pk, defaultId)
		req, err := http.NewRequest("GET", "/demo/admin", nil)
		require.NoError(router.T, err)
		router.runRequest(req, http.StatusUnauthorized)
	})

	t.Run("Allow to hit not protected endpoints", func(t *testing.T) {
		router := initMockService(t, users, time.Hour, "www.myd0main.com", pk, defaultId)
		req, err := http.NewRequest("GET", "/not-secured", nil)
		require.NoError(router.T, err)
		router.runRequest(req, http.StatusOK)
	})

	t.Run("Third party service should reject request if the token is not meant for it (aud claim)", func(t *testing.T) {
		router := initMockService(t, users, time.Hour, "www.myd0main.com", pk, "other-id")
		resp := router.doLogin("tito", "puente", auth.PasswordCredentials, http.StatusOK, "action-doer", "")
		accessTkn := resp["access_token"].(string)
		router.getActionEndpoint(accessTkn, auth.PasswordCredentials, http.StatusUnauthorized)
	})
}

func TestPublicKeyEndpoint(t *testing.T) {
	users := []demoUser{}
	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	router := initMockService(t, users, time.Hour, defaultId, pk, defaultId)

	pubKey := router.getPublicKey()
	assert.NotNil(t, pubKey)
	assert.Equal(t, pk.PublicKey, pubKey)

	pk2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	router2 := initMockService(t, users, time.Hour, defaultId, pk2, defaultId)

	pubKey2 := router2.getPublicKey()
	assert.NotNil(t, pubKey2)
	assert.Equal(t, pk2.PublicKey, pubKey2)

	assert.NotEqual(t, pubKey, pubKey2)
}

func (router testRouter) doLogin(user string, pass string, grant string, expectedStatus int, scope string, aud string) map[string]interface{} {
	url := fmt.Sprintf("/authorize?scope=%s&aud=%s", scope, aud)
	req, err := http.NewRequest("GET", url, nil)
	require.NoError(router.T, err)

	a := fmt.Sprintf("%s:%s", user, pass)
	b := []byte(a)
	creds := base64.StdEncoding.EncodeToString(b)

	req.Header.Set(auth.AuthorizationHeader, fmt.Sprintf("basic %s", creds))
	req.Header.Set(auth.GrantTypeHeader, grant)

	code, response := router.runRequest(req, expectedStatus)
	assert.Equal(router.T, code, expectedStatus)
	return response
}

func (router testRouter) getAdminEndpoint(accessToken string, grant string, expectedStatus int) {
	router.doAuthGet(accessToken, grant, expectedStatus, "/demo/admin")
}

func (router testRouter) getActionEndpoint(accessToken string, grant string, expectedStatus int) {
	router.doAuthGet(accessToken, grant, expectedStatus, "/demo/action")
}

func (router testRouter) getPublicKey() ecdsa.PublicKey {
	req, err := http.NewRequest("GET", "/public_key", nil)
	require.NoError(router.T, err)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(router.T, http.StatusOK, w.Code)

	key, err := ioutil.ReadAll(w.Body)

	pk, err := keys.PemDecodePublicKey(string(key))
	require.NoError(router.T, err)
	return *pk
}

func (router testRouter) doNewAccessToken(refresh string, grant string, expectedStatus int) map[string]interface{} {
	return router.doAuthGet(refresh, grant, expectedStatus, "/refresh")
}

func (router testRouter) doRefreshToken(refresh string, grant string, expectedStatus int) map[string]interface{} {
	return router.doAuthGet(refresh, grant, expectedStatus, "/token")
}

func (router testRouter) doAuthGet(token string, grant string, expectedStatus int, url string) map[string]interface{} {
	req, err := http.NewRequest("GET", url, nil)
	require.NoError(router.T, err)

	req.Header.Set(auth.AuthorizationHeader, fmt.Sprintf("bearer %s", token))
	req.Header.Set(auth.GrantTypeHeader, grant)

	code, response := router.runRequest(req, expectedStatus)
	assert.Equal(router.T, code, expectedStatus)
	return response
}

func (router testRouter) runRequest(req *http.Request, expectedStatus int) (int, map[string]interface{}) {
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(router.T, expectedStatus, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(router.T, err)

	return w.Code, response
}

func getClaims(token string, pk *ecdsa.PrivateKey, t *testing.T) jwt.MapClaims {
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("worng signing method")
		}
		return &pk.PublicKey, nil
	})
	require.NoError(t, err)
	return claims
}

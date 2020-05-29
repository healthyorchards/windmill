package auth

import "strings"

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

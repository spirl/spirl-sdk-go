package client

import (
	"log/slog"

	"github.com/spirl/spirl-sdk-go/spirlsdk/auth"
)

type config struct {
	log           *slog.Logger
	endpoint      string
	endpointProxy string
	tokenStore    auth.TokenStore
}

type Option = func(*config)

// WithLogger provides for the client to use. The client uses the default
// slog logger by default.
func WithLogger(log *slog.Logger) Option {
	return func(c *config) {
		c.log = log
	}
}

// WithEndpoint provides an alternate address for the SPIRL API endpoint.
func WithEndpoint(endpoint string) Option {
	return func(c *config) {
		c.endpoint = endpoint
	}
}

// WithEndpointProxy provides an HTTP Connect proxy address to use to connect
// to the SPIRL API endpoint.
func WithEndpointProxy(endpointProxy string) Option {
	return func(c *config) {
		c.endpointProxy = endpointProxy
	}
}

// WithTokenStore provides a token store for token persistence. The store is
// consulted for an authentication token when the client need sto authenticate.
// After authentication, the store is invoked to persist the new authentication token.
func WithTokenStore(tokenStore auth.TokenStore) Option {
	return func(c *config) {
		c.tokenStore = tokenStore
	}
}

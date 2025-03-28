package client

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/spirl/spirl-sdk-go/spirlsdk/auth"
)

const (
	tokenKey = "token"
)

// list of methods that do not require authentication
var authExemptList = []string{
	"/com.spirl.api.v1.session.API/Login",
	"/com.spirl.api.v1.session.API/AuthenticateServiceAccount",
}

type authInterceptor struct {
	log        *slog.Logger
	authn      auth.Authenticator
	tokenStore auth.TokenStore
	sem        chan struct{}
	loadOnce   sync.Once `exhaustruct:"optional"`

	tokenMu sync.RWMutex `exhaustruct:"optional"`
	token   string
}

func newAuthInterceptor(log *slog.Logger, authn auth.Authenticator, tokenStore auth.TokenStore) *authInterceptor {
	if tokenStore == nil {
		tokenStore = noopTokenStore{}
	}

	sem := make(chan struct{}, 1)
	sem <- struct{}{}
	return &authInterceptor{
		log:        log,
		authn:      authn,
		tokenStore: tokenStore,
		sem:        sem,
		token:      "",
	}
}

func (a *authInterceptor) interceptUnary(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
	alreadyRetried := false

	for {
		token, err := a.maybeGetToken(ctx, cc, method)
		if err != nil {
			return err
		}

		err = invoker(appendNonEmptyTokenToContext(ctx, token), method, req, reply, cc, opts...)
		if status.Code(err) == codes.Unauthenticated {
			a.resetTokenIf(token)
			if !alreadyRetried {
				alreadyRetried = true
				continue
			}
		}
		return err
	}
}

func (a *authInterceptor) maybeGetToken(ctx context.Context, cc grpc.ClientConnInterface, method string) (string, error) {
	// Skip if the method does not require authentication.
	if slices.Contains(authExemptList, method) {
		return "", nil
	}

	// Use an existing, valid token if available.
	if token, ok := a.getToken(ctx); ok {
		return token, nil
	}

	// Refresh and use a new token.
	return a.refreshToken(ctx, cc, false)
}

func (a *authInterceptor) refreshToken(ctx context.Context, cc grpc.ClientConnInterface, force bool) (string, error) {
	// Token either does not exist or is not valid. Take the auth lock to
	// obtain a token.
	unlock, err := a.lockAuth(ctx)
	if err != nil {
		return "", err
	}
	defer unlock()

	// Check if another goroutine won the race on the auth lock and already
	// refreshed the token.
	if token, ok := a.getToken(ctx); ok && !force {
		return token, nil
	}

	a.log.Info("Authenticating...")

	// Obtain a new token.
	token, err := a.authn.Authenticate(ctx, cc)
	if err != nil {
		return "", err
	}

	// Persist the token. This is a no-op if a TokenStore is not configured.
	if err := a.tokenStore.SaveToken(ctx, token); err != nil {
		a.log.WarnContext(ctx, "Failed to save auth token to store", slog.Any("err", err))
	}

	// Replace the cached token.
	a.setToken(token)
	return token, nil
}

func (a *authInterceptor) getToken(ctx context.Context) (string, bool) {
	a.loadOnce.Do(func() {
		token, err := a.tokenStore.LoadToken(ctx)
		switch {
		case err == nil:
			a.setToken(token)
		case errors.Is(err, auth.ErrNoToken):
			// no token in store
		default:
			a.log.WarnContext(ctx, "Failed to load auth token from store", slog.Any("err", err))
		}
	})

	a.tokenMu.RLock()
	defer a.tokenMu.RUnlock()
	return a.token, a.token != ""
}

func (a *authInterceptor) setToken(token string) {
	a.tokenMu.Lock()
	defer a.tokenMu.Unlock()
	a.token = token
}

func (a *authInterceptor) resetTokenIf(token string) {
	a.tokenMu.Lock()
	defer a.tokenMu.Unlock()
	if a.token == token {
		a.token = ""
	}
}

func (a *authInterceptor) lockAuth(ctx context.Context) (unlock func(), err error) {
	// Take the auth semaphore. sync.Mutex is not used here because we want
	// to respect caller context cancellation.
	select {
	case sem := <-a.sem:
		// Release the semaphore when returning from this function.
		return func() { a.sem <- sem }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

type noopTokenStore struct{}

func (noopTokenStore) LoadToken(ctx context.Context) (token string, err error) {
	return "", auth.ErrNoToken
}

func (noopTokenStore) SaveToken(ctx context.Context, token string) (err error) {
	return nil
}

func appendNonEmptyTokenToContext(ctx context.Context, token string) context.Context {
	if token != "" {
		ctx = metadata.AppendToOutgoingContext(ctx, tokenKey, token)
	}
	return ctx
}

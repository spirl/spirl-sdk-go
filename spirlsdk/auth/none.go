package auth

import (
	"context"

	"google.golang.org/grpc"

	"github.com/spirl/spirl-sdk-go/spirlsdk"
	"github.com/spirl/spirl-sdk-go/spirlsdk/internal"
)

func None() Authenticator {
	return none{}
}

type none struct {
	internal.Impl `exhaustruct:"optional"`
}

// Authenticate is called by the SDK to authenticate the client. It
// returns the authentication token to use in future calls.
func (none) Authenticate(ctx context.Context, clientConn grpc.ClientConnInterface) (string, error) {
	return "", spirlsdk.ErrUnauthenticated
}

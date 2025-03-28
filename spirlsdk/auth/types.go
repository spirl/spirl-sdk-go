package auth

import (
	"context"

	"google.golang.org/grpc"

	"github.com/spirl/spirl-sdk-go/spirlsdk/internal"
)

// Authenticator authenticates the SDK client with SPIRL cloud.
type Authenticator interface {
	internal.Intf

	// Authenticate is called by the SDK to authenticate the client. It
	// returns the authentication token to use in future calls.
	Authenticate(ctx context.Context, clientConn grpc.ClientConnInterface) (string, error)
}

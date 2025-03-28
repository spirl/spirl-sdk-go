package spirlsdk

import "github.com/spirl/spirl-sdk-go/spirlsdk/internal/xerrors"

var (
	ErrNotFound        = xerrors.ErrNotFound
	ErrUnauthenticated = xerrors.ErrUnauthenticated
	ErrOutOfDate       = xerrors.ErrOutOfDate
)

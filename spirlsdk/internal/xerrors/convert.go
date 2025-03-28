package xerrors

import (
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func Convert(err error) error {
	// TODO: others....
	st := status.Convert(err)
	switch st.Code() {
	case codes.OK:
	case codes.Canceled:
	case codes.Unknown:
	case codes.InvalidArgument:
	case codes.DeadlineExceeded:
	case codes.NotFound:
		err = fmt.Errorf("%w: %s", ErrNotFound, st.Message())
	case codes.AlreadyExists:
	case codes.PermissionDenied:
	case codes.ResourceExhausted:
	case codes.FailedPrecondition:
	case codes.Aborted:
	case codes.OutOfRange:
	case codes.Unimplemented:
	case codes.Internal:
	case codes.Unavailable:
	case codes.DataLoss:
	case codes.Unauthenticated:
		err = fmt.Errorf("%w: %s", ErrUnauthenticated, st.Message())
	}
	return err
}

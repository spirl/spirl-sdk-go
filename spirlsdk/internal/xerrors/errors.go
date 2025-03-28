package xerrors

import (
	"errors"
	"fmt"
)

var (
	ErrNotFound        = errors.New("not found")
	ErrUnauthenticated = errors.New("unauthenticated")
	ErrOutOfDate       = errors.New("out-of-date SDK")
)

func UnexpectedResponseField(field string) error {
	return fmt.Errorf("unexpected response in field %q: %w", field, ErrOutOfDate)
}

func UnexpectedResponseType(field string, t any) error {
	return fmt.Errorf("unexpected type in response field %q: %T: %w", field, t, ErrOutOfDate)
}

type AmbiguousOrgError struct {
	Orgs []string
}

func (AmbiguousOrgError) Error() string {
	return "multiple org memberships: must provide org to authenticate with"
}

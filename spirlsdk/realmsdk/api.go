package realmsdk

import (
	"context"
	"time"
)

type API interface {
	// CreateRealm creates a new realm under a trust domain.
	CreateRealm(ctx context.Context, params CreateRealmParams) (*CreateRealmResult, error)

	// ListRealms lists realms with optional filtering.
	ListRealms(ctx context.Context, params ListRealmsParams) (*ListRealmsResult, error)

	// DeleteRealm deletes a realm. Only a realm with no associated clusters can be deleted.
	DeleteRealm(ctx context.Context, params DeleteRealmParams) (*DeleteRealmResult, error)
}

type CreateRealmParams struct {
	// TrustDomainID identifies the trust domain to create the realm under. Required.
	TrustDomainID string

	// Name is the name of the realm. Must be a valid SPIFFE ID path segment. Required.
	Name string
}

type CreateRealmResult struct {
	// RealmID identifies the created realm.
	RealmID string
}

type ListRealmsParams struct {
	// Filter filters the results.
	Filter RealmFilter
}

type ListRealmsResult struct {
	// Realms are the realms matching the filter.
	Realms []Realm
}

type DeleteRealmParams struct {
	// RealmID identifies the realm to delete. Required.
	RealmID string
}

type DeleteRealmResult struct{}

type RealmFilter struct {
	// TrustDomainID filters realms to those in the given trust domain. Optional.
	TrustDomainID *string

	// Name filters realms to those with the given name. Optional.
	Name *string
}

type Realm struct {
	// ID identifies the realm.
	ID string

	// OrgID identifies the organization the realm belongs to.
	OrgID string

	// TrustDomainID identifies the trust domain the realm belongs to.
	TrustDomainID string

	// Name is the name of the realm (used as SPIFFE ID path prefix).
	Name string

	// CreatedAt is the timestamp when the realm was created.
	CreatedAt time.Time
}

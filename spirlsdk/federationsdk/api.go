package federationsdk

import (
	"context"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

type API interface {
	// SetLink creates/updates a federation link with a foreign trust domain.
	SetLink(ctx context.Context, params SetLinkParams) (*SetLinkResult, error)

	// DeleteLink deletes a federation link with a foreign trust domain.
	DeleteLink(ctx context.Context, params DeleteLinkParams) (*DeleteLinkResult, error)

	// ListLinks lists federation links with a foreign trust domains.
	ListLinks(ctx context.Context, params ListLinksParams) (*ListLinksResult, error)

	// RefreshLink causes the bundle endpoint of the foreign trust domain to
	// be proactively polled before the next scheduled poll.
	RefreshLink(ctx context.Context, params RefreshLinkParams) (*RefreshLinkResult, error)
}

type SetLinkParams struct {
	// TrustDomainID identifies the trust domain to link to the foreign trust
	// domain. Required.
	TrustDomainID string

	// Link is the federation link configuration for the foreign trust domain.
	// Required.
	Link Link
}

type SetLinkResult struct{}

type DeleteLinkParams struct {
	// TrustDomainID identifies the trust domain with the federation link to
	// delete. Required.
	TrustDomainID string

	// ForeignTrustDomain identifies which foreign trust domain federation
	// link to delete. Required.
	ForeignTrustDomain spiffeid.TrustDomain
}

type DeleteLinkResult struct{}

type ListLinksParams struct {
	// Filter filters the results.
	Filter LinkFilter
}

type ListLinksResult struct {
	// LinkStatuses are the federation links with status.
	LinkStatuses []LinkStatus
}

type RefreshLinkParams struct {
	// TrustDomainID identifies the trust domain that the federation link
	// belongs to. Required.
	TrustDomainID string

	// ForeignTrustDomain identifies the federation link within the given
	// trust domain to refresh. Required.
	ForeignTrustDomain spiffeid.TrustDomain
}

type RefreshLinkResult struct{}

type LinkFilter struct {
	// TrustDomainID filters the links to those belonging to the given
	// trust domain.
	TrustDomainID *string
}

type LinkStatus struct {
	// TrustDomainID identifies the trust domain (by ID) that the federation
	// link belongs to. Required.
	TrustDomainID string

	// TrustDomainID identifies the trust domain (by name) that the federation
	// link belongs to. Required.
	TrustDomainName string

	// Link is the federation link configuration.
	Link Link

	// LastPoll is the status of the last federation endpoint poll. If nil,
	// then no poll status is available.
	LastPoll *PollStatus

	// LastBundleUpdate indicates the last time the bundle for the foreign
	// trust domain was updated.
	LastBundleUpdate time.Time

	// CreatedAt is the timestamp when the link was created.
	CreatedAt time.Time
}

type Link struct {
	// ForeignTrustDomain is the trust domain federated with.
	ForeignTrustDomain spiffeid.TrustDomain

	// Endpoint describes the federation endpoint for the foreign trust domain.
	Endpoint Endpoint
}

type Endpoint struct {
	// URL is the HTTPS URL for the foreign trust domain bundle.
	URL string

	// Profile describes how to authenticate the URL.
	Profile Profile
}

type Profile interface {
	federationProfile()
}

type HTTPSWebProfile struct{}

func (HTTPSWebProfile) federationProfile() {}

type PollStatus struct {
	// Timestamp indicates when the last poll occurred.
	Timestamp time.Time

	// Error is a high-level description of the error encountered during
	// polling. If no error was encountered it will be empty.
	Error string

	// HTTPLog contains details of the HTTP request that polled the federation
	// endpoint. It is only intended to be used by operators in debugging
	// polling errors.
	HTTPLog string
}

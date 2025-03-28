package trustdomainsdk

import (
	"context"
	"time"
)

type API interface {
	// CreateTrustDomain creates a trust domain with SPIRL-managed deployments.
	CreateTrustDomain(ctx context.Context, params CreateTrustDomainParams) (*CreateTrustDomainResult, error)

	// RegisterTrustDomain registers a trust domain with self-managed
	// deployments.
	RegisterTrustDomain(ctx context.Context, params RegisterTrustDomainParams) (*RegisterTrustDomainResult, error)

	// ListTrustDomains lists trust domains.
	ListTrustDomains(ctx context.Context, params ListTrustDomainsParams) (*ListTrustDomainsResult, error)

	// DeleteTrustDomain deletes a trust domain. The trust domain cannot have
	// any active clusters.
	DeleteTrustDomain(ctx context.Context, params DeleteTrustDomainParams) (*DeleteTrustDomainResult, error)

	// TrustDomainInfo returns trust domain information.
	TrustDomainInfo(ctx context.Context, params TrustDomainInfoParams) (*TrustDomainInfoResult, error)

	// ListTrustDomainDeployments lists the trust domain deployments in the
	// organization.
	ListTrustDomainDeployments(ctx context.Context, params ListTrustDomainDeploymentsParams) (*ListTrustDomainDeploymentsResult, error)

	// DeleteTrustDomainDeployment deletes a trust domain deployment.
	DeleteTrustDomainDeployment(ctx context.Context, params DeleteTrustDomainDeploymentParams) (*DeleteTrustDomainDeploymentResult, error)

	// ListTrustDomainKeys lists trust domain keys.
	ListTrustDomainKeys(ctx context.Context, params ListTrustDomainKeysParams) (*ListTrustDomainKeysResult, error)

	// CreateTrustDomainKey creates a trust domain key.
	CreateTrustDomainKey(ctx context.Context, params CreateTrustDomainKeyParams) (*CreateTrustDomainKeyResult, error)

	// DeleteTrustDomainKey deletes a trust domain key.
	DeleteTrustDomainKey(ctx context.Context, params DeleteTrustDomainKeyParams) (*DeleteTrustDomainKeyResult, error)

	// EnableTrustDomainKey enables a trust domain key.
	EnableTrustDomainKey(ctx context.Context, params EnableTrustDomainKeyParams) (*EnableTrustDomainKeyResult, error)

	// DisableTrustDomainKey disables a trust domain key.
	DisableTrustDomainKey(ctx context.Context, params DisableTrustDomainKeyParams) (*DisableTrustDomainKeyResult, error)
}

type CreateTrustDomainParams struct {
	// Name is the name of the trust domain. Must be a valid trust domain
	// name as defined by the SPIFFE specification. Required.
	//
	// See: https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md#21-trust-domain
	Name string

	// Description is the trust domain description. Optional.
	Description *string
}

type CreateTrustDomainResult struct {
	// ID identifies the created trust domain.
	ID string

	// AgentEndpointURL is the endpoint agents use to connect to the
	// trust domain.
	AgentEndpointURL string
}

type RegisterTrustDomainParams struct {
	// Name is the name of the trust domain. Must be a valid trust domain
	// name as defined by the SPIFFE specification. Required.
	//
	// See: https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md#21-trust-domain
	Name string

	// Description is the trust domain description. Optional.
	Description *string
}

type RegisterTrustDomainResult struct {
	// ID identifies the created trust domain.
	ID string
}

type ListTrustDomainsParams struct {
	// Filter filters the results.
	Filter TrustDomainFilter

	// View adjusts details included in the results.
	View TrustDomainView
}

type ListTrustDomainsResult struct {
	TrustDomains []TrustDomain
}

type TrustDomainInfoParams struct {
	// ID is the ID of the trust domain to delete. Required.
	ID string
}

type TrustDomainInfoResult struct {
	TrustDomain TrustDomain
}

type DeleteTrustDomainParams struct {
	// ID is the ID of the trust domain to delete. Required.
	ID string
}

type DeleteTrustDomainResult struct{}

type ListTrustDomainDeploymentsParams struct {
	// Filter filters the results.
	Filter TrustDomainDeploymentFilter
}

type ListTrustDomainDeploymentsResult struct {
	TrustDomainDeployments []TrustDomainDeployment
}

type DeleteTrustDomainDeploymentParams struct {
	// DeploymentName is the name of the deployment to delete. Required.
	DeploymentName string

	// TrustDomainID is the name of the trust domain ID to delete. Required.
	TrustDomainID string

	// Force, if true, deletes the trust domain deployment regardless of state.
	// Optional.
	Force *bool
}

type DeleteTrustDomainDeploymentResult struct{}

type CreateTrustDomainKeyParams struct {
	// TrustDomainID identifies the trust domain the new key will reside in.
	// Required.
	TrustDomainID string

	// DeploymentName is the name of the deployment the key is for. A
	// deployment may have more than one key to facilitate rotation. Required.
	DeploymentName string

	// PublicKey is the public key component of the trust domain key. Currently
	// only ed25519.PublicKey is supported. Required.
	PublicKey any
}

type CreateTrustDomainKeyResult struct {
	// ID identifies the newly created trust domain key.
	ID string
}

type ListTrustDomainKeysParams struct {
	// Filter filters the results.
	Filter TrustDomainKeyFilter
}

type ListTrustDomainKeysResult struct {
	TrustDomainKeys []TrustDomainKey
}

type EnableTrustDomainKeyParams struct {
	// TrustDomainID identifies the trust domain the key to enable resides in.
	// Required.
	TrustDomainID string

	// TrustDomainKeyID identifies the key to enable. Required.
	TrustDomainKeyID string
}

type EnableTrustDomainKeyResult struct{}

type DisableTrustDomainKeyParams struct {
	// TrustDomainID identifies the trust domain the key to enable resides in.
	// Required.
	TrustDomainID string

	// TrustDomainKeyID identifies the key to enable. Required.
	TrustDomainKeyID string
}

type DisableTrustDomainKeyResult struct{}

type DeleteTrustDomainKeyParams struct {
	// TrustDomainID identifies the trust domain the key to enable resides in.
	// Required.
	TrustDomainID string

	// TrustDomainKeyID identifies the key to enable. Required.
	TrustDomainKeyID string

	// Force, if true, deletes the trust domain key regardless of state.
	// Optional.
	Force *bool
}

type DeleteTrustDomainKeyResult struct{}

type TrustDomainFilter struct {
	// Name filters the trust domains to those with the given name. Optional.
	Name *string
}

type TrustDomainView struct {
	// IncludeStatus, if true, includes additional status information for
	// the trust domain.
	IncludeStatus bool
}

type TrustDomain struct {
	// ID identifies the trust domain deployment.
	ID string

	// CreatedAt is the timestamp when the trust domain was created.
	CreatedAt time.Time

	// UpdatedAt is the timestamp when the trust domain was last updated.
	UpdatedAt time.Time

	// Name is the name of the trust domain.
	Name string

	// Description describes the trust domain.
	Description string

	// State is the state of the trust domain.
	State TrustDomainState

	// IsSelfManaged indicates whether the trust domain is managed by SPIRL
	// or self-managed by the organization.
	IsSelfManaged bool

	// JWTIssuer is the issuer claim to include in JWT-SVIDs signed for this
	// trust domain.
	JWTIssuer string

	// URLs contain URLs related to the trust domain.
	URLs TrustDomainURLs

	// Status is optional status information for the trust domain. It is
	// only set via list operations when the IncludeStatus view option is set.
	Status *TrustDomainStatus
}

type TrustDomainURLs struct {
	// AgentEndpointURL is the URL that agents use to reach trust domain servers
	// for the trust domain. It is empty when the trust domain is self-managed.
	AgentEndpointURL string

	// SPIFFEBundleEndpointURL is the URL to use to retrieve the SPIFFE
	// bundle for the trust domain, which contains the public keys used to
	// sign X509-SVIDs and JWT-SVIDs.
	SPIFFEBundleEndpointURL string

	// OIDCDiscoveryEndpointURL is the URL hosting the well-known OIDC discovery
	// document for use with OIDC federation.
	OIDCDiscoveryEndpointURL string

	// JWKSEndpointURL is the URL hosting the JWKS containing public keys used
	// to sign JWT-SVIDs. It is the same URL referenced in the jwks_url value in
	// the OIDC discovery document hosted at OIDCDiscoveryEndpointURL.
	JWKSEndpointURL string
}

type TrustDomainState string

const (
	// TrustDomainInitialized indicates that the trust domain is still
	// initializing and is not ready for use.
	TrustDomainInitializing TrustDomainState = "initializing"

	// TrustDomainProvisioning indicates that the trust domain is still
	// being provisioned and is not ready for use.
	TrustDomainProvisioning TrustDomainState = "provisioning"

	// TrustDomainAvailable indicates that the trust domain is ready for use.
	TrustDomainAvailable TrustDomainState = "available"

	// TrustDomainUpgrading indicates that the trust domain is ready but an
	// upgrade is in process.
	TrustDomainUpgrading TrustDomainState = "upgrading"
)

type TrustDomainStatus struct {
	// ClustersTotal is how many clusters are in the trust domain.
	ClustersTotal int64

	// ClustersActive is how many clusters in the trust domain appear to be
	// in active use.
	ClustersActive int64

	// FederationLinksTotal is how many foreign trust domains the trust domain
	// federations with.
	FederationLinksTotal int64

	// FederationLinksActive is how many foreign trust domains links appear to
	// be active. This is based on the ability for SPIRL to contact the
	// federated trust domain for bundle information. If this count is less
	// than the total, then the ListLinks method in the Federation API can
	// be used to determine which links are inactive.
	FederationLinksActive int64
}

type TrustDomainDeploymentFilter struct {
	// TrustDomainID filters deployments to those belonging to the given trust
	// domain. Optional.
	TrustDomainID *string
}

type TrustDomainDeployment struct {
	// ID identifies the trust domain deployment.
	ID string

	// TrustDomainID identifies the trust domain the deployment belongs to.
	TrustDomainID string

	// OrgID identifies the org the deployment belongs to.
	OrgID string

	// Name is the name of the deployment.
	Name string

	// LastAtIntent identifies last successful sync to the deployment of the
	// intended state.
	LastAtIntent time.Time

	// ConfigurationState is the state of deployment configuration.
	ConfigurationState TrustDomainDeploymentConfigurationState
}

type TrustDomainDeploymentConfigurationState string

const (
	// TrustDomainDeploymentConfigurationStateUpToDate indicates that the
	// trust domain deployment is actively participating in configuration
	// synchronization.
	TrustDomainDeploymentConfigurationStateUpToDate = "up-to-date"

	// TrustDomainDeploymentConfigurationStateStale indicates that the trust
	// domain deployment has not successfully participated in configuration
	// synchronization for some time and may have stale configuration.
	TrustDomainDeploymentConfigurationStateStale = "stale"
)

type TrustDomainKeyFilter struct {
	// TrustDomainID filters the trust domains keys to those residing in the
	// trust domain identified by the provided ID. Optional.
	TrustDomainID *string

	// DeploymentName filters the trust domains keys to those for the
	// given deployment. Optional.
	DeploymentName *string
}

type TrustDomainKey struct {
	// ID is the ID of the trust domain key.
	ID string

	// TrustDomainID identifies the trust domain the key resides in.
	TrustDomainID string

	// DeploymentName identifies the trust domain deployment within the
	// trust domain that the key belongs to.
	DeploymentName string

	// State is the trust domain key state.
	State TrustDomainKeyState

	// PublicKey is the public key component of the trust domain key. Currently
	// this is an ed25519.PublicKey.
	PublicKey any
}

type TrustDomainKeyState string

const (
	// TrustDomainKeyActive indicates that the trust domain key is active
	// and can be used for authentication with SPIRL.
	TrustDomainKeyActive TrustDomainKeyState = "active"

	// TrustDomainKeyInactive indicates that the trust domain key is inactive
	// and cannot be used for authentication with SPIRL.
	TrustDomainKeyInactive TrustDomainKeyState = "inactive"
)

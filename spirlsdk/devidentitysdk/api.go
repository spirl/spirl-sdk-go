package devidentitysdk

import (
	"context"
	"time"
)

type API interface {
	// AddDevIdentityPolicy adds a Developer Identity policy to the organization.
	AddDevIdentityPolicy(ctx context.Context, params AddDevIdentityPolicyParams) (*AddDevIdentityPolicyResult, error)

	// UpdateDevIdentityPolicy updates a Developer Identity policy.
	UpdateDevIdentityPolicy(ctx context.Context, params UpdateDevIdentityPolicyParams) (*UpdateDevIdentityPolicyResult, error)

	// ListDevIdentityPolicies lists Developer Identity policies.
	ListDevIdentityPolicies(ctx context.Context, params ListDevIdentityPoliciesParams) (*ListDevIdentityPoliciesResult, error)

	// DeleteDevIdentityPolicy deletes a Developer Identity policy.
	DeleteDevIdentityPolicy(ctx context.Context, params DeleteDevIdentityPolicyParams) (*DeleteDevIdentityPolicyResult, error)

	// AddDevIdentityOIDCConfig adds a Developer Identity OIDC configuration to the organization.
	AddDevIdentityOIDCConfig(ctx context.Context, params AddDevIdentityOIDCConfigParams) (*AddDevIdentityOIDCConfigResult, error)

	// UpdateDevIdentityOIDCConfig updates a Developer Identity OIDC configuration.
	UpdateDevIdentityOIDCConfig(ctx context.Context, params UpdateDevIdentityOIDCConfigParams) (*UpdateDevIdentityOIDCConfigResult, error)

	// ListDevIdentityOIDCConfigs lists Developer Identity OIDC configurations.
	ListDevIdentityOIDCConfigs(ctx context.Context, params ListDevIdentityOIDCConfigsParams) (*ListDevIdentityOIDCConfigsResult, error)

	// DeleteDevIdentityOIDCConfig deletes a Developer Identity OIDC configuration.
	DeleteDevIdentityOIDCConfig(ctx context.Context, params DeleteDevIdentityOIDCConfigParams) (*DeleteDevIdentityOIDCConfigResult, error)

	// EnablePolicy enables a Developer Identity policy on a trust domain.
	EnablePolicy(ctx context.Context, params EnablePolicyParams) (*EnablePolicyResult, error)

	// DisablePolicy disables Developer Identity policies on a trust domain.
	DisablePolicy(ctx context.Context, params DisablePolicyParams) (*DisablePolicyResult, error)

	// UnifiedAccessStatus returns Developer Identity status for trust domains.
	UnifiedAccessStatus(ctx context.Context, params UnifiedAccessStatusParams) (*UnifiedAccessStatusResult, error)
}

type DevIDPolicy struct {
	// ID identifies the policy.
	ID string

	// Name is the human-friendly name of the policy.
	Name string

	// DevOIDCConfigID identifies the OIDC configuration used with the policy.
	DevOIDCConfigID string

	// DevOIDCConfigName is the human-friendly name of the OIDC configuration
	// in use by the policy.
	DevOIDCConfigName string

	// ClaimsFilter declares claims that are required on the OIDC token.
	ClaimsFilter ClaimsFilter

	// PathTemplate controls how the SPIFFE ID is generated for the Developer
	// Identity.
	PathTemplate string

	// SVIDTTL is the lifetime of SVIDs issued against this policy.
	SVIDTTL time.Duration
}

type AddDevIdentityPolicyParams struct {
	// Name is the human-friendly name of the policy.
	Name string

	// DevOIDCConfigID identifies the OIDC configuration to use with the policy.
	DevOIDCConfigID string

	// ClaimsFilter declares claims that are required on the OIDC token.
	ClaimsFilter *ClaimsFilter

	// PathTemplate controls how the SPIFFE ID is generated for the Developer
	// Identity.
	PathTemplate *string

	// SVIDTTL is the lifetime of SVIDs issued against this policy.
	SVIDTTL *time.Duration
}

type AddDevIdentityPolicyResult struct {
	// ID identifies the Developer Identity policy that was added.
	ID string
}

type UpdateDevIdentityPolicyParams struct {
	// ID identifies the Developer Identity policy to update.
	ID string

	// DevOIDCConfigID, if non-nil, is the Developer Identity OIDC
	// configuration update to.
	DevOIDCConfigID *string

	// ClaimsFilter, if non-nil, is the claims filter to update to.
	ClaimsFilter *ClaimsFilter

	// PathTemplate, if non-nil, is the path template claims filter to update to.
	PathTemplate *string

	// SVIDTTL, if non-nil, is the SVID time-to-live to update to.
	SVIDTTL *time.Duration
}

type UpdateDevIdentityPolicyResult struct{}

type ListDevIdentityPoliciesParams struct {
	// Filter filters the results.
	Filter DevIDPolicyFilter
}

type ListDevIdentityPoliciesResult struct {
	// DevIDPolicies are the Developer Identity policies.
	DevIDPolicies []DevIDPolicy
}

type DeleteDevIdentityPolicyParams struct {
	// ID identifies the Developer Identity policy to delete.
	ID string
}

type DeleteDevIdentityPolicyResult struct{}

type DevIDPolicyFilter struct {
	// Name filters the policies by the given name.
	Name *string
}

type ClaimsFilter struct {
	// Filters are the claim filters to apply.
	Filters []ClaimFilter
}

type ClaimFilter struct {
	// Key identifies the name of the claim in the token to compare against.
	Key string

	// Value is the value to compare against the claim value in the token.
	Value string

	// Operator defines how to compare the filter value against the claim
	// value.
	Operator ClaimComparisonOperator
}

type ClaimComparisonOperator string

const (
	// ClaimComparisonOperatorEqual means to filter based on equality.
	ClaimComparisonOperatorEqual = ClaimComparisonOperator("equal")

	// ClaimComparisonOperatorNotEqual means to filter based on inequality.
	ClaimComparisonOperatorNotEqual = ClaimComparisonOperator("not-equal")
)

type DevOIDCConfig struct {
	// ID identifies the OIDC configuration.
	ID string

	// Name is the human-friendly name of the OIDC configuration.
	Name string

	// IssuerURL is the OIDC issuer.
	IssuerURL string

	// ClientID is the OIDC client ID used to do OIDC token exchange.
	ClientID string

	// ClientAuthMethod describes how to authenticate with the IDP to do
	// OIDC token exchange.
	ClientAuthMethod ClientAuthMethod

	// ClientSecret is the OIDC client secret for authenticating with the IDP.
	// It is set when using the following ClientAuthMethods:
	// - ClientAuthMethodSecretBasic
	// - ClientAuthMethodSecretPost
	// - ClientAuthMethodSecretJWT
	// - ClientAuthMethodSecretAutoDetect
	ClientSecret string

	// ClientPrivateKey is the private key used to authenticate with the IDP.
	// It is only set when using ClientAuthMethodPrivateKeyJWT.
	ClientPrivateKey string

	// ClientPrivateKeyID identifies the private key used to authenticate with
	// the IDP. It is only set when using ClientAuthMethodPrivateKeyJWT.
	ClientPrivateKeyID string
}

type DevOIDCConfigFilter struct {
	// Name filters the OIDC configurations by the given name.
	Name *string
}

type ClientAuthMethod string

const (
	// ClientAuthMethodNone indicates that no client authentication with the
	// IDP is required.
	ClientAuthMethodNone = ClientAuthMethod("")

	// ClientAuthMethodSecretBasic indicates
	ClientAuthMethodSecretBasic      = ClientAuthMethod("secret-basic")
	ClientAuthMethodSecretPost       = ClientAuthMethod("secret-post")
	ClientAuthMethodSecretJWT        = ClientAuthMethod("secret-jwt")
	ClientAuthMethodPrivateKeyJWT    = ClientAuthMethod("private-key-jwt")
	ClientAuthMethodSecretAutoDetect = ClientAuthMethod("secret-auto-detect")
)

type AddDevIdentityOIDCConfigParams struct {
	// Name is the human-friendly name of the OIDC configuration.
	Name string

	// IssuerURL is the OIDC issuer.
	IssuerURL string

	// ClientID is the OIDC client ID used to do OIDC token exchange.
	ClientID string

	// ClientAuthMethod describes how to authenticate with the IDP to do
	// OIDC token exchange.
	ClientAuthMethod ClientAuthMethod

	// ClientSecret is the OIDC client secret for authenticating with the IDP.
	// It is set when using the following ClientAuthMethods:
	// - ClientAuthMethodSecretBasic
	// - ClientAuthMethodSecretPost
	// - ClientAuthMethodSecretJWT
	// - ClientAuthMethodSecretAutoDetect
	ClientSecret *string

	// ClientPrivateKey is the private key used to authenticate with the IDP.
	// It is only set when using ClientAuthMethodPrivateKeyJWT.
	ClientPrivateKey *string

	// ClientPrivateKeyID identifies the private key used to authenticate with
	// the IDP. It is only set when using ClientAuthMethodPrivateKeyJWT.
	ClientPrivateKeyID *string
}

type AddDevIdentityOIDCConfigResult struct {
	// ID identifies the OIDC configuration that was added.
	ID string
}

type UpdateDevIdentityOIDCConfigParams struct {
	// ID identifies the OIDC configuration to update.
	ID string

	// IssuerURL is the OIDC issuer.
	IssuerURL *string

	// ClientID is the OIDC client ID used to do OIDC token exchange.
	ClientID *string

	// ClientAuthMethod describes how to authenticate with the IDP to do
	// OIDC token exchange.
	ClientAuthMethod *ClientAuthMethod

	// ClientSecret is the OIDC client secret for authenticating with the IDP.
	// It is set when using the following ClientAuthMethods:
	// - ClientAuthMethodSecretBasic
	// - ClientAuthMethodSecretPost
	// - ClientAuthMethodSecretJWT
	// - ClientAuthMethodSecretAutoDetect
	ClientSecret *string

	// ClientPrivateKey is the private key used to authenticate with the IDP.
	// It is only set when using ClientAuthMethodPrivateKeyJWT.
	ClientPrivateKey *string

	// ClientPrivateKeyID identifies the private key used to authenticate with
	// the IDP. It is only set when using ClientAuthMethodPrivateKeyJWT.
	ClientPrivateKeyID *string
}

type UpdateDevIdentityOIDCConfigResult struct{}

type ListDevIdentityOIDCConfigsParams struct {
	// Filter filters the results.
	Filter DevOIDCConfigFilter
}

type ListDevIdentityOIDCConfigsResult struct {
	// DevOIDCConfigs are the Developer Identity OIDC configurations.
	DevOIDCConfigs []DevOIDCConfig
}

type DeleteDevIdentityOIDCConfigParams struct {
	// ID identifies the Developer Identity OIDC configuration to delete.
	ID string
}

type DeleteDevIdentityOIDCConfigResult struct{}

type EnablePolicyParams struct {
	// TrustDomainID identifies the trust domain to enable Developer Identity
	// on.
	TrustDomainID string

	// PolicyID identifies the Developer Identity policy to use.
	PolicyID string
}

type EnablePolicyResult struct{}

type DisablePolicyParams struct {
	// TrustDomainID identifies the trust domain to disable Developer Identity
	// on.
	TrustDomainID string
}

type DisablePolicyResult struct {
	// PolicyName is the name of the policy that was disabled.
	PolicyName string
}

type UnifiedAccessStatusParams struct {
	// Filter filters the results.
	Filter UnifiedAccessFilter
}

type UnifiedAccessStatusResult struct {
	// UnifiedAccessFilter are the returned statuses.
	UnifiedAccessStatuses []UnifiedAccessStatus
}

type UnifiedAccessFilter struct {
	// TrustDomainID filters the unified access status to the trust
	// domain with the given ID.
	TrustDomainID *string
}

type UnifiedAccessStatus struct {
	// TrustDomainID identifies the trust domain.
	TrustDomainID string

	// TrustDomainName is the name of the trust domain.
	TrustDomainName string

	// Enabled is whether Developer Identity is enabled on the trust domain.
	Enabled bool

	// EnabledPolicyID identifies which Developer Identity policy is enabled on
	// the trust domain.
	EnabledPolicyID string

	// EnabledPolicyName is the name of the Developer Identity policy enabled
	// on the trust domain.
	EnabledPolicyName string
}

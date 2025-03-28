package providerattestationsdk

import "context"

type API interface {
	// CreateConfig creates a new provider attestation configuration.
	CreateConfig(ctx context.Context, params CreateConfigParams) (*CreateConfigResult, error)

	// ListConfigs returns a list of provider attestation configurations with the
	// given the filters.
	ListConfigs(ctx context.Context, params ListConfigsParams) (*ListConfigsResult, error)

	// GetConfig returns a provider attestation configuration with the given ID.
	GetConfig(ctx context.Context, params GetConfigParams) (*GetConfigResult, error)

	// DeleteConfig removes a provider attestation configuration with the given
	// ID.
	DeleteConfig(ctx context.Context, params DeleteConfigParams) (*DeleteConfigResult, error)
}

type CreateConfigParams struct {
	// Name is the name of the new provider attestation config. It must be unique
	// within the given trust domain. Required.
	Name string
	// AWS is the configuration for AWS provider attestation. Required if this is
	// an AWS attestation config.
	AWS *AWSProviderAttestationConfig
}

type CreateConfigResult struct {
	// Config is the provider attestation config.
	Config ProviderAttestation
}

type ListConfigsParams struct {
	// Filter filters the results.
	Filter ProviderAttestationFilter
}

type ListConfigsResult struct {
	// Configs is a list of provider attestation configs.
	Configs []ProviderAttestation
}

type GetConfigParams struct {
	// ID is the id of the provider attestation config.
	ID string
}

type GetConfigResult struct {
	// Config is the provider attestation config.
	Config ProviderAttestation
}

type DeleteConfigParams struct {
	// ID is the id of the provider attestation config.
	ID string
}

type DeleteConfigResult struct{}

type ProviderAttestation struct {
	// ID is the id of the provider attestation config.
	ID string
	// Name is the name of the provider attestation config.
	Name string
	// AWS is the configuration for AWS provider attestation if this is an AWS
	// attestation config.
	AWS *AWSProviderAttestationConfig
}

type AWSProviderAttestationConfig struct {
	// RoleArn is the ARN of the AWS role to assume, this role needs to be
	// provisioned separately, and should have the necessary permissions to query
	// EC2 instances.
	RoleArn string
}

type ProviderAttestationFilter struct {
	// Name is the name of the provider attestation config. Optional.
	Name *string
}

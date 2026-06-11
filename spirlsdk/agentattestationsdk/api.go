package agentattestationsdk

import "context"

// API provides operations for managing agent attestation configurations.
//
// Agent attestation configs define how SPIRL agents prove their identity
// to the SPIRL server. Currently, Kubernetes Projected Service Account
// Token (PSAT) is the supported attestation method.
type API interface {
	// CreateConfig creates a new agent attestation configuration.
	CreateConfig(ctx context.Context, params CreateConfigParams) (*CreateConfigResult, error)

	// ListConfigs returns all agent attestation configurations.
	ListConfigs(ctx context.Context, params ListConfigsParams) (*ListConfigsResult, error)

	// GetConfig returns an agent attestation configuration by ID.
	GetConfig(ctx context.Context, params GetConfigParams) (*GetConfigResult, error)

	// DeleteConfig removes an agent attestation configuration by ID.
	DeleteConfig(ctx context.Context, params DeleteConfigParams) (*DeleteConfigResult, error)
}

// CreateConfigParams contains parameters for creating an agent attestation
// configuration.
type CreateConfigParams struct {
	// K8SPSAT is the Kubernetes Projected Service Account Token configuration.
	// Required.
	K8SPSAT *K8SPSATConfig
}

// CreateConfigResult contains the result of creating an agent attestation
// configuration.
type CreateConfigResult struct {
	// Config is the created agent attestation configuration.
	Config AgentAttestationConfig
}

// ListConfigsParams contains parameters for listing agent attestation
// configurations.
type ListConfigsParams struct{}

// ListConfigsResult contains the result of listing agent attestation
// configurations.
type ListConfigsResult struct {
	// Configs is the list of agent attestation configurations.
	Configs []AgentAttestationConfig
}

// GetConfigParams contains parameters for getting an agent attestation
// configuration.
type GetConfigParams struct {
	// ID is the identifier of the agent attestation configuration. Required.
	ID string
}

// GetConfigResult contains the result of getting an agent attestation
// configuration.
type GetConfigResult struct {
	// Config is the agent attestation configuration.
	Config AgentAttestationConfig
}

// DeleteConfigParams contains parameters for deleting an agent attestation
// configuration.
type DeleteConfigParams struct {
	// ID is the identifier of the agent attestation configuration. Required.
	ID string
}

// DeleteConfigResult contains the result of deleting an agent attestation
// configuration.
type DeleteConfigResult struct{}

// AgentAttestationConfig represents an agent attestation configuration.
type AgentAttestationConfig struct {
	// ID is the unique identifier of the configuration.
	ID string

	// K8SPSAT is the Kubernetes PSAT configuration, if this is a K8S PSAT
	// attestation config.
	K8SPSAT *K8SPSATConfig
}

// K8SPSATConfig contains the configuration for Kubernetes Projected Service
// Account Token (PSAT) agent attestation.
type K8SPSATConfig struct {
	// OIDCIssuerURL is the OIDC issuer URL for the Kubernetes cluster.
	// This is used to validate the projected service account tokens.
	// For EKS, this is typically
	// https://oidc.eks.<region>.amazonaws.com/id/....
	OIDCIssuerURL string

	// ServiceAccountName is the name of the Kubernetes service account
	// used by the SPIRL agent.
	ServiceAccountName string

	// ServiceAccountNamespace is the namespace where the SPIRL agent
	// service account is located.
	ServiceAccountNamespace string
}

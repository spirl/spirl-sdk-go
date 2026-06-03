package configsdk

import (
	"context"
	"time"
)

type API interface {
	// GetClusterConfig gets cluster-level configuration.
	GetClusterConfig(ctx context.Context, params GetClusterConfigParams) (*GetClusterConfigResult, error)

	// GetOrgConfig gets organization-level configuration.
	GetOrgConfig(ctx context.Context, params GetOrgConfigParams) (*GetOrgConfigResult, error)

	// GetTrustDomainConfig gets trust domain-level configuration.
	GetTrustDomainConfig(ctx context.Context, params GetTrustDomainConfigParams) (*GetTrustDomainConfigResult, error)

	// GetTrustDomainDeploymentConfig gets trust domain deployment-level configuration.
	GetTrustDomainDeploymentConfig(ctx context.Context, params GetTrustDomainDeploymentConfigParams) (*GetTrustDomainDeploymentConfigResult, error)

	// UpdateClusterConfig updates cluster-level configuration.
	UpdateClusterConfig(ctx context.Context, params UpdateClusterConfigParams) (*UpdateClusterConfigResult, error)

	// UpdateOrgConfig updates organization-level configuration.
	UpdateOrgConfig(ctx context.Context, params UpdateOrgConfigParams) (*UpdateOrgConfigResult, error)

	// UpdateTrustDomainConfig updates trust domain-level configuration.
	UpdateTrustDomainConfig(ctx context.Context, params UpdateTrustDomainConfigParams) (*UpdateTrustDomainConfigResult, error)

	// UpdateTrustDomainDeploymentConfig updates trust domain deployment-level configuration.
	UpdateTrustDomainDeploymentConfig(ctx context.Context, params UpdateTrustDomainDeploymentConfigParams) (*UpdateTrustDomainDeploymentConfigResult, error)
}

type GetOrgConfigParams struct{}

type GetOrgConfigResult struct {
	// Config is the organization-level configuration.
	Config Config
}

type UpdateOrgConfigParams struct {
	// SectionUpdates contains self-describing YAML documents for sections to update.
	SectionUpdates []string

	// Prune removes existing sections that are not included in SectionUpdates.
	Prune bool

	// ExpectedVersion applies optimistic concurrency checks when set.
	ExpectedVersion string

	// ValidateOnly validates changes without persisting them.
	ValidateOnly bool
}

type UpdateOrgConfigResult struct {
	// Config is the resulting organization-level configuration.
	Config Config
}

type GetTrustDomainConfigParams struct {
	// TrustDomainID identifies the trust domain.
	TrustDomainID string
}

type GetTrustDomainConfigResult struct {
	// Config is the trust domain-level configuration.
	Config Config
}

type UpdateTrustDomainConfigParams struct {
	// TrustDomainID identifies the trust domain.
	TrustDomainID string

	// SectionUpdates contains self-describing YAML documents for sections to update.
	SectionUpdates []string

	// Prune removes existing sections that are not included in SectionUpdates.
	Prune bool

	// ExpectedVersion applies optimistic concurrency checks when set.
	ExpectedVersion string

	// ValidateOnly validates changes without persisting them.
	ValidateOnly bool
}

type UpdateTrustDomainConfigResult struct {
	// Config is the resulting trust domain-level configuration.
	Config Config
}

type GetClusterConfigParams struct {
	// ClusterID identifies the cluster.
	ClusterID string
}

type GetClusterConfigResult struct {
	// Config is the cluster-level configuration.
	Config Config
}

type UpdateClusterConfigParams struct {
	// ClusterID identifies the cluster.
	ClusterID string

	// SectionUpdates contains self-describing YAML documents for sections to update.
	SectionUpdates []string

	// Prune removes existing sections that are not included in SectionUpdates.
	Prune bool

	// ExpectedVersion applies optimistic concurrency checks when set.
	ExpectedVersion string

	// ValidateOnly validates changes without persisting them.
	ValidateOnly bool
}

type UpdateClusterConfigResult struct {
	// Config is the resulting cluster-level configuration.
	Config Config
}

type GetTrustDomainDeploymentConfigParams struct {
	// TrustDomainDeploymentID identifies the trust domain deployment.
	TrustDomainDeploymentID string
}

type GetTrustDomainDeploymentConfigResult struct {
	// Config is the trust domain deployment-level configuration.
	Config Config
}

type UpdateTrustDomainDeploymentConfigParams struct {
	// TrustDomainDeploymentID identifies the trust domain deployment.
	TrustDomainDeploymentID string

	// SectionUpdates contains self-describing YAML documents for sections to update.
	SectionUpdates []string

	// Prune removes existing sections that are not included in SectionUpdates.
	Prune bool

	// ExpectedVersion applies optimistic concurrency checks when set.
	ExpectedVersion string

	// ValidateOnly validates changes without persisting them.
	ValidateOnly bool
}

type UpdateTrustDomainDeploymentConfigResult struct {
	// Config is the resulting trust domain deployment-level configuration.
	Config Config
}

type Config struct {
	// UpdatedAt is when this configuration was last updated.
	UpdatedAt time.Time

	// Version is the opaque version identifier for the configuration.
	Version string

	// Sections are the configured sections.
	Sections []Section
}

type Section struct {
	// Name is the section name (for example, "AttributeRedaction").
	Name string

	// Schema is the section schema version (for example, "v1").
	Schema string

	// YAMLValue is the self-describing YAML document for this section.
	YAMLValue string
}

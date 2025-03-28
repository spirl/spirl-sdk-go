package clustersdk

import (
	"context"
	"time"
)

type API interface {
	// CreateCluster creates a new cluster in a trust domain.
	CreateCluster(ctx context.Context, params CreateClusterParams) (*CreateClusterResult, error)

	// ListClusters lists clusters.
	ListClusters(ctx context.Context, params ListClustersParams) (*ListClustersResult, error)

	// DeleteCluster deletes a cluster in a trust domain.
	DeleteCluster(ctx context.Context, params DeleteClusterParams) (*DeleteClusterResult, error)

	// NewClusterVersion creates a new version for a cluster.
	NewClusterVersion(ctx context.Context, params NewClusterVersionParams) (*NewClusterVersionResult, error)

	// ActivateClusterVersion activates a cluster version.
	ActivateClusterVersion(ctx context.Context, params ActivateClusterVersionParams) (*ActivateClusterVersionResult, error)

	// DeactivateClusterVersion deactivates a cluster version.
	DeactivateClusterVersion(ctx context.Context, params DeactivateClusterVersionParams) (*DeactivateClusterVersionResult, error)

	// DeleteClusterVersion deletes a cluster version. By default an active
	// cluster cannot be deleted unless forced.
	DeleteClusterVersion(ctx context.Context, params DeleteClusterVersionParams) (*DeleteClusterVersionResult, error)

	// ListClusterVersions lists cluster versions in a cluster.
	ListClusterVersions(ctx context.Context, params ListClusterVersionsParams) (*ListClusterVersionsResult, error)

	// ListWorkloads lists the workloads in a cluster.
	ListWorkloads(ctx context.Context, params ListWorkloadsParams) (*ListWorkloadsResult, error)

	// ListNodes lists the nodes in a cluster.
	ListNodes(ctx context.Context, params ListNodesParams) (*ListNodesResult, error)
}

type CreateClusterParams struct {
	// TrustDomainID identifies the trust domain the new cluster will belong
	// to. Required.
	TrustDomainID string

	// Name is the name of the new cluster. It must be unique within the given
	// trust domain. Required.
	Name string

	// Platform is the platform that will run the cluster. Required.
	Platform Platform

	// PublicKey is the public key for the cluster. Currently only
	// ed25519.PublicKey keys are supported. Required.
	PublicKey any

	// Description is a description of the cluster. Optional.
	Description *string

	// PathTemplate is custom path template used to formulate the path
	// component of SPIFFE IDs for SVIDs issued by this cluster. If unset, a
	// default path template will be used based on the given platform.
	// Optional.
	PathTemplate *string

	// CICDProfileName identifies the CICD profile to use with the cluster. See
	// the CICD API for more information on CICD profiles. This field is
	// ignored for cluster platforms other than Linux clusters. Optional.
	CICDProfileName *string

	// X509CustomizationTemplate customizes X509-SVIDs issued by this cluster.
	// Optional.
	X509CustomizationTemplate *string

	// ProviderAttestationConfigID identifies the provider attestation to
	// use with this cluster.
	ProviderAttestationConfigID *string
}

type CreateClusterResult struct {
	// ClusterVersionID identifies the initial cluster version for the newly
	// created cluster.
	ClusterVersionID string

	// Deployment contains information for deploying SPIRL system components in
	// the new cluster. The deployment information is platform specific and one
	// of the following types:
	// - KubernetesDeployment
	// - VMDeployment
	Deployment Deployment
}

type ListClustersParams struct {
	// Filter filters the results.
	Filter ClusterFilter
}

type ListClustersResult struct {
	Clusters []Cluster
}

type DeleteClusterParams struct {
	// ID identifies the cluster to delete.
	ID string
}

type DeleteClusterResult struct{}

type NewClusterVersionParams struct {
	// TrustDomainID identifies the trust domain the new cluster will belong
	// to. Required.
	TrustDomainID string

	// ClusterID identifies the cluster the new version will be added to.
	// Required.
	ClusterID string

	// PublicKey is the public key for the cluster. Currently only
	// ed25519.PublicKey keys are supported. Required.
	PublicKey any

	// PathTemplate is custom path template used to formulate the path
	// component of SPIFFE IDs for SVIDs issued by this cluster. If unset, a
	// default path template will be used based on the given platform.
	// Optional.
	PathTemplate *string

	// X509CustomizationTemplate customizes X509-SVIDs issued by this cluster.
	// Optional.
	// TODO: add template language documentation.
	X509CustomizationTemplate *string

	// ProviderAttestationConfigID identifies the provider attestation
	// configuration to use with this cluster.
	// Optional.
	ProviderAttestationConfigID *string
}

type NewClusterVersionResult struct {
	// ID identifies the newly created cluster version.
	ID string

	// Deployment contains information for deploying SPIRL system components in
	// the new cluster. The deployment information is platform specific and one
	// of the following types:
	// - KubernetesDeployment
	// - VMDeployment
	Deployment Deployment
}

type ActivateClusterVersionParams struct {
	// ID identifies the cluster version to activate. Required.
	ID string
}

type ActivateClusterVersionResult struct{}

type DeactivateClusterVersionParams struct {
	// ID identifies the cluster version to deactivate. Required.
	ID string
}

type DeactivateClusterVersionResult struct{}

type DeleteClusterVersionParams struct {
	// ID identifies the cluster version to deactivate. Required.
	ID string

	// Force, if true, deletes the cluster version regardless of state.
	// Optional.
	Force *bool
}

type DeleteClusterVersionResult struct{}

type ListClusterVersionsParams struct {
	// ClusterID identifies the cluster to list versions from. Required.
	ClusterID string
}

type ListClusterVersionsResult struct {
	ClusterVersions []ClusterVersion
}

type ListWorkloadsParams struct {
	// ClusterID identifies the cluster to list workloads from. Required.
	ClusterID string

	// Filter filters the results.
	Filter WorkloadFilter
}

type ListWorkloadsResult struct {
	Workloads []Workload
}

type ListNodesParams struct {
	// ClusterID identifies the cluster to list nodes from. Required.
	ClusterID string

	// Filter filters the results.
	Filter NodeFilter
}

type ListNodesResult struct {
	Nodes []Node
}

type ClusterFilter struct {
	// TrustDomainID filters clusters to those belonging to the given trust
	// domain.
	TrustDomainID *string

	// Name filters clusters to those with the given name.
	Name *string
}

type Cluster struct {
	// ID identifies the cluster.
	ID string

	// CreatedAt is a timestamp of when this cluster was created.
	CreatedAt time.Time

	// Name is the cluster name.
	Name string

	// Description is the cluster description.
	Description string

	// Platform is the platform hosting the cluster.
	Platform Platform

	// PathTemplate is path template used to formulate the path component of
	// SPIFFE IDs for SVIDs issued by this cluster.
	PathTemplate string

	// NumVersions is the number of cluster versions this cluster has.
	NumVersions int64

	// NumActiveAgents is an estimate on the number of active SPIRL Agents
	// running in this cluster.
	NumActiveAgents int64

	// EstimatedLastUsed is an estimate on the the last time a SPIRL Agent
	// belonging to this cluster was observed.
	EstimatedLastUsed time.Time

	// EstimatedNumActiveWorkloads is an estimate number of workloads observed
	// in the last 24 hrs.
	EstimatedNumActiveWorkloads int64

	// OrgID identifies the organization the cluster belongs to.
	OrgID string

	// TrustDomainID identifies the trust domain the cluster belongs to.
	TrustDomainID string

	// TrustDomainName is the name of the trust domain the cluster belongs to.
	TrustDomainName string

	// CICDProfileID identifies the CICD profile in use with the cluster.
	CICDProfileID string

	// CICDProfileName is the name of the CICD profile in use with the cluster.
	CICDProfileName string

	// X509CustomizationTemplate is the X509-SVIDs customization template
	// for the cluster.
	X509CustomizationTemplate string
}

type ClusterVersion struct {
	// ID identifies the cluster version.
	ID string

	// CreatedAt is a timestamp of when this cluster version was created.
	CreatedAt time.Time

	// ClusterID identifies the cluster this version belongs to.
	ClusterID string

	// Platform is the platform hosting the cluster version.
	Platform Platform

	// PublicKey is the public key for the cluster version.
	PublicKey any

	// Active is whether the cluster version is active.
	Active bool

	// PathTemplate is path template used to formulate the path component of
	// SPIFFE IDs for SVIDs issued by this cluster version.
	PathTemplate string

	// X509CustomizationTemplate is the X509-SVIDs customization template
	// for the cluster version.
	X509CustomizationTemplate string

	// ProviderAttestationConfigName is the name of the provider attestation.
	ProviderAttestationConfigName string

	// EstimatedLastUsed is an estimate on the the last time a SPIRL Agent
	// belonging to this cluster was observed.
	EstimatedLastUsed time.Time

	// NumActiveAgents is an estimate on the number of active SPIRL Agents
	// using this cluster version.
	NumActiveAgents int64

	// EstimatedNumActiveWorkloads is an estimate on the number of workloads
	// attached to SPIRL Agents using this cluster version.
	EstimatedNumActiveWorkloads int64
}

type WorkloadFilter struct {
	// ClusterVersionID filters the workloads to those using the given cluster
	// version. Optional.
	ClusterVersionID *string

	// IssuedWithin filters the workloads to those who have had identities
	// issued within the given time period. Optional.
	IssuedWithin *time.Duration
}

type Workload struct {
	// ID is the SPIFFE ID of the workload(s)
	ID string

	// Type is the type of SVID issued to the workload(s)
	Type WorkloadType

	// State is the estimated state of the workload(s) SVID.
	State WorkloadState

	// Count is how many workloads with this SPIFFE ID.
	Count int64

	// LastIssued is the last time a workload with this SPIFFE ID was
	// issued an SVID.
	LastIssued time.Time

	// ExpiresAt is the last observed expiration time for the SVID with this
	// SPIFFE ID.
	ExpiresAt time.Time
}

// NodeFilter filters node operations (e.g. listing).
type NodeFilter struct {
	// ClusterVersionID filters the nodes to those using the given cluster
	// version. Optional.
	ClusterVersionID *string

	// LastSeenWithin filters the nodes to those who have been seen within the
	// given time period. Optional.
	LastSeenWithin *time.Duration
}

// Node represents an agent running in the cluster.
type Node struct {
	// AgentID identifies the agent running on the node.
	AgentID string

	// Hostname is the host name of the node.
	Hostname string

	// MachineIDHash is a hash of various machine state.
	MachineIDHash string

	// IPAddress is the IP address of the node.
	IPAddress string

	// LastSeen is when the node was last seen by SPIRL Cloud.
	LastSeen time.Time
}

// Platform indicates the platform the workloads in the cluster are executing
// on. It influences how agents identify workloads among other things.
type Platform string

const (
	// PlatformKubernetes indicates a cluster running on generic Kubernetes.
	PlatformKubernetes Platform = "kubernetes"

	// PlatformIstio indicates a cluster running on Kubernetes using Istio.
	PlatformIstio Platform = "istio"

	// PlatformEKS indicates a cluster running on Kubernetes in Amazon EKS.
	PlatformEKS Platform = "eks"

	// PlatformEKSIstio indicates a cluster running on Kubernetes in Amazon EKS
	// using Istio.
	PlatformEKSIstio Platform = "eks-istio"

	// PlatformLinux indicates a cluster running on bare linux.
	PlatformLinux Platform = "linux"
)

// Deployment represents information needed to deploy SPIRL components into
// a cluster.
type Deployment interface {
	clusterDeployment()
}

// KubernetesDeployment contains information needed to deploy SPIRL system
// components into a Kubernetes cluster..
type KubernetesDeployment struct {
	// KubectlYAML is Kubernetes YAML that can be applied with "kubectl apply"
	// or an equivalent.
	KubectlYAML string
}

func (KubernetesDeployment) clusterDeployment() {}

// VMDeployment contains information needed to run SPIRL Agents directly on
// a virtual machine or a container.
type VMDeployment struct {
	// AgentConfigurationFile contains configuration that can be provided
	// to agents when launching them directly.
	AgentConfigurationFile string

	// DockerComposeYAML string contains necessary YAML for running agents
	// via Docker Compose.
	DockerComposeYAML string
}

func (VMDeployment) clusterDeployment() {}

// WorkloadType indicates what kinds of SVIDs the workload is leveraging.
type WorkloadType string

const (
	// WorkloadTypeX509 indicates a workload requesting X509-SVIDs.
	WorkloadTypeX509 = WorkloadType("x509")

	// WorkloadTypeJWT indicates a workload requesting JWT-SVIDs.
	WorkloadTypeJWT = WorkloadType("jwt")
)

// WorkloadState indicates the state that the workload is in, related to
// the expiration of SVIDs being leveraged.
type WorkloadState string

const (
	// WorkloadStateActive indicates that the workload is actively requesting
	// SVIDs from SPIRL.
	WorkloadStateActive = WorkloadState("active")

	// WorkloadStateExpiring indicates that the workload has requested
	// SVIDs from SPIRL in the past that may soon expire.
	WorkloadStateExpiring = WorkloadState("expiring")

	// WorkloadStateExpiring indicates that the workload has requested
	// SVIDs from SPIRL in the past that are likely expired.
	WorkloadStateExpired = WorkloadState("expired")
)

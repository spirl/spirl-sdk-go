package client

import (
	"context"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/spirl/spirl-sdk-go/spirlsdk/clustersdk"
	"github.com/spirl/spirl-sdk-go/spirlsdk/internal/protos/api/v1/clusterapi"
	"github.com/spirl/spirl-sdk-go/spirlsdk/internal/xerrors"
)

func makeClusterAPI(conn grpc.ClientConnInterface) clustersdk.API {
	return clusterAPI{client: clusterapi.NewAPIClient(conn)}
}

type clusterAPI struct {
	client clusterapi.APIClient
}

func (a clusterAPI) CreateCluster(ctx context.Context, params clustersdk.CreateClusterParams) (*clustersdk.CreateClusterResult, error) {
	publicKey, err := publicKeyToAPI(params.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %v", err)
	}
	req := &clusterapi.CreateClusterRequest{
		TrustDomainId: params.TrustDomainID,
		ClusterName:   params.Name,
		Platform:      clusterPlatformToAPI(params.Platform),
		Pubkey: &clusterapi.CreateClusterRequest_PkixPubkey{
			PkixPubkey: &clusterapi.PKIXPublicKey{Data: publicKey},
		},
		Description:                 optionalValue(params.Description),
		PathTemplate:                optionalValue(params.PathTemplate),
		CicdProfileName:             optionalValue(params.CICDProfileName),
		X509CustomizationTemplate:   optionalValue(params.X509CustomizationTemplate),
		ProviderAttestationConfigId: optionalValue(params.ProviderAttestationConfigID),
	}

	resp, err := a.client.CreateCluster(ctx, req)
	if err != nil {
		return nil, xerrors.Convert(err)
	}

	deployment, err := clusterDeploymentFromAPI(resp)
	if err != nil {
		return nil, err
	}

	return &clustersdk.CreateClusterResult{
		ClusterVersionID: resp.ClusterVersionId,
		Deployment:       deployment,
	}, nil
}

func (a clusterAPI) ListClusters(ctx context.Context, params clustersdk.ListClustersParams) (*clustersdk.ListClustersResult, error) {
	req := &clusterapi.ListClustersRequest{
		TrustDomainId: optionalValue(params.Filter.TrustDomainID),
		ClusterName:   optionalValue(params.Filter.Name),
	}

	resp, err := a.client.ListClusters(ctx, req)
	if err != nil {
		return nil, xerrors.Convert(err)
	}

	clusters := mapSlice(resp.Clusters, clusterFromAPI)

	return &clustersdk.ListClustersResult{Clusters: clusters}, nil
}

func (a clusterAPI) DeleteCluster(ctx context.Context, params clustersdk.DeleteClusterParams) (*clustersdk.DeleteClusterResult, error) {
	req := &clusterapi.DeleteClusterRequest{
		ClusterId: params.ID,
	}
	if _, err := a.client.DeleteCluster(ctx, req); err != nil {
		return nil, xerrors.Convert(err)
	}
	return &clustersdk.DeleteClusterResult{}, nil
}

func (a clusterAPI) NewClusterVersion(ctx context.Context, params clustersdk.NewClusterVersionParams) (*clustersdk.NewClusterVersionResult, error) {
	publicKey, err := publicKeyToAPI(params.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %v", err)
	}
	req := &clusterapi.NewClusterVersionRequest{
		TrustDomainId: params.TrustDomainID,
		ClusterId:     params.ClusterID,
		Pubkey: &clusterapi.NewClusterVersionRequest_PkixPubkey{
			PkixPubkey: &clusterapi.PKIXPublicKey{Data: publicKey},
		},
		PathTemplate:                optionalValue(params.PathTemplate),
		X509CustomizationTemplate:   optionalValue1(params.X509CustomizationTemplate, ptrOf),
		ProviderAttestationConfigId: optionalValue1(params.ProviderAttestationConfigID, ptrOf),
	}

	resp, err := a.client.NewClusterVersion(ctx, req)
	if err != nil {
		return nil, xerrors.Convert(err)
	}

	deployment, err := clusterDeploymentFromAPI(resp)
	if err != nil {
		return nil, err
	}

	return &clustersdk.NewClusterVersionResult{
		ID:         resp.ClusterVersionId,
		Deployment: deployment,
	}, nil
}

func (a clusterAPI) ActivateClusterVersion(ctx context.Context, params clustersdk.ActivateClusterVersionParams) (*clustersdk.ActivateClusterVersionResult, error) {
	req := &clusterapi.ActivateClusterVersionRequest{
		ClusterVersionId: params.ID,
	}

	if _, err := a.client.ActivateClusterVersion(ctx, req); err != nil {
		return nil, xerrors.Convert(err)
	}

	return &clustersdk.ActivateClusterVersionResult{}, nil
}

func (a clusterAPI) DeactivateClusterVersion(ctx context.Context, params clustersdk.DeactivateClusterVersionParams) (*clustersdk.DeactivateClusterVersionResult, error) {
	req := &clusterapi.DeactivateClusterVersionRequest{
		ClusterVersionId: params.ID,
	}

	if _, err := a.client.DeactivateClusterVersion(ctx, req); err != nil {
		return nil, xerrors.Convert(err)
	}

	return &clustersdk.DeactivateClusterVersionResult{}, nil
}

func (a clusterAPI) DeleteClusterVersion(ctx context.Context, params clustersdk.DeleteClusterVersionParams) (*clustersdk.DeleteClusterVersionResult, error) {
	req := &clusterapi.DeleteClusterVersionRequest{
		ClusterVersionId: params.ID,
		Force:            optionalValue(params.Force),
	}

	if _, err := a.client.DeleteClusterVersion(ctx, req); err != nil {
		return nil, xerrors.Convert(err)
	}

	return &clustersdk.DeleteClusterVersionResult{}, nil
}

func (a clusterAPI) ListClusterVersions(ctx context.Context, params clustersdk.ListClusterVersionsParams) (*clustersdk.ListClusterVersionsResult, error) {
	req := &clusterapi.ListClusterVersionsRequest{
		ClusterId: params.ClusterID,
	}

	resp, err := a.client.ListClusterVersions(ctx, req)
	if err != nil {
		return nil, xerrors.Convert(err)
	}

	clusterVersions, err := convertSlice(resp.ClusterVersions, clusterVersionFromAPI)
	if err != nil {
		return nil, err
	}

	return &clustersdk.ListClusterVersionsResult{ClusterVersions: clusterVersions}, nil
}

func (a clusterAPI) ListWorkloads(ctx context.Context, params clustersdk.ListWorkloadsParams) (*clustersdk.ListWorkloadsResult, error) {
	req := &clusterapi.ListWorkloadsRequest{
		ClusterId:        params.ClusterID,
		ClusterVersionId: optionalValue(params.Filter.ClusterVersionID),
		IssuedWithin:     optionalValue1(params.Filter.IssuedWithin, durationpb.New),
	}

	resp, err := a.client.ListWorkloads(ctx, req)
	if err != nil {
		return nil, xerrors.Convert(err)
	}

	workloads := mapSlice(resp.Workloads, clusterWorkloadFromAPI)

	return &clustersdk.ListWorkloadsResult{Workloads: workloads}, nil
}

func (a clusterAPI) ListNodes(ctx context.Context, params clustersdk.ListNodesParams) (*clustersdk.ListNodesResult, error) {
	req := &clusterapi.ListNodesRequest{
		ClusterId:        params.ClusterID,
		ClusterVersionId: optionalValue(params.Filter.ClusterVersionID),
		LastSeenWithin:   optionalValue1(params.Filter.LastSeenWithin, durationpb.New),
	}

	resp, err := a.client.ListNodes(ctx, req)
	if err != nil {
		return nil, xerrors.Convert(err)
	}

	nodes := mapSlice(resp.Nodes, clusterNodeFromAPI)

	return &clustersdk.ListNodesResult{Nodes: nodes}, nil
}

func clusterFromAPI(cluster *clusterapi.Cluster) clustersdk.Cluster {
	return clustersdk.Cluster{
		ID:                          cluster.Id,
		CreatedAt:                   cluster.CreatedAt.AsTime(),
		Name:                        cluster.Name,
		Description:                 cluster.Description,
		Platform:                    clusterPlatformFromAPI(cluster.Platform),
		PathTemplate:                cluster.PathTemplate,
		NumVersions:                 cluster.NumVersions,
		NumActiveAgents:             cluster.NumActiveAgents,
		EstimatedLastUsed:           cluster.EstimatedLastUsed.AsTime(),
		EstimatedNumActiveWorkloads: cluster.EstimatedNumActiveWorkloads,
		OrgID:                       cluster.OrgId,
		TrustDomainID:               cluster.TrustDomainId,
		TrustDomainName:             cluster.TrustDomainName,
		CICDProfileID:               cluster.CiCdProfileId,
		CICDProfileName:             cluster.CiCdProfileName,
		X509CustomizationTemplate:   cluster.X509CustomizationTemplate,
	}
}

func clusterVersionFromAPI(in *clusterapi.ClusterVersion) (clustersdk.ClusterVersion, error) {
	pkixPubkey := in.GetPkixPubkey()
	if pkixPubkey == nil {
		return clustersdk.ClusterVersion{}, fmt.Errorf("pkix pubkey is unset: %w", xerrors.UnexpectedResponseField("pubkey"))
	}
	publicKey, err := publicKeyFromAPI(pkixPubkey)
	if err != nil {
		return clustersdk.ClusterVersion{}, fmt.Errorf("pkix pubkey is malformed: %w: %v", xerrors.UnexpectedResponseField("pubkey"), err)
	}
	return clustersdk.ClusterVersion{
		ID:                            in.Id,
		CreatedAt:                     in.CreatedAt.AsTime(),
		ClusterID:                     in.ClusterId,
		Platform:                      clusterPlatformFromAPI(in.Platform),
		PublicKey:                     publicKey,
		Active:                        in.Active,
		PathTemplate:                  in.PathTemplate,
		X509CustomizationTemplate:     in.X509CustomizationTemplate,
		ProviderAttestationConfigName: in.ProviderAttestationConfigName,
		EstimatedLastUsed:             in.EstimatedLastUsed.AsTime(),
		NumActiveAgents:               in.NumActiveAgents,
		EstimatedNumActiveWorkloads:   in.EstimatedNumActiveWorkloads,
	}, nil
}

func clusterPlatformToAPI(clusterPlatform clustersdk.Platform) clusterapi.Platform {
	switch clusterPlatform {
	case clustersdk.PlatformKubernetes:
		return clusterapi.Platform_PLATFORM_KUBERNETES
	case clustersdk.PlatformIstio:
		return clusterapi.Platform_PLATFORM_ISTIO
	case clustersdk.PlatformEKS:
		return clusterapi.Platform_PLATFORM_EKS
	case clustersdk.PlatformEKSIstio:
		return clusterapi.Platform_PLATFORM_EKS_ISTIO
	case clustersdk.PlatformLinux:
		return clusterapi.Platform_PLATFORM_LINUX
	default:
		return clusterapi.Platform_PLATFORM_UNSPECIFIED
	}
}

func clusterPlatformFromAPI(clusterPlatform clusterapi.Platform) clustersdk.Platform {
	switch clusterPlatform {
	case clusterapi.Platform_PLATFORM_UNSPECIFIED:
		return ""
	case clusterapi.Platform_PLATFORM_KUBERNETES:
		return clustersdk.PlatformKubernetes
	case clusterapi.Platform_PLATFORM_ISTIO:
		return clustersdk.PlatformIstio
	case clusterapi.Platform_PLATFORM_EKS:
		return clustersdk.PlatformEKS
	case clusterapi.Platform_PLATFORM_EKS_ISTIO:
		return clustersdk.PlatformEKSIstio
	case clusterapi.Platform_PLATFORM_LINUX:
		return clustersdk.PlatformLinux
	}
	return ""
}

type clusterDeploymentResponse interface {
	GetKubernetesDeployment() *clusterapi.KubernetesDeployment
	GetVMDeployment() *clusterapi.VMDeployment
}

func clusterDeploymentFromAPI[R clusterDeploymentResponse](r R) (clustersdk.Deployment, error) {
	if deployment := r.GetKubernetesDeployment(); deployment != nil {
		return clustersdk.KubernetesDeployment{
			KubectlYAML: deployment.KubectlYaml,
		}, nil
	}

	if deployment := r.GetVMDeployment(); deployment != nil {
		return clustersdk.VMDeployment{
			AgentConfigurationFile: deployment.AgentConfigurationFile,
			DockerComposeYAML:      deployment.DockerComposeYaml,
		}, nil
	}

	return nil, xerrors.UnexpectedResponseField("unrecognized cluster deployment")
}

func clusterWorkloadFromAPI(in *clusterapi.WorkloadCount) clustersdk.Workload {
	return clustersdk.Workload{
		ID:         in.Id,
		Type:       clusterWorkloadTypeFromAPI(in.Type),
		State:      clusterWorkloadStateFromAPI(in.State),
		Count:      in.Count,
		LastIssued: timeFromAPI(in.LastIssued),
		ExpiresAt:  timeFromAPI(in.ExpiresAt),
	}
}

func clusterWorkloadTypeFromAPI(in clusterapi.WorkloadType) clustersdk.WorkloadType {
	switch in {
	case clusterapi.WorkloadType_WORKLOADTYPE_UNKNOWN:
		return ""
	case clusterapi.WorkloadType_WORKLOADTYPE_X509:
		return clustersdk.WorkloadTypeX509
	case clusterapi.WorkloadType_WORKLOADTYPE_JWT:
		return clustersdk.WorkloadTypeJWT
	}
	return ""
}

func clusterWorkloadStateFromAPI(in clusterapi.WorkloadState) clustersdk.WorkloadState {
	switch in {
	case clusterapi.WorkloadState_WORKLOADSTATE_UNKNOWN:
		return ""
	case clusterapi.WorkloadState_WORKLOADSTATE_ACTIVE:
		return clustersdk.WorkloadStateActive
	case clusterapi.WorkloadState_WORKLOADSTATE_EXPIRING:
		return clustersdk.WorkloadStateExpiring
	case clusterapi.WorkloadState_WORKLOADSTATE_EXPIRED:
		return clustersdk.WorkloadStateExpired
	}
	return ""
}

func clusterNodeFromAPI(in *clusterapi.Node) clustersdk.Node {
	return clustersdk.Node{
		AgentID:       in.AgentId,
		Hostname:      in.Hostname,
		MachineIDHash: in.MachineIdHash,
		IPAddress:     in.IpAddress,
		LastSeen:      timeFromAPI(in.LastSeen),
	}
}

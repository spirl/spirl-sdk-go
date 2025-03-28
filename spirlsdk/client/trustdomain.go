package client

import (
	"context"
	"fmt"

	"google.golang.org/grpc"

	"github.com/spirl/spirl-sdk-go/spirlsdk/internal/protos/api/v1/trustdomainapi"
	"github.com/spirl/spirl-sdk-go/spirlsdk/internal/xerrors"
	"github.com/spirl/spirl-sdk-go/spirlsdk/trustdomainsdk"
)

func makeTrustDomainAPI(conn grpc.ClientConnInterface) trustdomainsdk.API {
	return trustDomainAPI{client: trustdomainapi.NewAPIClient(conn)}
}

type trustDomainAPI struct {
	client trustdomainapi.APIClient
}

func (a trustDomainAPI) CreateTrustDomain(ctx context.Context, params trustdomainsdk.CreateTrustDomainParams) (*trustdomainsdk.CreateTrustDomainResult, error) {
	req := &trustdomainapi.CreateTrustDomainRequest{
		Name:        params.Name,
		Description: optionalValue(params.Description),
	}

	resp, err := a.client.CreateTrustDomain(ctx, req)
	if err != nil {
		return nil, xerrors.Convert(err)
	}

	return &trustdomainsdk.CreateTrustDomainResult{
		ID:               resp.TrustDomainId,
		AgentEndpointURL: resp.EndpointUrl,
	}, nil
}

func (a trustDomainAPI) RegisterTrustDomain(ctx context.Context, params trustdomainsdk.RegisterTrustDomainParams) (*trustdomainsdk.RegisterTrustDomainResult, error) {
	req := &trustdomainapi.RegisterTrustDomainRequest{
		Name:        params.Name,
		Description: optionalValue(params.Description),
	}

	resp, err := a.client.RegisterTrustDomain(ctx, req)
	if err != nil {
		return nil, xerrors.Convert(err)
	}

	return &trustdomainsdk.RegisterTrustDomainResult{
		ID: resp.TrustDomainId,
	}, nil
}

func (a trustDomainAPI) TrustDomainInfo(ctx context.Context, params trustdomainsdk.TrustDomainInfoParams) (*trustdomainsdk.TrustDomainInfoResult, error) {
	req := &trustdomainapi.TrustDomainInfoRequest{
		TrustDomainId: params.ID,
	}

	resp, err := a.client.TrustDomainInfo(ctx, req)
	if err != nil {
		return nil, xerrors.Convert(err)
	}

	return &trustdomainsdk.TrustDomainInfoResult{
		TrustDomain: trustdomainsdk.TrustDomain{
			ID:            resp.Id,
			CreatedAt:     timeFromAPI(resp.CreatedAt),
			UpdatedAt:     timeFromAPI(resp.UpdatedAt),
			Name:          resp.Name,
			Description:   resp.Description,
			State:         trustDomainStateFromAPI(resp.State),
			IsSelfManaged: resp.IsSelfManaged,
			JWTIssuer:     resp.JwtIssuerEndpointUrl,
			URLs: trustdomainsdk.TrustDomainURLs{
				AgentEndpointURL:         resp.SpirlAgentEndpointUrl,
				SPIFFEBundleEndpointURL:  resp.SpiffeBundleEndpointUrl,
				OIDCDiscoveryEndpointURL: resp.OidcDiscoveryEndpointUrl,
				JWKSEndpointURL:          resp.JwksEndpointUrl,
			},
			Status: nil, // not returned from TrustDomainInfo
		},
	}, nil
}

func (a trustDomainAPI) ListTrustDomains(ctx context.Context, params trustdomainsdk.ListTrustDomainsParams) (*trustdomainsdk.ListTrustDomainsResult, error) {
	req := &trustdomainapi.ListTrustDomainsRequest{
		IncludeDynamicData: params.View.IncludeStatus,
		TrustDomainName:    optionalValue(params.Filter.Name),
	}

	resp, err := a.client.ListTrustDomains(ctx, req)
	if err != nil {
		return nil, xerrors.Convert(err)
	}

	trustDomains, err := convertSlice(resp.TrustDomains, func(api *trustdomainapi.TrustDomain) (trustdomainsdk.TrustDomain, error) {
		return trustDomainFromAPI(api, params.View.IncludeStatus)
	})
	if err != nil {
		return nil, err
	}

	return &trustdomainsdk.ListTrustDomainsResult{TrustDomains: trustDomains}, nil
}

func (a trustDomainAPI) DeleteTrustDomain(ctx context.Context, params trustdomainsdk.DeleteTrustDomainParams) (*trustdomainsdk.DeleteTrustDomainResult, error) {
	req := &trustdomainapi.DeleteTrustDomainRequest{TrustDomainId: params.ID}

	if _, err := a.client.DeleteTrustDomain(ctx, req); err != nil {
		return nil, xerrors.Convert(err)
	}

	return &trustdomainsdk.DeleteTrustDomainResult{}, nil
}

func (a trustDomainAPI) ListTrustDomainDeployments(ctx context.Context, params trustdomainsdk.ListTrustDomainDeploymentsParams) (*trustdomainsdk.ListTrustDomainDeploymentsResult, error) {
	req := &trustdomainapi.ListTrustDomainDeploymentsRequest{
		TrustDomainId: optionalValue(params.Filter.TrustDomainID),
	}

	resp, err := a.client.ListTrustDomainDeployments(ctx, req)
	if err != nil {
		return nil, xerrors.Convert(err)
	}

	trustDomainDeployments, err := convertSlice(resp.TrustDomainDeployments, trustDomainDeploymentFromAPI)
	if err != nil {
		return nil, err
	}

	return &trustdomainsdk.ListTrustDomainDeploymentsResult{TrustDomainDeployments: trustDomainDeployments}, nil
}

func (a trustDomainAPI) DeleteTrustDomainDeployment(ctx context.Context, params trustdomainsdk.DeleteTrustDomainDeploymentParams) (*trustdomainsdk.DeleteTrustDomainDeploymentResult, error) {
	req := &trustdomainapi.DeleteTrustDomainDeploymentRequest{
		TrustDomainId:  params.TrustDomainID,
		DeploymentName: params.DeploymentName,
		Force:          optionalValue(params.Force),
	}

	if _, err := a.client.DeleteTrustDomainDeployment(ctx, req); err != nil {
		return nil, xerrors.Convert(err)
	}

	return &trustdomainsdk.DeleteTrustDomainDeploymentResult{}, nil
}

func (a trustDomainAPI) CreateTrustDomainKey(ctx context.Context, params trustdomainsdk.CreateTrustDomainKeyParams) (*trustdomainsdk.CreateTrustDomainKeyResult, error) {
	publicKey, err := publicKeyToAPI(params.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %v", err)
	}

	req := &trustdomainapi.CreateTrustDomainKeyRequest{
		TrustDomainId:  params.TrustDomainID,
		DeploymentName: params.DeploymentName,
		Pubkey: &trustdomainapi.CreateTrustDomainKeyRequest_PkixPubkey{
			PkixPubkey: &trustdomainapi.PKIXPublicKey{Data: publicKey},
		},
	}

	resp, err := a.client.CreateTrustDomainKey(ctx, req)
	if err != nil {
		return nil, xerrors.Convert(err)
	}

	return &trustdomainsdk.CreateTrustDomainKeyResult{
		ID: resp.Id,
	}, nil
}

func (a trustDomainAPI) ListTrustDomainKeys(ctx context.Context, params trustdomainsdk.ListTrustDomainKeysParams) (*trustdomainsdk.ListTrustDomainKeysResult, error) {
	req := &trustdomainapi.ListTrustDomainKeysRequest{
		TrustDomainId:  optionalValue(params.Filter.TrustDomainID),
		DeploymentName: optionalValue(params.Filter.DeploymentName),
	}

	resp, err := a.client.ListTrustDomainKeys(ctx, req)
	if err != nil {
		return nil, xerrors.Convert(err)
	}

	trustDomainKeys, err := convertSlice(resp.TrustDomainKeys, trustDomainKeyFromAPI)
	if err != nil {
		return nil, err
	}

	return &trustdomainsdk.ListTrustDomainKeysResult{TrustDomainKeys: trustDomainKeys}, nil
}

func (a trustDomainAPI) EnableTrustDomainKey(ctx context.Context, params trustdomainsdk.EnableTrustDomainKeyParams) (*trustdomainsdk.EnableTrustDomainKeyResult, error) {
	req := &trustdomainapi.EnableTrustDomainKeyRequest{
		TrustDomainId:    params.TrustDomainID,
		TrustDomainKeyId: params.TrustDomainKeyID,
	}

	if _, err := a.client.EnableTrustDomainKey(ctx, req); err != nil {
		return nil, xerrors.Convert(err)
	}

	return &trustdomainsdk.EnableTrustDomainKeyResult{}, nil
}

func (a trustDomainAPI) DisableTrustDomainKey(ctx context.Context, params trustdomainsdk.DisableTrustDomainKeyParams) (*trustdomainsdk.DisableTrustDomainKeyResult, error) {
	req := &trustdomainapi.DisableTrustDomainKeyRequest{
		TrustDomainId:    params.TrustDomainID,
		TrustDomainKeyId: params.TrustDomainKeyID,
	}

	if _, err := a.client.DisableTrustDomainKey(ctx, req); err != nil {
		return nil, xerrors.Convert(err)
	}

	return &trustdomainsdk.DisableTrustDomainKeyResult{}, nil
}

func (a trustDomainAPI) DeleteTrustDomainKey(ctx context.Context, params trustdomainsdk.DeleteTrustDomainKeyParams) (*trustdomainsdk.DeleteTrustDomainKeyResult, error) {
	req := &trustdomainapi.DeleteTrustDomainKeyRequest{
		TrustDomainId:    params.TrustDomainID,
		TrustDomainKeyId: params.TrustDomainKeyID,
		Force:            optionalValue(params.Force),
	}

	if _, err := a.client.DeleteTrustDomainKey(ctx, req); err != nil {
		return nil, xerrors.Convert(err)
	}

	return &trustdomainsdk.DeleteTrustDomainKeyResult{}, nil
}

func trustDomainFromAPI(api *trustdomainapi.TrustDomain, includeStatus bool) (trustdomainsdk.TrustDomain, error) {
	out := trustdomainsdk.TrustDomain{
		ID:            api.Id,
		CreatedAt:     timeFromAPI(api.CreatedAt),
		UpdatedAt:     timeFromAPI(api.UpdatedAt),
		Name:          api.Name,
		Description:   api.Description,
		State:         trustDomainStateFromAPI(api.State),
		IsSelfManaged: api.IsSelfManaged,
		JWTIssuer:     api.JwtIssuerEndpointUrl,
		URLs: trustdomainsdk.TrustDomainURLs{
			AgentEndpointURL:         api.EndpointUrl,
			SPIFFEBundleEndpointURL:  api.SpiffeBundleEndpointUrl,
			JWKSEndpointURL:          api.JwksEndpointUrl,
			OIDCDiscoveryEndpointURL: api.OidcDiscoveryEndpointUrl,
		},
		Status: nil, // set below if includeStatus is true
	}
	if includeStatus {
		out.Status = &trustdomainsdk.TrustDomainStatus{
			ClustersTotal:         api.ClustersTotal,
			ClustersActive:        api.ClustersActive,
			FederationLinksTotal:  api.FederationLinksTotal,
			FederationLinksActive: api.FederationLinksActive,
		}
	}
	return out, nil
}

func trustDomainStateFromAPI(state string) trustdomainsdk.TrustDomainState {
	return trustdomainsdk.TrustDomainState(state)
}

func trustDomainDeploymentFromAPI(api *trustdomainapi.TrustDomainDeployment) (trustdomainsdk.TrustDomainDeployment, error) {
	configurationState, err := trustDomainDeploymentConfigurationStateFromAPI(api.ConfigurationState)
	if err != nil {
		return trustdomainsdk.TrustDomainDeployment{}, fmt.Errorf("%w: %v", xerrors.UnexpectedResponseField("configuration_state"), err)
	}
	return trustdomainsdk.TrustDomainDeployment{
		ID:                 api.Id,
		TrustDomainID:      api.TrustDomainId,
		OrgID:              api.OrgId,
		Name:               api.DeploymentName,
		LastAtIntent:       timeFromAPI(api.LastAtIntent),
		ConfigurationState: configurationState,
	}, nil
}

func trustDomainDeploymentConfigurationStateFromAPI(state trustdomainapi.TrustDomainDeployment_ConfigurationState) (trustdomainsdk.TrustDomainDeploymentConfigurationState, error) {
	switch state {
	case trustdomainapi.TrustDomainDeployment_CONFIGURATION_STATE_UNKNOWN:
		return "", nil
	case trustdomainapi.TrustDomainDeployment_CONFIGURATION_STATE_UP_TO_DATE:
		return trustdomainsdk.TrustDomainDeploymentConfigurationStateUpToDate, nil
	case trustdomainapi.TrustDomainDeployment_CONFIGURATION_STATE_STALE:
		return trustdomainsdk.TrustDomainDeploymentConfigurationStateStale, nil
	default:
		return "", fmt.Errorf("unknown configuration state %q", state)
	}
}

func trustDomainKeyFromAPI(api *trustdomainapi.TrustDomainKey) (trustdomainsdk.TrustDomainKey, error) {
	pkixPubkey := api.GetPkixPubkey()
	if pkixPubkey == nil {
		return trustdomainsdk.TrustDomainKey{}, fmt.Errorf("pkix pubkey is unset: %w", xerrors.UnexpectedResponseField("pubkey"))
	}

	publicKey, err := publicKeyFromAPI(pkixPubkey)
	if err != nil {
		return trustdomainsdk.TrustDomainKey{}, fmt.Errorf("pkix pubkey is malformed: %w: %v", xerrors.UnexpectedResponseField("pubkey"), err)
	}

	return trustdomainsdk.TrustDomainKey{
		ID:             api.Id,
		TrustDomainID:  api.TrustDomainId,
		DeploymentName: api.DeploymentName,
		State:          trustDomainKeyStateFromAPI(api.State),
		PublicKey:      publicKey,
	}, nil
}

func trustDomainKeyStateFromAPI(state string) trustdomainsdk.TrustDomainKeyState {
	return trustdomainsdk.TrustDomainKeyState(state)
}

package client

import (
	"context"
	"fmt"
	"log/slog"

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
		JwtIssuer:   jwtIssuerConfigToAPI(params.JwtIssuerConfig),
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
		JwtIssuer:   jwtIssuerConfigToAPI(params.JwtIssuerConfig),
	}

	resp, err := a.client.RegisterTrustDomain(ctx, req)
	if err != nil {
		return nil, xerrors.Convert(err)
	}

	return &trustdomainsdk.RegisterTrustDomainResult{
		ID: resp.TrustDomainId,
	}, nil
}

func (a trustDomainAPI) UpdateTrustDomain(ctx context.Context, params trustdomainsdk.UpdateTrustDomainParams) (*trustdomainsdk.UpdateTrustDomainResult, error) {
	req := &trustdomainapi.UpdateTrustDomainRequest{
		TrustDomainId: params.ID,
		JwtIssuer:     jwtIssuerConfigToAPI(params.JwtIssuerConfig),
	}

	if _, err := a.client.UpdateTrustDomain(ctx, req); err != nil {
		return nil, xerrors.Convert(err)
	}

	return &trustdomainsdk.UpdateTrustDomainResult{}, nil
}

func (a trustDomainAPI) TrustDomainInfo(ctx context.Context, params trustdomainsdk.TrustDomainInfoParams) (*trustdomainsdk.TrustDomainInfoResult, error) {
	req := &trustdomainapi.TrustDomainInfoRequest{
		TrustDomainId: params.ID,
	}

	resp, err := a.client.TrustDomainInfo(ctx, req)
	if err != nil {
		return nil, xerrors.Convert(err)
	}

	jwtIssuerStatus := jwtIssuerStatusFromAPI(resp.JwtIssuerStatus)

	return &trustdomainsdk.TrustDomainInfoResult{
		TrustDomain: trustdomainsdk.TrustDomain{
			ID:              resp.Id,
			CreatedAt:       timeFromAPI(resp.CreatedAt),
			UpdatedAt:       timeFromAPI(resp.UpdatedAt),
			Name:            resp.Name,
			Description:     resp.Description,
			State:           trustDomainStateFromAPI(resp.State),
			IsSelfManaged:   resp.IsSelfManaged,
			JWTIssuer:       effectiveIssuerFromStatus(jwtIssuerStatus),
			JwtIssuerStatus: jwtIssuerStatus,
			URLs: trustdomainsdk.TrustDomainURLs{
				AgentEndpointURL:         resp.SpirlAgentEndpointUrl,
				SPIFFEBundleEndpointURL:  resp.SpiffeBundleEndpointUrl,
				OIDCDiscoveryEndpointURL: oidcDiscoveryFromStatus(jwtIssuerStatus),
				JWKSEndpointURL:          resp.JwksEndpointUrl,
			},
			Status: nil, // not returned from TrustDomainInfo
		},
	}, nil
}

func (a trustDomainAPI) TrustDomainSigningAuthorityStatus(ctx context.Context, params trustdomainsdk.TrustDomainSigningAuthorityStatusParams) (*trustdomainsdk.TrustDomainSigningAuthorityStatusResult, error) {
	req := &trustdomainapi.TrustDomainSigningAuthorityStatusRequest{
		TrustDomainId: params.ID,
	}

	resp, err := a.client.TrustDomainSigningAuthorityStatus(ctx, req)
	if err != nil {
		return nil, xerrors.Convert(err)
	}

	result := &trustdomainsdk.TrustDomainSigningAuthorityStatusResult{
		SigningAuthorityStatuses: make([]trustdomainsdk.SigningAuthorityStatus, 0, len(resp.SigningAuthorityStatuses)),
	}
	for _, s := range resp.SigningAuthorityStatuses {
		result.SigningAuthorityStatuses = append(result.SigningAuthorityStatuses, signingAuthorityStatusFromAPI(s))
	}
	return result, nil
}

func signingAuthorityStatusFromAPI(api *trustdomainapi.SigningAuthorityStatus) trustdomainsdk.SigningAuthorityStatus {
	result := trustdomainsdk.SigningAuthorityStatus{
		TrustDomainDeploymentID:   api.TrustDomainDeploymentId,
		TrustDomainDeploymentName: api.TrustDomainDeploymentName,
		RotationSchedule:          bundleRotationScheduleFromAPI(api.RotationSchedule),
		SigningKeys:               make([]trustdomainsdk.SigningKey, 0, len(api.SigningKeys)),
	}
	for _, key := range api.SigningKeys {
		result.SigningKeys = append(result.SigningKeys, signingKeyFromAPI(key))
	}
	return result
}

func bundleRotationScheduleFromAPI(api *trustdomainapi.BundleRotationSchedule) *trustdomainsdk.BundleRotationSchedule {
	if api == nil {
		return nil
	}
	return &trustdomainsdk.BundleRotationSchedule{
		LastRotatedAt:        timeFromAPI(api.LastRotatedAt),
		PreparationThreshold: api.PreparationThreshold.AsDuration(),
		ActivationThreshold:  api.ActivationThreshold.AsDuration(),
	}
}

func signingKeyFromAPI(api *trustdomainapi.SigningKey) trustdomainsdk.SigningKey {
	var keyType trustdomainsdk.SigningKeyType
	switch api.KeyType {
	case trustdomainapi.SigningKey_KEY_TYPE_UNSPECIFIED:
		keyType = trustdomainsdk.SigningKeyTypeUnspecified
	case trustdomainapi.SigningKey_KEY_TYPE_X509:
		keyType = trustdomainsdk.SigningKeyTypeX509
	case trustdomainapi.SigningKey_KEY_TYPE_JWT:
		keyType = trustdomainsdk.SigningKeyTypeJWT
	}

	var state trustdomainsdk.SigningKeyState
	switch api.State {
	case trustdomainapi.SigningKey_STATE_UNSPECIFIED:
		state = trustdomainsdk.SigningKeyStateUnspecified
	case trustdomainapi.SigningKey_STATE_ACTIVE:
		state = trustdomainsdk.SigningKeyStateActive
	case trustdomainapi.SigningKey_STATE_PREPARED:
		state = trustdomainsdk.SigningKeyStatePrepared
	case trustdomainapi.SigningKey_STATE_TAINTED:
		state = trustdomainsdk.SigningKeyStateTainted
	}

	return trustdomainsdk.SigningKey{
		KeyType:   keyType,
		KeyID:     api.KeyId,
		IssuedAt:  timeFromAPI(api.IssuedAt),
		ExpiresAt: timeFromAPI(api.ExpiresAt),
		State:     state,
	}
}

func (a trustDomainAPI) ListTrustDomains(ctx context.Context, params trustdomainsdk.ListTrustDomainsParams) (*trustdomainsdk.ListTrustDomainsResult, error) {
	req := &trustdomainapi.ListTrustDomainsRequest{
		ExcludeStats:       params.View.ExcludeStats,
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
		TrustDomainId:      optionalValue(params.Filter.TrustDomainID),
		IncludeDynamicData: false,
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
	jwtIssuerStatus := jwtIssuerStatusFromAPI(api.JwtIssuerStatus)

	out := trustdomainsdk.TrustDomain{
		ID:              api.Id,
		CreatedAt:       timeFromAPI(api.CreatedAt),
		UpdatedAt:       timeFromAPI(api.UpdatedAt),
		Name:            api.Name,
		Description:     api.Description,
		State:           trustDomainStateFromAPI(api.State),
		IsSelfManaged:   api.IsSelfManaged,
		JWTIssuer:       effectiveIssuerFromStatus(jwtIssuerStatus),
		JwtIssuerStatus: jwtIssuerStatus,
		URLs: trustdomainsdk.TrustDomainURLs{
			AgentEndpointURL:         api.EndpointUrl,
			SPIFFEBundleEndpointURL:  api.SpiffeBundleEndpointUrl,
			JWKSEndpointURL:          api.JwksEndpointUrl,
			OIDCDiscoveryEndpointURL: oidcDiscoveryFromStatus(jwtIssuerStatus),
		},
		Status: nil, // set below if includeStatus is true
	}
	if includeStatus {
		out.Status = &trustdomainsdk.TrustDomainStatus{
			ClustersTotal:         api.ClustersTotal,
			ClustersActive:        api.ClustersActive,
			FederationLinksTotal:  api.FederationLinksTotal,
			FederationLinksActive: api.FederationLinksActive,
			WorkloadsActive:       api.WorkloadsActive,
			WorkloadsTotal:        api.WorkloadsTotal,
			CredentialsActive:     api.CredentialsActive,
			CredentialsTotal:      api.CredentialsTotal,
			LastExpiryIn:          api.LastExpiryIn.AsDuration(),
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

func effectiveIssuerFromStatus(status *trustdomainsdk.JwtIssuerStatus) string {
	if status == nil {
		return ""
	}
	return status.EffectiveIssuer
}

func oidcDiscoveryFromStatus(status *trustdomainsdk.JwtIssuerStatus) string {
	issuer := effectiveIssuerFromStatus(status)
	if issuer == "" {
		return ""
	}
	return issuer + "/.well-known/openid-configuration"
}

func jwtIssuerConfigToAPI(config *trustdomainsdk.JwtIssuerConfig) *trustdomainapi.JwtIssuerConfig {
	if config == nil {
		return nil
	}
	return &trustdomainapi.JwtIssuerConfig{
		Set:    config.Set,
		Issuer: config.Issuer,
	}
}

func jwtIssuerStatusFromAPI(status *trustdomainapi.JwtIssuerStatus) *trustdomainsdk.JwtIssuerStatus {
	if status == nil {
		return nil
	}
	return &trustdomainsdk.JwtIssuerStatus{
		Mode:            jwtIssuerModeFromAPI(status.Mode),
		EffectiveIssuer: status.EffectiveIssuer,
	}
}

func jwtIssuerModeFromAPI(mode trustdomainapi.JwtIssuerStatus_Mode) trustdomainsdk.JwtIssuerMode {
	switch mode {
	case trustdomainapi.JwtIssuerStatus_MODE_BUILTIN:
		return trustdomainsdk.JwtIssuerModeBuiltin
	case trustdomainapi.JwtIssuerStatus_MODE_DISABLED:
		return trustdomainsdk.JwtIssuerModeDisabled
	case trustdomainapi.JwtIssuerStatus_MODE_CUSTOM:
		return trustdomainsdk.JwtIssuerModeCustom
	default:
		slog.Warn("Unknown JWT issuer mode from API, defaulting to builtin", slog.Any("mode", mode))
		return trustdomainsdk.JwtIssuerModeBuiltin
	}
}

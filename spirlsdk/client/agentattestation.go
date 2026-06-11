package client

import (
	"context"

	"google.golang.org/grpc"

	"github.com/spirl/spirl-sdk-go/spirlsdk/agentattestationsdk"
	"github.com/spirl/spirl-sdk-go/spirlsdk/internal/protos/api/v1/agentattestationapi"
	"github.com/spirl/spirl-sdk-go/spirlsdk/internal/xerrors"
)

func makeAgentAttestationAPI(conn grpc.ClientConnInterface) agentattestationsdk.API {
	return agentAttestationAPI{client: agentattestationapi.NewAPIClient(conn)}
}

type agentAttestationAPI struct {
	client agentattestationapi.APIClient
}

func (a agentAttestationAPI) CreateConfig(ctx context.Context, params agentattestationsdk.CreateConfigParams) (*agentattestationsdk.CreateConfigResult, error) {
	req := &agentattestationapi.CreateConfigRequest{
		Config: nil,
	}
	switch {
	case params.K8SPSAT != nil:
		req.Config = &agentattestationapi.CreateConfigRequest_K8SPsat{
			K8SPsat: &agentattestationapi.K8SPSATConfig{
				OidcIssuerUrl:           params.K8SPSAT.OIDCIssuerURL,
				ServiceAccountName:      params.K8SPSAT.ServiceAccountName,
				ServiceAccountNamespace: params.K8SPSAT.ServiceAccountNamespace,
			},
		}
	default:
	}

	resp, err := a.client.CreateConfig(ctx, req)
	if err != nil {
		return nil, xerrors.Convert(err)
	}

	config, err := agentAttestationConfigFromAPI(resp.Config)
	if err != nil {
		return nil, err
	}

	return &agentattestationsdk.CreateConfigResult{Config: config}, nil
}

func (a agentAttestationAPI) ListConfigs(ctx context.Context, params agentattestationsdk.ListConfigsParams) (*agentattestationsdk.ListConfigsResult, error) {
	req := &agentattestationapi.ListConfigsRequest{}

	resp, err := a.client.ListConfigs(ctx, req)
	if err != nil {
		return nil, xerrors.Convert(err)
	}

	configs, err := convertSlice(resp.Configs, agentAttestationConfigFromAPI)
	if err != nil {
		return nil, err
	}

	return &agentattestationsdk.ListConfigsResult{Configs: configs}, nil
}

func (a agentAttestationAPI) GetConfig(ctx context.Context, params agentattestationsdk.GetConfigParams) (*agentattestationsdk.GetConfigResult, error) {
	req := &agentattestationapi.GetConfigRequest{
		Id: params.ID,
	}

	resp, err := a.client.GetConfig(ctx, req)
	if err != nil {
		return nil, xerrors.Convert(err)
	}

	config, err := agentAttestationConfigFromAPI(resp.Config)
	if err != nil {
		return nil, err
	}

	return &agentattestationsdk.GetConfigResult{Config: config}, nil
}

func (a agentAttestationAPI) DeleteConfig(ctx context.Context, params agentattestationsdk.DeleteConfigParams) (*agentattestationsdk.DeleteConfigResult, error) {
	req := &agentattestationapi.DeleteConfigRequest{
		Id: params.ID,
	}

	if _, err := a.client.DeleteConfig(ctx, req); err != nil {
		return nil, xerrors.Convert(err)
	}

	return &agentattestationsdk.DeleteConfigResult{}, nil
}

func agentAttestationConfigFromAPI(in *agentattestationapi.Config) (agentattestationsdk.AgentAttestationConfig, error) {
	if in == nil {
		return agentattestationsdk.AgentAttestationConfig{}, xerrors.UnexpectedResponseField("config")
	}
	ret := agentattestationsdk.AgentAttestationConfig{
		ID:      in.Id,
		K8SPSAT: nil,
	}
	switch v := in.Config.(type) {
	case *agentattestationapi.Config_K8SPsat:
		if v.K8SPsat == nil {
			return agentattestationsdk.AgentAttestationConfig{}, xerrors.UnexpectedResponseField("config.config.k8s_psat")
		}
		ret.K8SPSAT = &agentattestationsdk.K8SPSATConfig{
			OIDCIssuerURL:           v.K8SPsat.OidcIssuerUrl,
			ServiceAccountName:      v.K8SPsat.ServiceAccountName,
			ServiceAccountNamespace: v.K8SPsat.ServiceAccountNamespace,
		}
	case nil:
		return agentattestationsdk.AgentAttestationConfig{}, xerrors.UnexpectedResponseField("config.config")
	default:
		return agentattestationsdk.AgentAttestationConfig{}, xerrors.UnexpectedResponseType("config.config", v)
	}
	return ret, nil
}

package client

import (
	"context"

	"google.golang.org/grpc"

	"github.com/spirl/spirl-sdk-go/spirlsdk/internal/protos/api/v1/providerattestationapi"
	"github.com/spirl/spirl-sdk-go/spirlsdk/internal/xerrors"
	"github.com/spirl/spirl-sdk-go/spirlsdk/providerattestationsdk"
)

func makeProviderattestationAPI(conn grpc.ClientConnInterface) providerattestationsdk.API {
	return providerattestationAPI{client: providerattestationapi.NewAPIClient(conn)}
}

type providerattestationAPI struct {
	client providerattestationapi.APIClient
}

func (a providerattestationAPI) CreateConfig(ctx context.Context, params providerattestationsdk.CreateConfigParams) (*providerattestationsdk.CreateConfigResult, error) {
	req := &providerattestationapi.CreateConfigRequest{
		Name:   params.Name,
		Config: nil,
	}
	switch {
	case params.AWS != nil:
		req.Config = &providerattestationapi.CreateConfigRequest_Aws{
			Aws: &providerattestationapi.AWSConfig{
				RoleArn: params.AWS.RoleArn,
			},
		}
	default:
	}

	resp, err := a.client.CreateConfig(ctx, req)
	if err != nil {
		return nil, xerrors.Convert(err)
	}

	config, err := providerAttestationFromAPI(resp.Config)
	if err != nil {
		return nil, err
	}

	return &providerattestationsdk.CreateConfigResult{
		Config: config,
	}, nil
}

func (a providerattestationAPI) ListConfigs(ctx context.Context, params providerattestationsdk.ListConfigsParams) (*providerattestationsdk.ListConfigsResult, error) {
	req := &providerattestationapi.ListConfigsRequest{
		Filter: &providerattestationapi.ConfigFilter{
			Name: optionalValue(params.Filter.Name),
		},
	}

	resp, err := a.client.ListConfigs(ctx, req)
	if err != nil {
		return nil, xerrors.Convert(err)
	}

	configs, err := convertSlice(resp.Configs, providerAttestationFromAPI)
	if err != nil {
		return nil, err
	}

	return &providerattestationsdk.ListConfigsResult{Configs: configs}, nil
}

func (a providerattestationAPI) GetConfig(ctx context.Context, params providerattestationsdk.GetConfigParams) (*providerattestationsdk.GetConfigResult, error) {
	req := &providerattestationapi.GetConfigRequest{
		Id: params.ID,
	}

	resp, err := a.client.GetConfig(ctx, req)
	if err != nil {
		return nil, xerrors.Convert(err)
	}

	config, err := providerAttestationFromAPI(resp.Config)
	if err != nil {
		return nil, err
	}

	return &providerattestationsdk.GetConfigResult{Config: config}, nil
}

func (a providerattestationAPI) DeleteConfig(ctx context.Context, params providerattestationsdk.DeleteConfigParams) (*providerattestationsdk.DeleteConfigResult, error) {
	req := &providerattestationapi.DeleteConfigRequest{
		Id: params.ID,
	}

	if _, err := a.client.DeleteConfig(ctx, req); err != nil {
		return nil, xerrors.Convert(err)
	}

	return &providerattestationsdk.DeleteConfigResult{}, nil
}

func providerAttestationFromAPI(in *providerattestationapi.Config) (providerattestationsdk.ProviderAttestation, error) {
	if in == nil {
		return providerattestationsdk.ProviderAttestation{}, xerrors.UnexpectedResponseField("config")
	}
	ret := providerattestationsdk.ProviderAttestation{
		ID:   in.Id,
		Name: in.Name,
		AWS:  nil,
	}
	switch v := in.Config.(type) {
	case *providerattestationapi.Config_Aws:
		ret.AWS = &providerattestationsdk.AWSProviderAttestationConfig{
			RoleArn: v.Aws.RoleArn,
		}
	default:
		return ret, xerrors.UnexpectedResponseType("config.config", v)
	}
	return ret, nil
}

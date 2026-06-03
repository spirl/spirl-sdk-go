package client

import (
	"context"

	"google.golang.org/grpc"

	"github.com/spirl/spirl-sdk-go/spirlsdk/configsdk"
	"github.com/spirl/spirl-sdk-go/spirlsdk/internal/protos/api/v1/configapi"
	"github.com/spirl/spirl-sdk-go/spirlsdk/internal/xerrors"
)

func makeConfigAPI(conn grpc.ClientConnInterface) configsdk.API {
	return configAPI{client: configapi.NewAPIClient(conn)}
}

type configAPI struct {
	client configapi.APIClient
}

func (a configAPI) GetOrgConfig(ctx context.Context, params configsdk.GetOrgConfigParams) (*configsdk.GetOrgConfigResult, error) {
	resp, err := a.client.GetOrgConfig(ctx, &configapi.GetOrgConfigRequest{})
	if err != nil {
		return nil, xerrors.Convert(err)
	}

	config, err := configFromAPI(resp.Config)
	if err != nil {
		return nil, err
	}

	return &configsdk.GetOrgConfigResult{Config: config}, nil
}

func (a configAPI) UpdateOrgConfig(ctx context.Context, params configsdk.UpdateOrgConfigParams) (*configsdk.UpdateOrgConfigResult, error) {
	resp, err := a.client.UpdateOrgConfig(ctx, &configapi.UpdateOrgConfigRequest{
		Params: updateConfigParamsToAPI(params.SectionUpdates, params.Prune, params.ExpectedVersion, params.ValidateOnly),
	})
	if err != nil {
		return nil, xerrors.Convert(err)
	}

	config, err := configFromAPI(resp.Config)
	if err != nil {
		return nil, err
	}

	return &configsdk.UpdateOrgConfigResult{Config: config}, nil
}

func (a configAPI) GetTrustDomainConfig(ctx context.Context, params configsdk.GetTrustDomainConfigParams) (*configsdk.GetTrustDomainConfigResult, error) {
	resp, err := a.client.GetTrustDomainConfig(ctx, &configapi.GetTrustDomainConfigRequest{
		TrustDomainId: params.TrustDomainID,
	})
	if err != nil {
		return nil, xerrors.Convert(err)
	}

	config, err := configFromAPI(resp.Config)
	if err != nil {
		return nil, err
	}

	return &configsdk.GetTrustDomainConfigResult{Config: config}, nil
}

func (a configAPI) UpdateTrustDomainConfig(ctx context.Context, params configsdk.UpdateTrustDomainConfigParams) (*configsdk.UpdateTrustDomainConfigResult, error) {
	resp, err := a.client.UpdateTrustDomainConfig(ctx, &configapi.UpdateTrustDomainConfigRequest{
		TrustDomainId: params.TrustDomainID,
		Params:        updateConfigParamsToAPI(params.SectionUpdates, params.Prune, params.ExpectedVersion, params.ValidateOnly),
	})
	if err != nil {
		return nil, xerrors.Convert(err)
	}

	config, err := configFromAPI(resp.Config)
	if err != nil {
		return nil, err
	}

	return &configsdk.UpdateTrustDomainConfigResult{Config: config}, nil
}

func (a configAPI) GetClusterConfig(ctx context.Context, params configsdk.GetClusterConfigParams) (*configsdk.GetClusterConfigResult, error) {
	resp, err := a.client.GetClusterConfig(ctx, &configapi.GetClusterConfigRequest{
		ClusterId: params.ClusterID,
	})
	if err != nil {
		return nil, xerrors.Convert(err)
	}

	config, err := configFromAPI(resp.Config)
	if err != nil {
		return nil, err
	}

	return &configsdk.GetClusterConfigResult{Config: config}, nil
}

func (a configAPI) UpdateClusterConfig(ctx context.Context, params configsdk.UpdateClusterConfigParams) (*configsdk.UpdateClusterConfigResult, error) {
	resp, err := a.client.UpdateClusterConfig(ctx, &configapi.UpdateClusterConfigRequest{
		ClusterId: params.ClusterID,
		Params:    updateConfigParamsToAPI(params.SectionUpdates, params.Prune, params.ExpectedVersion, params.ValidateOnly),
	})
	if err != nil {
		return nil, xerrors.Convert(err)
	}

	config, err := configFromAPI(resp.Config)
	if err != nil {
		return nil, err
	}

	return &configsdk.UpdateClusterConfigResult{Config: config}, nil
}

func (a configAPI) GetTrustDomainDeploymentConfig(ctx context.Context, params configsdk.GetTrustDomainDeploymentConfigParams) (*configsdk.GetTrustDomainDeploymentConfigResult, error) {
	resp, err := a.client.GetTrustDomainDeploymentConfig(ctx, &configapi.GetTrustDomainDeploymentConfigRequest{
		TrustDomainDeploymentId: params.TrustDomainDeploymentID,
	})
	if err != nil {
		return nil, xerrors.Convert(err)
	}

	config, err := configFromAPI(resp.Config)
	if err != nil {
		return nil, err
	}

	return &configsdk.GetTrustDomainDeploymentConfigResult{Config: config}, nil
}

func (a configAPI) UpdateTrustDomainDeploymentConfig(ctx context.Context, params configsdk.UpdateTrustDomainDeploymentConfigParams) (*configsdk.UpdateTrustDomainDeploymentConfigResult, error) {
	resp, err := a.client.UpdateTrustDomainDeploymentConfig(ctx, &configapi.UpdateTrustDomainDeploymentConfigRequest{
		TrustDomainDeploymentId: params.TrustDomainDeploymentID,
		Params:                  updateConfigParamsToAPI(params.SectionUpdates, params.Prune, params.ExpectedVersion, params.ValidateOnly),
	})
	if err != nil {
		return nil, xerrors.Convert(err)
	}

	config, err := configFromAPI(resp.Config)
	if err != nil {
		return nil, err
	}

	return &configsdk.UpdateTrustDomainDeploymentConfigResult{Config: config}, nil
}

func updateConfigParamsToAPI(sectionUpdates []string, prune bool, expectedVersion string, validateOnly bool) *configapi.UpdateConfigParams {
	return &configapi.UpdateConfigParams{
		SectionUpdates:  sectionUpdates,
		Prune:           prune,
		ExpectedVersion: expectedVersion,
		ValidateOnly:    validateOnly,
	}
}

func configFromAPI(in *configapi.Config) (configsdk.Config, error) {
	if in == nil {
		return configsdk.Config{}, xerrors.UnexpectedResponseField("config")
	}

	sections, err := convertSlice(in.Sections, configSectionFromAPI)
	if err != nil {
		return configsdk.Config{}, err
	}

	return configsdk.Config{
		UpdatedAt: timeFromAPI(in.UpdatedAt),
		Version:   in.Version,
		Sections:  sections,
	}, nil
}

func configSectionFromAPI(in *configapi.Section) (configsdk.Section, error) {
	if in == nil {
		return configsdk.Section{}, xerrors.UnexpectedResponseField("config.sections")
	}

	return configsdk.Section{
		Name:      in.Name,
		Schema:    in.Schema,
		YAMLValue: in.YamlValue,
	}, nil
}

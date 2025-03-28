package client

import (
	"context"
	"fmt"

	"google.golang.org/grpc"

	"github.com/spirl/spirl-sdk-go/spirlsdk/cicdsdk"
	"github.com/spirl/spirl-sdk-go/spirlsdk/internal/protos/api/v1/cicdapi"
	"github.com/spirl/spirl-sdk-go/spirlsdk/internal/xerrors"
)

func makeCICDAPI(conn grpc.ClientConnInterface) cicdsdk.API {
	return cicdAPI{client: cicdapi.NewAPIClient(conn)}
}

type cicdAPI struct {
	client cicdapi.APIClient
}

func (a cicdAPI) CreateCICDProfile(ctx context.Context, params cicdsdk.CreateCICDProfileParams) (*cicdsdk.CreateCICDProfileResult, error) {
	req := &cicdapi.CreateCICDProfileRequest{
		Name:    params.Name,
		Type:    cicdTypeToAPI(params.Type),
		Issuer:  optionalValue(params.Issuer),
		JwksUrl: optionalValue(params.JWKSURL),
		Claims:  optionalValue(params.Claims),
	}

	resp, err := a.client.CreateCICDProfile(ctx, req)
	if err != nil {
		return nil, xerrors.Convert(err)
	}

	cicdProfile, err := cicdProfileFromAPI(resp.Profile)
	if err != nil {
		return nil, err
	}

	return &cicdsdk.CreateCICDProfileResult{
		CICDProfile: cicdProfile,
	}, nil
}

func (a cicdAPI) ListCICDProfiles(ctx context.Context, params cicdsdk.ListCICDProfilesParams) (*cicdsdk.ListCICDProfilesResult, error) {
	req := &cicdapi.ListCICDProfilesRequest{}

	resp, err := a.client.ListCICDProfiles(ctx, req)
	if err != nil {
		return nil, xerrors.Convert(err)
	}

	cicdProfiles, err := convertSlice(resp.Profiles, cicdProfileFromAPI)
	if err != nil {
		return nil, err
	}

	return &cicdsdk.ListCICDProfilesResult{CICDProfiles: cicdProfiles}, nil
}

func (a cicdAPI) GetCICDProfileInfo(ctx context.Context, params cicdsdk.GetCICDProfileInfoParams) (*cicdsdk.GetCICDProfileInfoResult, error) {
	req := &cicdapi.GetCICDProfileInfoRequest{
		Name: params.Name,
	}

	resp, err := a.client.GetCICDProfileInfo(ctx, req)
	if err != nil {
		return nil, xerrors.Convert(err)
	}

	cicdProfile, err := cicdProfileFromAPI(resp.Profile)
	if err != nil {
		return nil, err
	}

	return &cicdsdk.GetCICDProfileInfoResult{CICDProfile: cicdProfile}, nil
}

func (a cicdAPI) DeleteCICDProfile(ctx context.Context, params cicdsdk.DeleteCICDProfileParams) (*cicdsdk.DeleteCICDProfileResult, error) {
	req := &cicdapi.DeleteCICDProfileRequest{
		Id: params.ID,
	}

	if _, err := a.client.DeleteCICDProfile(ctx, req); err != nil {
		return nil, xerrors.Convert(err)
	}

	return &cicdsdk.DeleteCICDProfileResult{}, nil
}

func cicdProfileFromAPI(in *cicdapi.CICDProfile) (cicdsdk.CICDProfile, error) {
	if in == nil {
		return cicdsdk.CICDProfile{}, xerrors.UnexpectedResponseField("profile")
	}
	typ, err := cicdTypeFromAPI(in.Type)
	if err != nil {
		return cicdsdk.CICDProfile{}, err
	}
	return cicdsdk.CICDProfile{
		ID:          in.Id,
		Type:        typ,
		Name:        in.Name,
		Issuer:      in.Issuer,
		CreatedBy:   in.CreatedBy,
		CreatedBySA: in.CreatedBySa,
		JWKSURL:     in.JwksUrl,
		Claims:      in.Claims,
	}, nil
}

func cicdTypeToAPI(in cicdsdk.CICDType) cicdapi.CICDType {
	switch in {
	case cicdsdk.CICDTypeJenkins:
		return cicdapi.CICDType_CICDTYPE_JENKINS
	case cicdsdk.CICDTypeGithubSAAS:
		return cicdapi.CICDType_CICDTYPE_GITHUB_SAAS
	case cicdsdk.CICDTypeGithubSelfHosted:
		return cicdapi.CICDType_CICDTYPE_GITHUB_SELF_HOSTED
	case cicdsdk.CICDTypeGithubHybrid:
		return cicdapi.CICDType_CICDTYPE_GITHUB_HYBRID
	case cicdsdk.CICDTypeGitlabSAAS:
		return cicdapi.CICDType_CICDTYPE_GITLAB_SAAS
	case cicdsdk.CICDTypeGitlabSelfHosted:
		return cicdapi.CICDType_CICDTYPE_GITLAB_SELF_HOSTED
	case cicdsdk.CICDTypeGitlabHybrid:
		return cicdapi.CICDType_CICDTYPE_GITLAB_HYBRID
	}
	return cicdapi.CICDType_CICDTYPE_UNKNOWN
}

func cicdTypeFromAPI(in cicdapi.CICDType) (cicdsdk.CICDType, error) {
	switch in {
	case cicdapi.CICDType_CICDTYPE_UNKNOWN:
		return "", nil
	case cicdapi.CICDType_CICDTYPE_JENKINS:
		return cicdsdk.CICDTypeJenkins, nil
	case cicdapi.CICDType_CICDTYPE_GITHUB_SAAS:
		return cicdsdk.CICDTypeGithubSAAS, nil
	case cicdapi.CICDType_CICDTYPE_GITHUB_SELF_HOSTED:
		return cicdsdk.CICDTypeGithubSelfHosted, nil
	case cicdapi.CICDType_CICDTYPE_GITHUB_HYBRID:
		return cicdsdk.CICDTypeGithubHybrid, nil
	case cicdapi.CICDType_CICDTYPE_GITLAB_SAAS:
		return cicdsdk.CICDTypeGitlabSAAS, nil
	case cicdapi.CICDType_CICDTYPE_GITLAB_SELF_HOSTED:
		return cicdsdk.CICDTypeGitlabSelfHosted, nil
	case cicdapi.CICDType_CICDTYPE_GITLAB_HYBRID:
		return cicdsdk.CICDTypeGitlabHybrid, nil
	}
	return "", fmt.Errorf("%w: cicd type %d", xerrors.UnexpectedResponseField("profile.type"), in)
}

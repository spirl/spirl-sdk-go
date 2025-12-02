package client

import (
	"context"

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
		Issuer:  optionalValue(params.Issuer),
		JwksUrl: optionalValue(params.JWKSURL),
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
	return cicdsdk.CICDProfile{
		ID:      in.Id,
		Name:    in.Name,
		Issuer:  in.Issuer,
		JWKSURL: in.JwksUrl,
	}, nil
}

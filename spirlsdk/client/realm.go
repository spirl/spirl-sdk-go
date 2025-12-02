package client

import (
	"context"

	"google.golang.org/grpc"

	"github.com/spirl/spirl-sdk-go/spirlsdk/internal/protos/api/v1/realmapi"
	"github.com/spirl/spirl-sdk-go/spirlsdk/internal/xerrors"
	"github.com/spirl/spirl-sdk-go/spirlsdk/realmsdk"
)

func makeRealmAPI(conn grpc.ClientConnInterface) realmsdk.API {
	return realmAPI{client: realmapi.NewAPIClient(conn)}
}

type realmAPI struct {
	client realmapi.APIClient
}

func (a realmAPI) CreateRealm(ctx context.Context, params realmsdk.CreateRealmParams) (*realmsdk.CreateRealmResult, error) {
	req := &realmapi.CreateRealmRequest{
		TrustDomainId: params.TrustDomainID,
		Name:          params.Name,
	}

	resp, err := a.client.CreateRealm(ctx, req)
	if err != nil {
		return nil, xerrors.Convert(err)
	}

	return &realmsdk.CreateRealmResult{
		RealmID: resp.RealmId,
	}, nil
}

func (a realmAPI) ListRealms(ctx context.Context, params realmsdk.ListRealmsParams) (*realmsdk.ListRealmsResult, error) {
	req := &realmapi.ListRealmsRequest{
		TrustDomainId: optionalValue(params.Filter.TrustDomainID),
		Name:          optionalValue(params.Filter.Name),
	}

	resp, err := a.client.ListRealms(ctx, req)
	if err != nil {
		return nil, xerrors.Convert(err)
	}

	realms, err := convertSlice(resp.Realms, realmFromAPI)
	if err != nil {
		return nil, err
	}

	return &realmsdk.ListRealmsResult{Realms: realms}, nil
}

func (a realmAPI) DeleteRealm(ctx context.Context, params realmsdk.DeleteRealmParams) (*realmsdk.DeleteRealmResult, error) {
	req := &realmapi.DeleteRealmRequest{
		RealmId: params.RealmID,
	}

	if _, err := a.client.DeleteRealm(ctx, req); err != nil {
		return nil, xerrors.Convert(err)
	}

	return &realmsdk.DeleteRealmResult{}, nil
}

func realmFromAPI(in *realmapi.Realm) (realmsdk.Realm, error) {
	if in == nil {
		return realmsdk.Realm{}, xerrors.UnexpectedResponseField("realm")
	}
	return realmsdk.Realm{
		ID:            in.Id,
		OrgID:         in.OrgId,
		TrustDomainID: in.TrustDomainId,
		Name:          in.Name,
		CreatedAt:     timeFromAPI(in.CreatedAt),
	}, nil
}

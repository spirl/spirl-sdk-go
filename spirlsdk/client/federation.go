package client

import (
	"context"
	"fmt"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"google.golang.org/grpc"

	"github.com/spirl/spirl-sdk-go/spirlsdk/federationsdk"
	"github.com/spirl/spirl-sdk-go/spirlsdk/internal/protos/api/v1/federationapi"
	"github.com/spirl/spirl-sdk-go/spirlsdk/internal/xerrors"
)

func makeFederationAPI(conn grpc.ClientConnInterface) federationsdk.API {
	return federationAPI{client: federationapi.NewAPIClient(conn)}
}

type federationAPI struct {
	client federationapi.APIClient
}

func (a federationAPI) SetLink(ctx context.Context, params federationsdk.SetLinkParams) (*federationsdk.SetLinkResult, error) {
	link, err := federationLinkToAPI(params.Link)
	if err != nil {
		return nil, err
	}

	req := &federationapi.SetLinkRequest{
		TrustDomainId: params.TrustDomainID,
		Link:          link,
	}

	if _, err := a.client.SetLink(ctx, req); err != nil {
		return nil, xerrors.Convert(err)
	}

	return &federationsdk.SetLinkResult{}, nil
}

func (a federationAPI) DeleteLink(ctx context.Context, params federationsdk.DeleteLinkParams) (*federationsdk.DeleteLinkResult, error) {
	req := &federationapi.DeleteLinkRequest{
		TrustDomainId:          params.TrustDomainID,
		ForeignTrustDomainName: params.ForeignTrustDomain.Name(),
	}

	if _, err := a.client.DeleteLink(ctx, req); err != nil {
		return nil, xerrors.Convert(err)
	}

	return &federationsdk.DeleteLinkResult{}, nil
}

func (a federationAPI) ListLinks(ctx context.Context, params federationsdk.ListLinksParams) (*federationsdk.ListLinksResult, error) {
	req := &federationapi.ListLinksRequest{
		TrustDomainId: optionalValue(params.Filter.TrustDomainID),
	}

	resp, err := a.client.ListLinks(ctx, req)
	if err != nil {
		return nil, xerrors.Convert(err)
	}

	linkStatuses, err := convertSlice(resp.LinkStatuses, federationLinkStatusFromAPI)
	if err != nil {
		return nil, err
	}

	return &federationsdk.ListLinksResult{LinkStatuses: linkStatuses}, nil
}

func (a federationAPI) RefreshLink(ctx context.Context, params federationsdk.RefreshLinkParams) (*federationsdk.RefreshLinkResult, error) {
	req := &federationapi.RefreshLinkRequest{
		TrustDomainId:          params.TrustDomainID,
		ForeignTrustDomainName: params.ForeignTrustDomain.Name(),
	}

	if _, err := a.client.RefreshLink(ctx, req); err != nil {
		return nil, xerrors.Convert(err)
	}

	return &federationsdk.RefreshLinkResult{}, nil
}

func federationLinkToAPI(in federationsdk.Link) (*federationapi.Link, error) {
	endpoint := &federationapi.Endpoint{
		Url:     in.Endpoint.URL,
		Profile: nil, // filled out below
	}

	switch in.Endpoint.Profile.(type) {
	case federationsdk.HTTPSWebProfile:
		endpoint.Profile = &federationapi.Endpoint_HttpsWeb{
			HttpsWeb: &federationapi.HTTPSWebProfile{},
		}
	default:
		return nil, fmt.Errorf("unhandled profile type %T", in.Endpoint.Profile)
	}

	return &federationapi.Link{
		TrustDomainName: in.ForeignTrustDomain.Name(),
		Endpoint:        endpoint,
	}, nil
}

func federationLinkStatusFromAPI(in *federationapi.LinkStatus) (federationsdk.LinkStatus, error) {
	link, err := federationLinkFromAPI(in.Link)
	if err != nil {
		return federationsdk.LinkStatus{}, err
	}

	var lastPoll *federationsdk.PollStatus
	if in.LastPoll != nil {
		lastPoll = &federationsdk.PollStatus{
			Timestamp: timeFromAPI(in.LastPoll.Timestamp),
			Error:     in.LastPoll.Error,
			HTTPLog:   in.LastPoll.HttpLog,
		}
	}
	return federationsdk.LinkStatus{
		TrustDomainID:    in.TrustDomainId,
		TrustDomainName:  in.TrustDomainName,
		Link:             link,
		LastPoll:         lastPoll,
		LastBundleUpdate: timeFromAPI(in.LastBundleUpdate),
		CreatedAt:        timeFromAPI(in.CreatedAt),
	}, nil
}

func federationLinkFromAPI(in *federationapi.Link) (federationsdk.Link, error) {
	foreignTrustDomain, err := spiffeid.TrustDomainFromString(in.TrustDomainName)
	if err != nil {
		return federationsdk.Link{}, fmt.Errorf("%w: %v", xerrors.UnexpectedResponseField("link.trust_domain_name"), err)
	}
	endpoint, err := federationEndpointFromAPI(in.Endpoint)
	if err != nil {
		return federationsdk.Link{}, fmt.Errorf("%w: %v", xerrors.UnexpectedResponseField("link.endpoint.profile"), err)
	}
	return federationsdk.Link{
		ForeignTrustDomain: foreignTrustDomain,
		Endpoint:           endpoint,
	}, nil
}

func federationEndpointFromAPI(in *federationapi.Endpoint) (federationsdk.Endpoint, error) {
	endpoint := federationsdk.Endpoint{
		URL:     in.Url,
		Profile: nil, // filled out below
	}

	switch in.Profile.(type) {
	case *federationapi.Endpoint_HttpsWeb:
		endpoint.Profile = federationsdk.HTTPSWebProfile{}
	default:
		return federationsdk.Endpoint{}, xerrors.UnexpectedResponseType("link.endpoint.profile", in.Profile)
	}

	return endpoint, nil
}

package client

import (
	"context"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/spirl/spirl-sdk-go/spirlsdk/devidentitysdk"
	"github.com/spirl/spirl-sdk-go/spirlsdk/internal/protos/api/v1/devidentityapi"
	"github.com/spirl/spirl-sdk-go/spirlsdk/internal/xerrors"
)

func makeDevIdentityAPI(conn grpc.ClientConnInterface) devidentitysdk.API {
	return devIdentityAPI{client: devidentityapi.NewAPIClient(conn)}
}

type devIdentityAPI struct {
	client devidentityapi.APIClient
}

func (a devIdentityAPI) AddDevIdentityPolicy(ctx context.Context, params devidentitysdk.AddDevIdentityPolicyParams) (*devidentitysdk.AddDevIdentityPolicyResult, error) {
	req := &devidentityapi.AddDevIdentityPolicyRequest{
		Name:            params.Name,
		DevOidcConfigId: params.DevOIDCConfigID,
		ClaimsFilter:    optionalValue1(params.ClaimsFilter, devIdentityClaimsFilterToAPI),
		PathTemplate:    optionalValue(params.PathTemplate),
		SvidTtl:         optionalValue1(params.SVIDTTL, durationpb.New),
	}

	resp, err := a.client.AddDevIdentityPolicy(ctx, req)
	if err != nil {
		return nil, xerrors.Convert(err)
	}

	return &devidentitysdk.AddDevIdentityPolicyResult{ID: resp.Id}, nil
}

func (a devIdentityAPI) UpdateDevIdentityPolicy(ctx context.Context, params devidentitysdk.UpdateDevIdentityPolicyParams) (*devidentitysdk.UpdateDevIdentityPolicyResult, error) {
	req := &devidentityapi.UpdateDevIdentityPolicyRequest{
		Id:              params.ID,
		DevOidcConfigId: optionalValue(params.DevOIDCConfigID),
		ClaimsFilter:    optionalValue1(params.ClaimsFilter, devIdentityClaimsFilterToAPI),
		PathTemplate:    optionalValue(params.PathTemplate),
		SvidTtl:         optionalValue1(params.SVIDTTL, durationpb.New),
	}

	if _, err := a.client.UpdateDevIdentityPolicy(ctx, req); err != nil {
		return nil, xerrors.Convert(err)
	}

	return &devidentitysdk.UpdateDevIdentityPolicyResult{}, nil
}

func (a devIdentityAPI) DeleteDevIdentityPolicy(ctx context.Context, params devidentitysdk.DeleteDevIdentityPolicyParams) (*devidentitysdk.DeleteDevIdentityPolicyResult, error) {
	req := &devidentityapi.DeleteDevIdentityPolicyRequest{
		Id: params.ID,
	}

	if _, err := a.client.DeleteDevIdentityPolicy(ctx, req); err != nil {
		return nil, xerrors.Convert(err)
	}

	return &devidentitysdk.DeleteDevIdentityPolicyResult{}, nil
}

func (a devIdentityAPI) ListDevIdentityPolicies(ctx context.Context, params devidentitysdk.ListDevIdentityPoliciesParams) (*devidentitysdk.ListDevIdentityPoliciesResult, error) {
	req := &devidentityapi.ListDevIdentityPoliciesRequest{
		Name: optionalValue(params.Filter.Name),
	}

	resp, err := a.client.ListDevIdentityPolicies(ctx, req)
	if err != nil {
		return nil, xerrors.Convert(err)
	}

	policies, err := convertSlice(resp.Policies, devIdentityPolicyFromAPI)
	if err != nil {
		return nil, err
	}

	return &devidentitysdk.ListDevIdentityPoliciesResult{DevIDPolicies: policies}, nil
}

func (a devIdentityAPI) AddDevIdentityOIDCConfig(ctx context.Context, params devidentitysdk.AddDevIdentityOIDCConfigParams) (*devidentitysdk.AddDevIdentityOIDCConfigResult, error) {
	req := &devidentityapi.AddDevIdentityOIDCConfigRequest{
		Name:               params.Name,
		IssuerUrl:          params.IssuerURL,
		ClientId:           params.ClientID,
		ClientAuthMethod:   devIdentityClientAuthMethodToAPI(params.ClientAuthMethod),
		ClientSecret:       optionalValue(params.ClientSecret),
		ClientPrivateKey:   optionalValue(params.ClientPrivateKey),
		ClientPrivateKeyId: optionalValue(params.ClientPrivateKeyID),
	}

	resp, err := a.client.AddDevIdentityOIDCConfig(ctx, req)
	if err != nil {
		return nil, xerrors.Convert(err)
	}

	return &devidentitysdk.AddDevIdentityOIDCConfigResult{ID: resp.Id}, nil
}

func (a devIdentityAPI) UpdateDevIdentityOIDCConfig(ctx context.Context, params devidentitysdk.UpdateDevIdentityOIDCConfigParams) (*devidentitysdk.UpdateDevIdentityOIDCConfigResult, error) {
	req := &devidentityapi.UpdateDevIdentityOIDCConfigRequest{
		Id:                 params.ID,
		IssuerUrl:          optionalValue(params.IssuerURL),
		ClientId:           optionalValue(params.ClientID),
		ClientAuthMethod:   optionalValue2(params.ClientAuthMethod, devIdentityClientAuthMethodToAPI, ptrOf),
		ClientSecret:       optionalValue(params.ClientSecret),
		ClientPrivateKey:   optionalValue(params.ClientPrivateKey),
		ClientPrivateKeyId: optionalValue(params.ClientPrivateKeyID),
	}

	if _, err := a.client.UpdateDevIdentityOIDCConfig(ctx, req); err != nil {
		return nil, xerrors.Convert(err)
	}

	return &devidentitysdk.UpdateDevIdentityOIDCConfigResult{}, nil
}

func (a devIdentityAPI) ListDevIdentityOIDCConfigs(ctx context.Context, params devidentitysdk.ListDevIdentityOIDCConfigsParams) (*devidentitysdk.ListDevIdentityOIDCConfigsResult, error) {
	req := &devidentityapi.ListDevIdentityOIDCConfigsRequest{
		Name: optionalValue(params.Filter.Name),
	}

	resp, err := a.client.ListDevIdentityOIDCConfigs(ctx, req)
	if err != nil {
		return nil, xerrors.Convert(err)
	}

	devOIDCConfigs, err := convertSlice(resp.Configs, devIdentityOIDCConfigFromAPI)
	if err != nil {
		return nil, err
	}

	return &devidentitysdk.ListDevIdentityOIDCConfigsResult{DevOIDCConfigs: devOIDCConfigs}, nil
}

func (a devIdentityAPI) DeleteDevIdentityOIDCConfig(ctx context.Context, params devidentitysdk.DeleteDevIdentityOIDCConfigParams) (*devidentitysdk.DeleteDevIdentityOIDCConfigResult, error) {
	req := &devidentityapi.DeleteDevIdentityOIDCConfigRequest{
		Id: params.ID,
	}

	if _, err := a.client.DeleteDevIdentityOIDCConfig(ctx, req); err != nil {
		return nil, xerrors.Convert(err)
	}

	return &devidentitysdk.DeleteDevIdentityOIDCConfigResult{}, nil
}

func (a devIdentityAPI) EnablePolicy(ctx context.Context, params devidentitysdk.EnablePolicyParams) (*devidentitysdk.EnablePolicyResult, error) {
	req := &devidentityapi.EnablePolicyRequest{
		PolicyId:      params.PolicyID,
		TrustDomainId: params.TrustDomainID,
	}

	if _, err := a.client.EnablePolicy(ctx, req); err != nil {
		return nil, xerrors.Convert(err)
	}

	return &devidentitysdk.EnablePolicyResult{}, nil
}

func (a devIdentityAPI) DisablePolicy(ctx context.Context, params devidentitysdk.DisablePolicyParams) (*devidentitysdk.DisablePolicyResult, error) {
	req := &devidentityapi.DisablePolicyRequest{
		TrustDomainId: params.TrustDomainID,
	}

	resp, err := a.client.DisablePolicy(ctx, req)
	if err != nil {
		return nil, xerrors.Convert(err)
	}

	return &devidentitysdk.DisablePolicyResult{
		PolicyName: resp.PolicyName,
	}, nil
}

func (a devIdentityAPI) UnifiedAccessStatus(ctx context.Context, params devidentitysdk.UnifiedAccessStatusParams) (*devidentitysdk.UnifiedAccessStatusResult, error) {
	req := &devidentityapi.UnifiedAccessStatusRequest{
		TrustDomainId: optionalValue(params.Filter.TrustDomainID),
	}

	resp, err := a.client.UnifiedAccessStatus(ctx, req)
	if err != nil {
		return nil, xerrors.Convert(err)
	}

	statuses := mapSlice(resp.UnifiedAccessStatus, unifiedAccessStatusFromAPI)

	return &devidentitysdk.UnifiedAccessStatusResult{UnifiedAccessStatuses: statuses}, nil
}

func devIdentityPolicyFromAPI(in *devidentityapi.DevIDPolicy) (devidentitysdk.DevIDPolicy, error) {
	claimsFilter, err := devIdentityClaimsFilterFromAPI(in.ClaimsFilter)
	if err != nil {
		return devidentitysdk.DevIDPolicy{}, err
	}
	return devidentitysdk.DevIDPolicy{
		ID:                in.Id,
		Name:              in.Name,
		DevOIDCConfigID:   in.DevOidcConfigId,
		DevOIDCConfigName: in.DevOidcConfigName,
		ClaimsFilter:      claimsFilter,
		PathTemplate:      in.PathTemplate,
		SVIDTTL:           durationFromAPI(in.SvidTtl),
	}, nil
}

func devIdentityClaimsFilterFromAPI(in *devidentityapi.ClaimsFilter) (devidentitysdk.ClaimsFilter, error) {
	filters, err := convertSlice(in.Filters, devIdentityClaimFilterFromAPI)
	if err != nil {
		return devidentitysdk.ClaimsFilter{}, err
	}
	return devidentitysdk.ClaimsFilter{
		Filters: filters,
	}, nil
}

func devIdentityClaimFilterFromAPI(in *devidentityapi.ClaimFilter) (devidentitysdk.ClaimFilter, error) {
	operator, err := devIdentityClaimComparisonOperatorFromAPI(in.Operator)
	if err != nil {
		return devidentitysdk.ClaimFilter{}, err
	}
	return devidentitysdk.ClaimFilter{
		Key:      in.Key,
		Value:    in.Value,
		Operator: operator,
	}, nil
}

func devIdentityClaimComparisonOperatorFromAPI(in devidentityapi.ComparisonOperator) (devidentitysdk.ClaimComparisonOperator, error) {
	switch in {
	case devidentityapi.ComparisonOperator_EQUAL:
		return devidentitysdk.ClaimComparisonOperatorEqual, nil
	case devidentityapi.ComparisonOperator_NOT_EQUAL:
		return devidentitysdk.ClaimComparisonOperatorNotEqual, nil
	}
	return "", fmt.Errorf("%w: comparison operator %d", xerrors.UnexpectedResponseField("policy.claims_filter.operator"), in)
}

func devIdentityOIDCConfigFromAPI(in *devidentityapi.DevOIDCConfig) (devidentitysdk.DevOIDCConfig, error) {
	clientAuthMethod, err := devIdentityClientAuthMethodFromAPI(in.ClientAuthMethod)
	if err != nil {
		return devidentitysdk.DevOIDCConfig{}, err
	}
	return devidentitysdk.DevOIDCConfig{
		ID:                 in.Id,
		Name:               in.Name,
		IssuerURL:          in.IssuerUrl,
		ClientID:           in.ClientId,
		ClientAuthMethod:   clientAuthMethod,
		ClientSecret:       in.ClientSecret,
		ClientPrivateKey:   in.ClientPrivateKey,
		ClientPrivateKeyID: in.ClientPrivateKeyId,
	}, nil
}

func devIdentityClientAuthMethodFromAPI(in devidentityapi.ClientAuthMethod) (devidentitysdk.ClientAuthMethod, error) {
	switch in {
	case devidentityapi.ClientAuthMethod_CLIENTAUTHMETHOD_NONE:
		return devidentitysdk.ClientAuthMethodNone, nil
	case devidentityapi.ClientAuthMethod_CLIENTAUTHMETHOD_SECRET_BASIC:
		return devidentitysdk.ClientAuthMethodSecretBasic, nil
	case devidentityapi.ClientAuthMethod_CLIENTAUTHMETHOD_SECRET_POST:
		return devidentitysdk.ClientAuthMethodSecretPost, nil
	case devidentityapi.ClientAuthMethod_CLIENTAUTHMETHOD_SECRET_JWT:
		return devidentitysdk.ClientAuthMethodSecretJWT, nil
	case devidentityapi.ClientAuthMethod_CLIENTAUTHMETHOD_PRIVATEKEY_JWT:
		return devidentitysdk.ClientAuthMethodPrivateKeyJWT, nil
	case devidentityapi.ClientAuthMethod_CLIENTAUTHMETHOD_SECRET_AUTODETECT:
		return devidentitysdk.ClientAuthMethodSecretAutoDetect, nil
	}
	return "", fmt.Errorf("%w: client auth method %d", xerrors.UnexpectedResponseField("policy.claims_filter.operator"), in)
}

func devIdentityClaimsFilterToAPI(in devidentitysdk.ClaimsFilter) *devidentityapi.ClaimsFilter {
	return &devidentityapi.ClaimsFilter{
		Filters: mapSlice(in.Filters, devIdentityClaimFilterToAPI),
	}
}

func devIdentityClaimFilterToAPI(in devidentitysdk.ClaimFilter) *devidentityapi.ClaimFilter {
	return &devidentityapi.ClaimFilter{
		Key:      in.Key,
		Value:    in.Value,
		Operator: devIdentityClaimComparisonOperatorToAPI(in.Operator),
	}
}

func devIdentityClaimComparisonOperatorToAPI(in devidentitysdk.ClaimComparisonOperator) devidentityapi.ComparisonOperator {
	switch in {
	case devidentitysdk.ClaimComparisonOperatorEqual:
		return devidentityapi.ComparisonOperator_EQUAL
	case devidentitysdk.ClaimComparisonOperatorNotEqual:
		return devidentityapi.ComparisonOperator_NOT_EQUAL
	}
	return 0
}

func devIdentityClientAuthMethodToAPI(in devidentitysdk.ClientAuthMethod) devidentityapi.ClientAuthMethod {
	switch in {
	case devidentitysdk.ClientAuthMethodNone:
		return devidentityapi.ClientAuthMethod_CLIENTAUTHMETHOD_NONE
	case devidentitysdk.ClientAuthMethodSecretBasic:
		return devidentityapi.ClientAuthMethod_CLIENTAUTHMETHOD_SECRET_BASIC
	case devidentitysdk.ClientAuthMethodSecretPost:
		return devidentityapi.ClientAuthMethod_CLIENTAUTHMETHOD_SECRET_POST
	case devidentitysdk.ClientAuthMethodSecretJWT:
		return devidentityapi.ClientAuthMethod_CLIENTAUTHMETHOD_SECRET_JWT
	case devidentitysdk.ClientAuthMethodPrivateKeyJWT:
		return devidentityapi.ClientAuthMethod_CLIENTAUTHMETHOD_PRIVATEKEY_JWT
	case devidentitysdk.ClientAuthMethodSecretAutoDetect:
		return devidentityapi.ClientAuthMethod_CLIENTAUTHMETHOD_SECRET_AUTODETECT
	}
	return 0
}

func unifiedAccessStatusFromAPI(in *devidentityapi.UnifiedAccessStatus) devidentitysdk.UnifiedAccessStatus {
	return devidentitysdk.UnifiedAccessStatus{
		TrustDomainID:     in.TrustDomainId,
		TrustDomainName:   in.TrustDomainName,
		Enabled:           in.Enabled,
		EnabledPolicyID:   in.EnabledPolicyId,
		EnabledPolicyName: in.EnabledPolicyName,
	}
}

package client

import (
	"context"
	"fmt"

	"google.golang.org/grpc"

	"github.com/spirl/spirl-sdk-go/spirlsdk"
	"github.com/spirl/spirl-sdk-go/spirlsdk/accesssdk"
	"github.com/spirl/spirl-sdk-go/spirlsdk/internal/protos/api/v1/accessapi"
	"github.com/spirl/spirl-sdk-go/spirlsdk/internal/xerrors"
)

func makeAccessAPI(conn grpc.ClientConnInterface) accesssdk.API {
	return accessAPI{client: accessapi.NewAPIClient(conn)}
}

type accessAPI struct {
	client accessapi.APIClient
}

func (a accessAPI) ListOrgRoles(ctx context.Context, params accesssdk.ListOrgRolesParams) (*accesssdk.ListOrgRolesResult, error) {
	req := &accessapi.ListOrgRolesRequest{}

	resp, err := a.client.ListOrgRoles(ctx, req)
	if err != nil {
		return nil, xerrors.Convert(err)
	}

	roles, err := convertSlice(resp.Roles, orgRoleFromAPI)
	if err != nil {
		return nil, xerrors.Convert(err)
	}

	return &accesssdk.ListOrgRolesResult{Roles: roles}, nil
}

func (a accessAPI) ListUsers(ctx context.Context, params accesssdk.ListUsersParams) (*accesssdk.ListUsersResult, error) {
	req := &accessapi.ListUsersRequest{
		ByEmail: optionalValue(params.Filter.Email),
	}

	resp, err := a.client.ListUsers(ctx, req)
	if err != nil {
		return nil, xerrors.Convert(err)
	}

	users, err := convertSlice(resp.Users, userFromAPI)
	if err != nil {
		return nil, err
	}

	return &accesssdk.ListUsersResult{Users: users}, nil
}

func (a accessAPI) UpdateUserRole(ctx context.Context, params accesssdk.UpdateUserRoleParams) (*accesssdk.UpdateUserRoleResult, error) {
	req := &accessapi.UpdateUserRoleRequest{
		Id:     params.ID,
		RoleId: params.RoleID,
	}

	if _, err := a.client.UpdateUserRole(ctx, req); err != nil {
		return nil, xerrors.Convert(err)
	}

	return &accesssdk.UpdateUserRoleResult{}, nil
}

func (a accessAPI) DeleteUser(ctx context.Context, params accesssdk.DeleteUserParams) (*accesssdk.DeleteUserResult, error) {
	req := &accessapi.DeleteUserRequest{
		Id: params.ID,
	}

	if _, err := a.client.DeleteUser(ctx, req); err != nil {
		return nil, xerrors.Convert(err)
	}

	return &accesssdk.DeleteUserResult{}, nil
}

func (a accessAPI) CreateUserInvitation(ctx context.Context, params accesssdk.CreateUserInvitationParams) (*accesssdk.CreateUserInvitationResult, error) {
	req := &accessapi.CreateUserInvitationRequest{
		Email:  params.Email,
		RoleId: params.RoleID,
		Ttl:    optionalValue1(params.TTL, durationToAPI),
	}

	resp, err := a.client.CreateUserInvitation(ctx, req)
	if err != nil {
		return nil, xerrors.Convert(err)
	}

	invitation, err := userInvitationFromAPI(resp.Invitation)
	if err != nil {
		return nil, err
	}

	return &accesssdk.CreateUserInvitationResult{UserInvitation: invitation}, nil
}

func (a accessAPI) RenewUserInvitation(ctx context.Context, params accesssdk.RenewUserInvitationParams) (*accesssdk.RenewUserInvitationResult, error) {
	req := &accessapi.RenewUserInvitationRequest{
		Id:  params.ID,
		Ttl: optionalValue1(params.TTL, durationToAPI),
	}

	resp, err := a.client.RenewUserInvitation(ctx, req)
	if err != nil {
		return nil, xerrors.Convert(err)
	}

	invitation, err := userInvitationFromAPI(resp.Invitation)
	if err != nil {
		return nil, err
	}

	return &accesssdk.RenewUserInvitationResult{UserInvitation: invitation}, nil
}

func (a accessAPI) DeleteUserInvitation(ctx context.Context, params accesssdk.DeleteUserInvitationParams) (*accesssdk.DeleteUserInvitationResult, error) {
	req := &accessapi.DeleteUserInvitationRequest{
		Id: params.ID,
	}

	if _, err := a.client.DeleteUserInvitation(ctx, req); err != nil {
		return nil, xerrors.Convert(err)
	}

	return &accesssdk.DeleteUserInvitationResult{}, nil
}

func (a accessAPI) ListUserInvitations(ctx context.Context, params accesssdk.ListUserInvitationsParams) (*accesssdk.ListUserInvitationsResult, error) {
	req := &accessapi.ListUserInvitationsRequest{}

	resp, err := a.client.ListUserInvitations(ctx, req)
	if err != nil {
		return nil, xerrors.Convert(err)
	}

	userInvitations, err := convertSlice(resp.Invitations, userInvitationFromAPI)
	if err != nil {
		return nil, err
	}

	return &accesssdk.ListUserInvitationsResult{UserInvitations: userInvitations}, nil
}

func (a accessAPI) CreateServiceAccount(ctx context.Context, params accesssdk.CreateServiceAccountParams) (*accesssdk.CreateServiceAccountResult, error) {
	req := &accessapi.CreateServiceAccountRequest{
		Name:        params.Name,
		Description: optionalValue(params.Description),
		RoleId:      optionalValue(params.RoleID),
	}

	resp, err := a.client.CreateServiceAccount(ctx, req)
	if err != nil {
		return nil, xerrors.Convert(err)
	}

	serviceAccount, err := serviceAccountFromAPI(resp.ServiceAccount)
	if err != nil {
		return nil, err
	}

	return &accesssdk.CreateServiceAccountResult{ServiceAccount: serviceAccount}, nil
}

func (a accessAPI) ListServiceAccounts(ctx context.Context, params accesssdk.ListServiceAccountsParams) (*accesssdk.ListServiceAccountsResult, error) {
	req := &accessapi.ListServiceAccountsRequest{
		ByName: optionalValue(params.Filter.Name),
	}

	resp, err := a.client.ListServiceAccounts(ctx, req)
	if err != nil {
		return nil, xerrors.Convert(err)
	}

	serviceAccounts, err := convertSlice(resp.ServiceAccounts, serviceAccountFromAPI)
	if err != nil {
		return nil, err
	}

	return &accesssdk.ListServiceAccountsResult{ServiceAccounts: serviceAccounts}, nil
}

func (a accessAPI) GetServiceAccountInfo(ctx context.Context, params accesssdk.GetServiceAccountInfoParams) (*accesssdk.GetServiceAccountInfoResult, error) {
	req := &accessapi.GetServiceAccountInfoRequest{
		Id: params.ID,
	}

	resp, err := a.client.GetServiceAccountInfo(ctx, req)
	if err != nil {
		return nil, xerrors.Convert(err)
	}

	serviceAccount, err := serviceAccountFromAPI(resp.ServiceAccount)
	if err != nil {
		return nil, err
	}

	keys, err := convertSlice(resp.ServiceAccountKeys, serviceAccountKeyFromAPI)
	if err != nil {
		return nil, err
	}

	return &accesssdk.GetServiceAccountInfoResult{ServiceAccount: serviceAccount, Keys: keys}, nil
}

func (a accessAPI) UpdateServiceAccountRole(ctx context.Context, params accesssdk.UpdateServiceAccountRoleParams) (*accesssdk.UpdateServiceAccountRoleResult, error) {
	req := &accessapi.UpdateServiceAccountRoleRequest{
		Id:     params.ID,
		RoleId: params.RoleID,
	}

	resp, err := a.client.UpdateServiceAccountRole(ctx, req)
	if err != nil {
		return nil, xerrors.Convert(err)
	}

	serviceAccount, err := serviceAccountFromAPI(resp.ServiceAccount)
	if err != nil {
		return nil, err
	}

	return &accesssdk.UpdateServiceAccountRoleResult{ServiceAccount: serviceAccount}, nil
}

func (a accessAPI) DeleteServiceAccount(ctx context.Context, params accesssdk.DeleteServiceAccountParams) (*accesssdk.DeleteServiceAccountResult, error) {
	req := &accessapi.DeleteServiceAccountRequest{
		Id:    params.ID,
		Force: optionalValue(params.Force),
	}

	if _, err := a.client.DeleteServiceAccount(ctx, req); err != nil {
		return nil, xerrors.Convert(err)
	}

	return &accesssdk.DeleteServiceAccountResult{}, nil
}

func (a accessAPI) CreateServiceAccountKey(ctx context.Context, params accesssdk.CreateServiceAccountKeyParams) (*accesssdk.CreateServiceAccountKeyResult, error) {
	publicKey, err := publicKeyToAPI(params.PublicKey)
	if err != nil {
		return nil, err
	}

	req := &accessapi.CreateServiceAccountKeyRequest{
		ServiceAccountId: params.ServiceAccountID,
		PubKey: &accessapi.CreateServiceAccountKeyRequest_PkixPubkey{
			PkixPubkey: &accessapi.PKIXPublicKey{Data: publicKey},
		},
	}

	resp, err := a.client.CreateServiceAccountKey(ctx, req)
	if err != nil {
		return nil, xerrors.Convert(err)
	}

	serviceAccountKey, err := serviceAccountKeyFromAPI(resp.ServiceAccountKey)
	if err != nil {
		return nil, err
	}

	return &accesssdk.CreateServiceAccountKeyResult{ServiceAccountKey: serviceAccountKey}, nil
}

func (a accessAPI) DeleteServiceAccountKey(ctx context.Context, params accesssdk.DeleteServiceAccountKeyParams) (*accesssdk.DeleteServiceAccountKeyResult, error) {
	req := &accessapi.DeleteServiceAccountKeyRequest{
		Id:    params.ID,
		Force: optionalValue(params.Force),
	}

	if _, err := a.client.DeleteServiceAccountKey(ctx, req); err != nil {
		return nil, xerrors.Convert(err)
	}

	return &accesssdk.DeleteServiceAccountKeyResult{}, nil
}

func (a accessAPI) UpdateServiceAccountKeyStatus(ctx context.Context, params accesssdk.UpdateServiceAccountKeyStatusParams) (*accesssdk.UpdateServiceAccountKeyStatusResult, error) {
	req := &accessapi.UpdateServiceAccountKeyStatusRequest{
		Id:       params.ID,
		IsActive: params.IsActive,
	}

	resp, err := a.client.UpdateServiceAccountKeyStatus(ctx, req)
	if err != nil {
		return nil, xerrors.Convert(err)
	}

	serviceAccountKey, err := serviceAccountKeyFromAPI(resp.ServiceAccountKey)
	if err != nil {
		return nil, err
	}

	return &accesssdk.UpdateServiceAccountKeyStatusResult{ServiceAccountKey: serviceAccountKey}, nil
}

func (a accessAPI) ListAuditLogs(ctx context.Context, params accesssdk.ListAuditLogsParams) (*accesssdk.ListAuditLogsResult, error) {
	filter := &accessapi.AuditLogFilter{
		ByTrustDomainId:   optionalValue1(params.Filter.TrustDomainID, ptrOf),
		ByTrustDomainName: optionalValue1(params.Filter.TrustDomainName, ptrOf),
		ByRequestId:       optionalValue1(params.Filter.RequestID, ptrOf),
		BySource:          optionalValue2(params.Filter.Source, auditLogSourceToAPI, ptrOf),
		ByService:         optionalValue1(params.Filter.Service, ptrOf),
		ByMethod:          optionalValue1(params.Filter.Method, ptrOf),
		ByActorId:         optionalValue1(params.Filter.ActorID, ptrOf),
		ByActorType:       optionalValue2(params.Filter.ActorType, auditLogActorToAPI, ptrOf),
		ByActorEmail:      optionalValue1(params.Filter.ActorEmail, ptrOf),
		ByActorName:       optionalValue1(params.Filter.ActorName, ptrOf),
		ByActorKeyId:      optionalValue1(params.Filter.ActorKeyID, ptrOf),
		ByStatusCode:      optionalValue1(params.Filter.StatusCode, ptrOf),
	}

	req := &accessapi.ListAuditLogsRequest{
		PageSize:  params.Page.Limit,
		PageToken: params.Page.Token,
		Filter:    messageOrNilIfEmpty(filter),
		StartTime: optionalValue1(params.Filter.StartTime, timeToAPI),
		EndTime:   optionalValue1(params.Filter.EndTime, timeToAPI),
	}

	resp, err := a.client.ListAuditLogs(ctx, req)
	if err != nil {
		return nil, xerrors.Convert(err)
	}

	logs, err := convertSlice(resp.Logs, auditLogFromAPI)
	if err != nil {
		return nil, err
	}

	return &accesssdk.ListAuditLogsResult{
		Page:      spirlsdk.PageResult{NextToken: resp.NextPageToken},
		AuditLogs: logs,
	}, nil
}

func orgRoleFromAPI(in *accessapi.OrgRole) (accesssdk.OrgRole, error) {
	if in == nil {
		return accesssdk.OrgRole{}, xerrors.UnexpectedResponseField("role")
	}
	return accesssdk.OrgRole{
		ID:   in.Id,
		Name: in.Name,
	}, nil
}

func userFromAPI(in *accessapi.User) (accesssdk.User, error) {
	ssoProvider, err := ssoProviderFromAPI(in.SsoProvider)
	if err != nil {
		return accesssdk.User{}, err
	}
	role, err := orgRoleFromAPI(in.Role)
	if err != nil {
		return accesssdk.User{}, err
	}
	return accesssdk.User{
		ID:          in.Id,
		Email:       in.Email,
		Name:        in.Name,
		Role:        role,
		SSOProvider: ssoProvider,
	}, nil
}

func userInvitationFromAPI(in *accessapi.UserInvitation) (accesssdk.UserInvitation, error) {
	if in == nil {
		return accesssdk.UserInvitation{}, xerrors.UnexpectedResponseField("user_invitation")
	}
	role, err := orgRoleFromAPI(in.Role)
	if err != nil {
		return accesssdk.UserInvitation{}, err
	}
	return accesssdk.UserInvitation{
		ID:        in.Id,
		CreatedAt: timeFromAPI(in.CreatedAt),
		ExpiresAt: timeFromAPI(in.ExpiresAt),
		Email:     in.Email,
		Role:      role,
		Code:      in.Code,
		CreatedBy: in.CreatedBy,
		URL:       in.Url,
	}, nil
}

func ssoProviderFromAPI(in string) (accesssdk.SSOProvider, error) {
	switch in {
	case "", "unset":
		return "", nil
	case "enterprise":
		return accesssdk.SSOProviderEnterprise, nil
	case "google":
		return accesssdk.SSOProviderGoogle, nil
	}
	return "", fmt.Errorf("%w: sso provider %q", xerrors.UnexpectedResponseField("sso_provider"), in)
}

func serviceAccountFromAPI(in *accessapi.ServiceAccount) (accesssdk.ServiceAccount, error) {
	if in == nil {
		return accesssdk.ServiceAccount{}, xerrors.UnexpectedResponseField("service_account")
	}
	out := accesssdk.ServiceAccount{
		ID:          in.Id,
		Name:        in.Name,
		Description: in.Description,
		RoleID:      in.RoleId,
		CreatedAt:   timeFromAPI(in.CreatedAt),
		CreatedBy:   accesssdk.CreatedBy{}, //nolint: exhaustruct // filled out below
	}

	if createdBy := in.GetCreatedBy(); createdBy != nil {
		out.CreatedBy = accesssdk.CreatedBy{
			ID:    createdBy.Id,
			Email: createdBy.Email,
		}
	}

	return out, nil
}

func serviceAccountKeyFromAPI(in *accessapi.ServiceAccountKey) (accesssdk.ServiceAccountKey, error) {
	if in == nil {
		return accesssdk.ServiceAccountKey{}, xerrors.UnexpectedResponseField("service_account_key")
	}
	if in.PublicKey == nil {
		return accesssdk.ServiceAccountKey{}, fmt.Errorf("pkix pubkey is unset: %w", xerrors.UnexpectedResponseField("service_account_key.public_key"))
	}
	publicKey, err := publicKeyFromAPI(in.PublicKey)
	if err != nil {
		return accesssdk.ServiceAccountKey{}, fmt.Errorf("pkix pubkey is malformed: %w: %v", xerrors.UnexpectedResponseField("service_account_key.public_key"), err)
	}
	return accesssdk.ServiceAccountKey{
		ID:               in.Id,
		ServiceAccountID: in.ServiceAccountId,
		IsActive:         in.IsActive,
		PublicKey:        publicKey,
		CreatedAt:        timeFromAPI(in.CreatedAt),
	}, nil
}

func auditLogSourceFromAPI(in accessapi.AuditLogSource) (accesssdk.AuditLogSource, error) {
	switch in {
	case accessapi.AuditLogSource_AUDIT_LOG_SOURCE_UNKNOWN:
		return "", nil
	case accessapi.AuditLogSource_AUDIT_LOG_SOURCE_AUTOMATED:
		return accesssdk.AuditLogSourceAutomated, nil
	case accessapi.AuditLogSource_AUDIT_LOG_SOURCE_USER:
		return accesssdk.AuditLogSourceUser, nil
	}
	return "", fmt.Errorf("%w: audit log source %d", xerrors.UnexpectedResponseField("audit_log_source"), in)
}

func auditLogSourceToAPI(in accesssdk.AuditLogSource) accessapi.AuditLogSource {
	switch in {
	case "":
		return accessapi.AuditLogSource_AUDIT_LOG_SOURCE_UNKNOWN
	case accesssdk.AuditLogSourceAutomated:
		return accessapi.AuditLogSource_AUDIT_LOG_SOURCE_AUTOMATED
	case accesssdk.AuditLogSourceUser:
		return accessapi.AuditLogSource_AUDIT_LOG_SOURCE_USER
	}
	return 0
}

func auditLogActorToAPI(in accesssdk.AuditLogActorType) accessapi.AuditLogActorType {
	switch in {
	case "":
		return accessapi.AuditLogActorType_AUDIT_LOG_ACTOR_TYPE_UNKNOWN
	case accesssdk.AuditLogActorTypeUser:
		return accessapi.AuditLogActorType_AUDIT_LOG_ACTOR_TYPE_USER
	case accesssdk.AuditLogActorTypeServiceAccount:
		return accessapi.AuditLogActorType_AUDIT_LOG_ACTOR_TYPE_SERVICE_ACCOUNT
	case accesssdk.AuditLogActorTypeAdmin:
		return accessapi.AuditLogActorType_AUDIT_LOG_ACTOR_TYPE_ADMIN
	}
	return 0
}

func auditLogFromAPI(in *accessapi.AuditLog) (accesssdk.AuditLog, error) {
	actor, err := auditActorFromAPI(in.Actor)
	if err != nil {
		return accesssdk.AuditLog{}, err
	}

	source, err := auditLogSourceFromAPI(in.Source)
	if err != nil {
		return accesssdk.AuditLog{}, err
	}

	return accesssdk.AuditLog{
		Actor:       actor,
		Timestamp:   timeFromAPI(in.Ts),
		TrustDomain: accessTrustDomainFromAPI(in.TrustDomain),
		Source:      source,
		RequestID:   in.RequestId,
		Request:     auditRequestFromAPI(in.Request),
		StatusCode:  in.Status,
	}, nil
}

func auditActorFromAPI(in *accessapi.Actor) (accesssdk.AuditActor, error) {
	if in == nil {
		return nil, nil // nolint: nilnil // intentional
	}
	switch actor := in.Actor.(type) {
	case *accessapi.Actor_User:
		if actor.User == nil {
			// purely defensive; should always be non-nil if the oneof is set.
			return nil, xerrors.UnexpectedResponseField("audit_log.actor.user")
		}
		return accesssdk.UserActor{
			ID:    actor.User.Id,
			Email: actor.User.Email,
		}, nil
	case *accessapi.Actor_ServiceAccount:
		if actor.ServiceAccount == nil {
			// purely defensive; should always be non-nil if the oneof is set.
			return nil, xerrors.UnexpectedResponseField("audit_log.actor.service_account")
		}
		return accesssdk.ServiceAccountActor{
			ID:    actor.ServiceAccount.Id,
			Name:  actor.ServiceAccount.Name,
			KeyID: actor.ServiceAccount.KeyId,
		}, nil
	case *accessapi.Actor_SpirlAdmin:
		if actor.SpirlAdmin == nil {
			// purely defensive; should always be non-nil if the oneof is set.
			return nil, xerrors.UnexpectedResponseField("audit_log.actor.spirl_admin")
		}
		return accesssdk.SPIRLAdminActor{
			ID:    actor.SpirlAdmin.Id,
			Email: actor.SpirlAdmin.Email,
		}, nil
	}
	return nil, xerrors.UnexpectedResponseType("audit_log.actor", in.Actor)
}

func accessTrustDomainFromAPI(req *accessapi.TrustDomain) accesssdk.TrustDomain {
	if req == nil {
		return accesssdk.TrustDomain{} //nolint: exhaustruct // zero value ok
	}
	return accesssdk.TrustDomain{
		ID:   req.Id,
		Name: req.Name,
	}
}

func auditRequestFromAPI(req *accessapi.Request) accesssdk.AuditedRequest {
	if req == nil {
		return accesssdk.AuditedRequest{} //nolint: exhaustruct // zero value ok
	}
	return accesssdk.AuditedRequest{
		Service: req.Service,
		Method:  req.Method,
		Message: req.Message,
	}
}

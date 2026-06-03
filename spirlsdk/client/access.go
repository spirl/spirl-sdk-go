package client

import (
	"context"
	"fmt"

	"google.golang.org/grpc"

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

func (a accessAPI) AssignUserRealmRole(ctx context.Context, params accesssdk.AssignUserRealmRoleParams) (*accesssdk.AssignUserRealmRoleResult, error) {
	req := &accessapi.AssignRoleAssignmentRequest{
		Principal: &accessapi.AssignRoleAssignmentRequest_UserId{UserId: params.UserID},
		RoleAssignment: &accessapi.AssignRoleAssignmentRequest_RealmRole{
			RealmRole: &accessapi.RealmRoleAssignment{
				RealmId: params.RealmID,
				RoleId:  params.RoleID,
			},
		},
	}

	resp, err := a.client.AssignRoleAssignment(ctx, req)
	if err != nil {
		return nil, xerrors.Convert(err)
	}

	if resp.GetAssignmentId() == "" {
		return nil, xerrors.UnexpectedResponseField("assignment_id")
	}

	return &accesssdk.AssignUserRealmRoleResult{AssignmentID: resp.AssignmentId, CreatedAt: resp.CreatedAt.AsTime()}, nil
}

func (a accessAPI) AssignServiceAccountRealmRole(ctx context.Context, params accesssdk.AssignServiceAccountRealmRoleParams) (*accesssdk.AssignServiceAccountRealmRoleResult, error) {
	req := &accessapi.AssignRoleAssignmentRequest{
		Principal: &accessapi.AssignRoleAssignmentRequest_ServiceAccountId{ServiceAccountId: params.ServiceAccountID},
		RoleAssignment: &accessapi.AssignRoleAssignmentRequest_RealmRole{
			RealmRole: &accessapi.RealmRoleAssignment{
				RealmId: params.RealmID,
				RoleId:  params.RoleID,
			},
		},
	}

	resp, err := a.client.AssignRoleAssignment(ctx, req)
	if err != nil {
		return nil, xerrors.Convert(err)
	}

	if resp.GetAssignmentId() == "" {
		return nil, xerrors.UnexpectedResponseField("assignment_id")
	}

	return &accesssdk.AssignServiceAccountRealmRoleResult{AssignmentID: resp.AssignmentId, CreatedAt: resp.CreatedAt.AsTime()}, nil
}

func (a accessAPI) ListUserRealmRoleAssignments(ctx context.Context, params accesssdk.ListUserRealmRoleAssignmentsParams) (*accesssdk.ListUserRealmRoleAssignmentsResult, error) {
	req := &accessapi.ListRoleAssignmentsRequest{
		Principal: &accessapi.ListRoleAssignmentsRequest_UserId{UserId: params.UserID},
	}

	resp, err := a.client.ListRoleAssignments(ctx, req)
	if err != nil {
		return nil, xerrors.Convert(err)
	}

	assignments, err := convertSlice(resp.Assignments, roleAssignmentFromAPI)
	if err != nil {
		return nil, err
	}

	return &accesssdk.ListUserRealmRoleAssignmentsResult{Assignments: assignments}, nil
}

func (a accessAPI) ListServiceAccountRealmRoleAssignments(ctx context.Context, params accesssdk.ListServiceAccountRealmRoleAssignmentsParams) (*accesssdk.ListServiceAccountRealmRoleAssignmentsResult, error) {
	req := &accessapi.ListRoleAssignmentsRequest{
		Principal: &accessapi.ListRoleAssignmentsRequest_ServiceAccountId{ServiceAccountId: params.ServiceAccountID},
	}

	resp, err := a.client.ListRoleAssignments(ctx, req)
	if err != nil {
		return nil, xerrors.Convert(err)
	}

	assignments, err := convertSlice(resp.Assignments, roleAssignmentFromAPI)
	if err != nil {
		return nil, err
	}

	return &accesssdk.ListServiceAccountRealmRoleAssignmentsResult{Assignments: assignments}, nil
}

func (a accessAPI) ListAssignmentIDRealmRoleAssignments(ctx context.Context, params accesssdk.ListAssignmentIDRealmRoleAssignmentsParams) (*accesssdk.ListAssignmentIDRealmRoleAssignmentsResult, error) {
	req := &accessapi.ListRoleAssignmentsRequest{
		Principal: &accessapi.ListRoleAssignmentsRequest_AssignmentId{AssignmentId: params.AssignmentID},
	}

	resp, err := a.client.ListRoleAssignments(ctx, req)
	if err != nil {
		return nil, xerrors.Convert(err)
	}

	assignments, err := convertSlice(resp.Assignments, roleAssignmentFromAPI)
	if err != nil {
		return nil, err
	}

	return &accesssdk.ListAssignmentIDRealmRoleAssignmentsResult{Assignments: assignments}, nil
}

func (a accessAPI) RemoveRealmRoleAssignment(ctx context.Context, params accesssdk.RemoveRealmRoleAssignmentParams) (*accesssdk.RemoveRealmRoleAssignmentResult, error) {
	req := &accessapi.RemoveRoleAssignmentRequest{
		AssignmentId: params.AssignmentID,
	}

	if _, err := a.client.RemoveRoleAssignment(ctx, req); err != nil {
		return nil, xerrors.Convert(err)
	}

	return &accesssdk.RemoveRealmRoleAssignmentResult{}, nil
}

func roleAssignmentFromAPI(in *accessapi.RoleAssignment) (accesssdk.RoleAssignment, error) {
	if in == nil {
		return accesssdk.RoleAssignment{}, xerrors.UnexpectedResponseField("role_assignment")
	}
	if in.Id == "" {
		return accesssdk.RoleAssignment{}, xerrors.UnexpectedResponseField("role_assignment.id")
	}

	principal, err := roleAssignmentPrincipalFromAPI(in.GetPrincipal())
	if err != nil {
		return accesssdk.RoleAssignment{}, err
	}

	realmRole, err := realmRoleAssignmentFromAPI(in.GetRealmRole())
	if err != nil {
		return accesssdk.RoleAssignment{}, err
	}

	if in.CreatedAt == nil {
		return accesssdk.RoleAssignment{}, xerrors.UnexpectedResponseField("role_assignment.created_at")
	}

	return accesssdk.RoleAssignment{
		ID:        in.Id,
		Principal: principal,
		RealmRole: realmRole,
		CreatedAt: timeFromAPI(in.CreatedAt),
	}, nil
}

func roleAssignmentPrincipalFromAPI(in any) (accesssdk.RoleAssignmentPrincipal, error) {
	switch principal := in.(type) {
	case *accessapi.RoleAssignment_UserId:
		if principal.UserId == "" {
			return nil, xerrors.UnexpectedResponseField("role_assignment.principal.user_id")
		}
		return accesssdk.UserRoleAssignmentPrincipal{UserID: principal.UserId}, nil
	case *accessapi.RoleAssignment_ServiceAccountId:
		if principal.ServiceAccountId == "" {
			return nil, xerrors.UnexpectedResponseField("role_assignment.principal.service_account_id")
		}
		return accesssdk.ServiceAccountRoleAssignmentPrincipal{ServiceAccountID: principal.ServiceAccountId}, nil
	case nil:
		return nil, xerrors.UnexpectedResponseField("role_assignment.principal")
	default:
		return nil, xerrors.UnexpectedResponseType("role_assignment.principal", principal)
	}
}

func realmRoleAssignmentFromAPI(in *accessapi.RealmRoleAssignment) (accesssdk.RealmRoleAssignment, error) {
	if in == nil {
		return accesssdk.RealmRoleAssignment{}, xerrors.UnexpectedResponseField("realm_role_assignment")
	}
	if in.RealmId == "" {
		return accesssdk.RealmRoleAssignment{}, xerrors.UnexpectedResponseField("realm_role_assignment.realm_id")
	}
	if in.RoleId == "" {
		return accesssdk.RealmRoleAssignment{}, xerrors.UnexpectedResponseField("realm_role_assignment.role_id")
	}

	return accesssdk.RealmRoleAssignment{
		RealmID: in.RealmId,
		RoleID:  in.RoleId,
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

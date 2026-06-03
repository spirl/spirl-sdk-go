package accesssdk

import (
	"context"
	"time"
)

type API interface {
	// ListOrgRoles lists the roles.
	ListOrgRoles(ctx context.Context, params ListOrgRolesParams) (*ListOrgRolesResult, error)

	// ListUsers lists users.
	ListUsers(ctx context.Context, params ListUsersParams) (*ListUsersResult, error)

	// UpdateUserRole updates the role of a user.
	UpdateUserRole(ctx context.Context, params UpdateUserRoleParams) (*UpdateUserRoleResult, error)

	// DeleteUser deletes a user.
	DeleteUser(ctx context.Context, params DeleteUserParams) (*DeleteUserResult, error)

	// CreateUserInvitation creates a user invitation to the organization.
	CreateUserInvitation(ctx context.Context, params CreateUserInvitationParams) (*CreateUserInvitationResult, error)

	// RenewUserInvitation renews a user invitation by setting a new expiration date.
	RenewUserInvitation(ctx context.Context, params RenewUserInvitationParams) (*RenewUserInvitationResult, error)

	// DeleteUserInvitation deletes a user invitation to the organization.
	DeleteUserInvitation(ctx context.Context, params DeleteUserInvitationParams) (*DeleteUserInvitationResult, error)

	// ListUserInvitations lists the user invitations to the organization.
	ListUserInvitations(ctx context.Context, params ListUserInvitationsParams) (*ListUserInvitationsResult, error)

	// CreateServiceAccount creates a new service account.
	// The caller role must be as permissive as the desired service account
	// role.
	CreateServiceAccount(ctx context.Context, params CreateServiceAccountParams) (*CreateServiceAccountResult, error)

	// ListServiceAccounts lists service accounts.
	ListServiceAccounts(ctx context.Context, params ListServiceAccountsParams) (*ListServiceAccountsResult, error)

	// GetServiceAccountInfo retrieves information about a service account.
	GetServiceAccountInfo(ctx context.Context, params GetServiceAccountInfoParams) (*GetServiceAccountInfoResult, error)

	// UpdateServiceAccountRole updates the role for a service account.
	UpdateServiceAccountRole(ctx context.Context, params UpdateServiceAccountRoleParams) (*UpdateServiceAccountRoleResult, error)

	// DeleteServiceAccountKey deletes a service account.
	DeleteServiceAccount(ctx context.Context, params DeleteServiceAccountParams) (*DeleteServiceAccountResult, error)

	// CreateServiceAccountKey creates a new key for a service account.
	CreateServiceAccountKey(ctx context.Context, params CreateServiceAccountKeyParams) (*CreateServiceAccountKeyResult, error)

	// DeleteServiceAccountKey deletes a key from a service account.
	DeleteServiceAccountKey(ctx context.Context, params DeleteServiceAccountKeyParams) (*DeleteServiceAccountKeyResult, error)

	// UpdateServiceAccountRoleStatus changes the "active" status of a service account key.
	UpdateServiceAccountKeyStatus(ctx context.Context, params UpdateServiceAccountKeyStatusParams) (*UpdateServiceAccountKeyStatusResult, error)

	// AssignUserRealmRole assigns a realm role to a user.
	AssignUserRealmRole(ctx context.Context, params AssignUserRealmRoleParams) (*AssignUserRealmRoleResult, error)

	// AssignServiceAccountRealmRole assigns a realm role to a service account.
	AssignServiceAccountRealmRole(ctx context.Context, params AssignServiceAccountRealmRoleParams) (*AssignServiceAccountRealmRoleResult, error)

	// ListUserRealmRoleAssignments lists realm role assignments for a user.
	ListUserRealmRoleAssignments(ctx context.Context, params ListUserRealmRoleAssignmentsParams) (*ListUserRealmRoleAssignmentsResult, error)

	// ListServiceAccountRealmRoleAssignments lists realm role assignments for a service account.
	ListServiceAccountRealmRoleAssignments(ctx context.Context, params ListServiceAccountRealmRoleAssignmentsParams) (*ListServiceAccountRealmRoleAssignmentsResult, error)

	// ListAssignmentIDRealmRoleAssignments lists realm role assignments for an assignment ID.
	ListAssignmentIDRealmRoleAssignments(ctx context.Context, params ListAssignmentIDRealmRoleAssignmentsParams) (*ListAssignmentIDRealmRoleAssignmentsResult, error)

	// RemoveRealmRoleAssignment removes a realm role assignment from any principal.
	RemoveRealmRoleAssignment(ctx context.Context, params RemoveRealmRoleAssignmentParams) (*RemoveRealmRoleAssignmentResult, error)
}

type ListOrgRolesParams struct{}

type ListOrgRolesResult struct {
	// Roles are the roles.
	Roles []OrgRole
}

type ListUsersParams struct {
	// Filter filters the results.
	Filter UserFilter
}

type ListUsersResult struct {
	// Users are the users. If a filter was used, these
	// users are the subset that passed the filter.
	Users []User
}

type UpdateUserRoleParams struct {
	// ID identifies the user to update the role of. Required.
	ID string

	// RoleID identifies the organization role to grant to the user. Required.
	RoleID string
}

type UpdateUserRoleResult struct{}

type DeleteUserParams struct {
	// ID identifies the user to delete. Required.
	ID string
}

type DeleteUserResult struct{}

type CreateUserInvitationParams struct {
	// Email is the email address of the user to invite. Required.
	Email string

	// RoleID identifies the organization role to grant to the user. Required.
	RoleID string

	// TTL indicates the new time-to-live for the user invitation, relative
	// to the current time. Defaults to 24 hours if unset. Optional.
	TTL *time.Duration
}

type CreateUserInvitationResult struct {
	// UserInvitation is the newly created user invitation.
	UserInvitation UserInvitation
}

type RenewUserInvitationParams struct {
	// ID identifies the user invitation to renew. Required.
	ID string

	// TTL indicates the new time-to-live for the user invitation, relative
	// to the current time. Defaults to 24 hours if unset. Optional.
	TTL *time.Duration
}

type RenewUserInvitationResult struct {
	// UserInvitation is the user invitation that was renewed.
	UserInvitation UserInvitation
}

type DeleteUserInvitationParams struct {
	// ID identifies the user invitation to delete. Required.
	ID string
}

type DeleteUserInvitationResult struct{}

type ListUserInvitationsParams struct{}

type ListUserInvitationsResult struct {
	// ListUserInvitations are the user invitations.
	UserInvitations []UserInvitation
}

type CreateServiceAccountParams struct {
	// Name is the name of the new service account. It must be unique to
	// the organization. Required.
	Name string

	// RoleID identifies the organization role to grant to the service account.
	// Defaults to the admin role if unset. Optional.
	RoleID *string

	// Description is the service account description. Optional.
	Description *string
}

type CreateServiceAccountResult struct {
	// ServiceAccount is the newly created service account.
	ServiceAccount ServiceAccount
}

type ListServiceAccountsParams struct {
	// Filter filters the results.
	Filter ServiceAccountFilter
}

type ListServiceAccountsResult struct {
	// ServiceAccounts is the newly created service account.
	ServiceAccounts []ServiceAccount
}

type GetServiceAccountInfoParams struct {
	// ID identifies the service account to return info for. Required.
	ID string
}

type GetServiceAccountInfoResult struct {
	// ServiceAccount is the service account.
	ServiceAccount ServiceAccount

	// Keys are the service account keys for the service account.
	Keys []ServiceAccountKey
}

type UpdateServiceAccountRoleParams struct {
	// ID identifies the service account to update. Required.
	ID string

	// RoleID identifies the organization role to grant to the service account.
	// Required.
	RoleID string
}

type UpdateServiceAccountRoleResult struct {
	// ServiceAccount is the updated service account.
	ServiceAccount ServiceAccount
}

type DeleteServiceAccountParams struct {
	// ID identifies the service account to delete. Required.
	ID string

	// Force, if true, deletes the service account regardless of state.
	// Optional.
	Force *bool
}

type DeleteServiceAccountResult struct{}

type CreateServiceAccountKeyParams struct {
	// ServiceAccountID identifies the service account the new key belongs to.
	ServiceAccountID string

	// PublicKey is the public key for the service account key. Currently only
	// ed25519.PublicKey keys are supported. Required.
	PublicKey any
}

type CreateServiceAccountKeyResult struct {
	// ServiceAccountKey is the newly created service account key.
	ServiceAccountKey ServiceAccountKey
}

type DeleteServiceAccountKeyParams struct {
	// ID identifies the service account key to delete. Required.
	ID string

	// Force, if true, deletes the service account key regardless of state.
	// Optional.
	Force *bool
}

type DeleteServiceAccountKeyResult struct{}

type UpdateServiceAccountKeyStatusParams struct {
	// ID identifies the service account key to delete. Required.
	ID string

	// IsActive is the updated "active" state of the service account key.
	// Required.
	IsActive bool
}

type UpdateServiceAccountKeyStatusResult struct {
	// ServiceAccountKey is the updated service account key information.
	ServiceAccountKey ServiceAccountKey
}

type AssignUserRealmRoleParams struct {
	// UserID identifies the user to assign the realm role to. Required.
	UserID string

	// RealmID identifies the realm the role applies to. Required.
	RealmID string

	// RoleID identifies the realm role to grant. Required.
	RoleID string
}

type AssignServiceAccountRealmRoleParams struct {
	// ServiceAccountID identifies the service account to assign the realm role to. Required.
	ServiceAccountID string

	// RealmID identifies the realm the role applies to. Required.
	RealmID string

	// RoleID identifies the realm role to grant. Required.
	RoleID string
}

type AssignUserRealmRoleResult struct {
	// AssignmentID identifies the created realm role assignment.
	AssignmentID string

	// CreatedAt is when the assignment was created.
	CreatedAt time.Time
}

type AssignServiceAccountRealmRoleResult struct {
	// AssignmentID identifies the created realm role assignment.
	AssignmentID string

	// CreatedAt is when the assignment was created.
	CreatedAt time.Time
}

type RemoveRealmRoleAssignmentParams struct {
	// AssignmentID identifies the realm role assignment to remove. Required.
	AssignmentID string
}

type RemoveRealmRoleAssignmentResult struct{}

type ListUserRealmRoleAssignmentsParams struct {
	// UserID identifies the user whose realm role assignments are listed. Required.
	UserID string
}

type ListServiceAccountRealmRoleAssignmentsParams struct {
	// ServiceAccountID identifies the service account whose realm role assignments are listed. Required.
	ServiceAccountID string
}

type ListAssignmentIDRealmRoleAssignmentsParams struct {
	// AssignmentID identifies the assignment unique id whose realm role assignments are listed. Required.
	AssignmentID string
}

type ListUserRealmRoleAssignmentsResult struct {
	// Assignments are the realm role assignments for the user.
	Assignments []RoleAssignment
}

type ListServiceAccountRealmRoleAssignmentsResult struct {
	// Assignments are the realm role assignments for the service account.
	Assignments []RoleAssignment
}

type ListAssignmentIDRealmRoleAssignmentsResult struct {
	// Assignments are the realm role assignments for the assignment ID.
	Assignments []RoleAssignment
}

type RoleAssignment struct {
	// ID identifies the role assignment.
	ID string

	// Principal identifies the principal that received the role assignment.
	Principal RoleAssignmentPrincipal

	// RealmRole describes the realm role granted by the assignment.
	RealmRole RealmRoleAssignment

	// CreatedAt is when the role assignment was created.
	CreatedAt time.Time
}

type RealmRoleAssignment struct {
	// RealmID identifies the realm the role applies to.
	RealmID string

	// RoleID identifies the realm role granted.
	RoleID string
}

type RoleAssignmentPrincipal interface {
	roleAssignmentPrincipal()
}

type UserRoleAssignmentPrincipal struct {
	// UserID identifies the user principal on the assignment.
	UserID string
}

func (UserRoleAssignmentPrincipal) roleAssignmentPrincipal() {}

type ServiceAccountRoleAssignmentPrincipal struct {
	// ServiceAccountID identifies the service account principal on the assignment.
	ServiceAccountID string
}

func (ServiceAccountRoleAssignmentPrincipal) roleAssignmentPrincipal() {}

type OrgRole struct {
	// ID identifies the org role.
	ID string

	// Name is a human readable name for the role.
	Name string
}

type User struct {
	// ID identifies the user.
	ID string

	// Email is the user's email address.
	Email string

	// Name is the user's name.
	Name string

	// Role is the organization role assigned to the user.
	Role OrgRole

	// SSOProvider identifies the SSO provider for the user.
	SSOProvider SSOProvider
}

type UserInvitation struct {
	// ID identifies the user invitation.
	ID string

	// CreatedAt is when the user invitation was created.
	CreatedAt time.Time

	// ExpiresAt is when the user invitation expires
	ExpiresAt time.Time

	// Email is the invited user's email address.
	Email string

	// Role is the organization role to assign the user.
	Role OrgRole

	// Code is the invitation code used during login to accept the invitation.
	Code string

	// CreatedBy identifies the user who created the invitation.
	CreatedBy string

	// URL is a URL that can be used to login and accept the invitation.
	URL string
}

type ServiceAccountKey struct {
	// ID identifies the service account key.
	ID string

	// ServiceAccountID identifies the service account the key belongs to.
	ServiceAccountID string

	// IsActive indicates whether the service account key is active.
	IsActive bool

	// PublicKey is the public key component of the service account key.
	PublicKey any

	// CreatedAt is when the service account key was created.
	CreatedAt time.Time
}

type ServiceAccountFilter struct {
	// Name filters the service accounts to those with the given name. Optional.
	Name *string
}

type ServiceAccount struct {
	// ID identifies the service account.
	ID string

	// Name is the human-friendly name given to the service account.
	Name string

	// Description optionally describes the service account.
	Description string

	// RoleID identifies the organization role granted to the service account.
	RoleID string

	// CreatedAt is when the service account was created.
	CreatedAt time.Time

	// CreatedBy describes which entity created the service account.
	CreatedBy CreatedBy
}

type CreatedBy struct {
	// ID identifies the user
	ID string

	// Email is the user's email address.
	Email string
}

type UserFilter struct {
	// Email filters the users by the given email address.
	Email *string
}

type SSOProvider string

const (
	// SSOProviderEnterprise indicates that the user signs on using an SSO
	// provider configured for the organization.
	SSOProviderEnterprise = SSOProvider("enterprise")

	// SSOProviderGoogle indicates that the user signs on Google SSO.
	SSOProviderGoogle = SSOProvider("google")
)

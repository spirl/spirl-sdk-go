package accesssdk

import (
	"context"
	"time"

	"google.golang.org/protobuf/types/known/anypb"

	"github.com/spirl/spirl-sdk-go/spirlsdk"
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

	// ListAuditLogs returns audit logs for the organization.
	ListAuditLogs(ctx context.Context, params ListAuditLogsParams) (*ListAuditLogsResult, error)
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

type ListAuditLogsParams struct {
	// Page provides parameters for paging the list.
	Page spirlsdk.PageParams

	// Filter filters the results.
	Filter AuditLogFilter
}

type ListAuditLogsResult struct {
	// Page contains required information for listing the next page.
	Page spirlsdk.PageResult

	// AuditLogs are the available audit logs. If a filter was used, these
	// logs are the subset that passed the filter.
	AuditLogs []AuditLog
}

type AuditLogFilter struct {
	// TrustDomainID filters audit logs to those with the the given trust
	// domain. Optional.
	TrustDomainID *string

	// TrustDomainName filters audit logs to those with the given trust domain
	// name. Optional.
	TrustDomainName *string

	// RequestID filters audit logs to those with the given request ID.
	// Optional.
	RequestID *string

	// Source filters audit logs to those with the given source. Optional.
	Source *AuditLogSource

	// Service filters audit logs to those with the given service. Optional.
	Service *string

	// Method filters audit logs to those with the given method. Optional.
	Method *string

	// ActorID filters audit logs to those with the given actor ID. Optional.
	ActorID *string

	// ActorType filters audit logs to those with the given actor type. Optional.
	ActorType *AuditLogActorType

	// ActorEmail filters audit logs to those with the given actor email. Optional.
	ActorEmail *string

	// ActorName filters audit logs to those with the given actor name. Optional.
	ActorName *string

	// ActorKeyID filters audit logs to those with the given actor key ID. Optional.
	ActorKeyID *string

	// StatusCode filters audit logs to those with the given status code. Optional.
	StatusCode *int32

	// StartTime filters logs to those logged at or after the given time. If unset
	// the current time is used. Optional.
	StartTime *time.Time

	// EndTime filters logs to those logged at or before the given time. If unset
	// the current time minus 24 hours is used. Optional.
	EndTime *time.Time
}

type AuditLogSource string

const (
	// AuditLogSourceAutomated indicates that the audit log entry was the
	// result of an automated action.
	AuditLogSourceAutomated = AuditLogSource("automated")

	// AuditLogSourceUser indicates that the audit log entry was the result
	// of a user-initiated action.
	AuditLogSourceUser = AuditLogSource("user")
)

type AuditLogActorType string

const (
	// AuditLogActorTypeUser indicates that a user performed the action
	// that was audited.
	AuditLogActorTypeUser = AuditLogActorType("user")

	// AuditLogActorTypeUser indicates that a service account performed the
	// action that was audited.
	AuditLogActorTypeServiceAccount = AuditLogActorType("serviceAccount")

	// AuditLogActorTypeAdmin indicates that a SPIRL admin performed the
	// action that was audited.
	AuditLogActorTypeAdmin = AuditLogActorType("admin")
)

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

type AuditLog struct {
	// Actor is the persona who took action.
	Actor AuditActor

	// Timestamp is when the action occurred.
	Timestamp time.Time

	// TrustDomain identifies which trust domain the action occurred in.
	TrustDomain TrustDomain

	// Source identifies the source of the action (e.g. user initiated or not)
	Source AuditLogSource

	// RequestID identifies the
	RequestID string

	// Request contain details of the request that initiated the action.
	Request AuditedRequest

	// StatusCode is the status of the request. It may not be available if
	// the request was not completed.
	StatusCode *int32
}

type AuditedRequest struct {
	// Service is the request service.
	Service string

	// Method is the request method.
	Method string

	// Message is the request payload.
	Message *anypb.Any
}

type AuditActor interface {
	auditActor()
}

type UserActor struct {
	// ID identifies the user who performed the action.
	ID string

	// Email is the email address of the user who performed the action.
	Email string
}

func (UserActor) auditActor() {}

type ServiceAccountActor struct {
	// ID identifies the service account who performed the action.
	ID string

	// Name is the name service account who performed the action.
	Name string

	// KeyID identifies which service account key was used to authenticate
	// the service account who performed the action.
	KeyID string
}

func (ServiceAccountActor) auditActor() {}

type SPIRLAdminActor struct {
	// ID identifies the SPIRL admin who performed the action.
	ID string

	// Email identifies the email address of the SPIRL admin who performed
	// the action.
	Email string
}

func (SPIRLAdminActor) auditActor() {}

type TrustDomain struct {
	// ID identifies the trust domain the action took place in.
	ID string

	// Name is the name of the trust domain the action took place in.
	Name string
}

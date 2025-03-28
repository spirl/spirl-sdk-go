package cicdsdk

import "context"

type API interface {
	CreateCICDProfile(ctx context.Context, params CreateCICDProfileParams) (*CreateCICDProfileResult, error)
	ListCICDProfiles(ctx context.Context, params ListCICDProfilesParams) (*ListCICDProfilesResult, error)
	GetCICDProfileInfo(ctx context.Context, params GetCICDProfileInfoParams) (*GetCICDProfileInfoResult, error)
	DeleteCICDProfile(ctx context.Context, params DeleteCICDProfileParams) (*DeleteCICDProfileResult, error)
}

type CreateCICDProfileParams struct {
	// Name is the name of the CI/CD profile. Required.
	Name string

	// Type is the type of the CI/CD profile. Required.
	Type CICDType

	// Issuer is the token issuer. If unset, a default value will be provided
	// based on the profile type. Optional.
	Issuer *string

	// JWKSURL is the URL for the JWKS used to verify tokens. If unset, a
	// default URL is provided based on the profile type. Optional.
	JWKSURL *string

	// Claims are additional allowed claims on the token beyond what is already
	// allowed based on the profile type. Optional.
	Claims *[]string
}

type CreateCICDProfileResult struct {
	// CICDProfile is the newly created CI/CD profile.
	CICDProfile CICDProfile
}

type ListCICDProfilesParams struct{}

type ListCICDProfilesResult struct {
	// CICDProfiles are the CI/CD profiles.
	CICDProfiles []CICDProfile
}

type GetCICDProfileInfoParams struct {
	// Name identifies the name of the CI/CD profile to get information for.
	Name string
}

type GetCICDProfileInfoResult struct {
	// CICDProfile is the CI/CD profile information.
	CICDProfile CICDProfile
}

type DeleteCICDProfileParams struct {
	// ID identifies the CI/CD profile to delete.
	ID string
}

type DeleteCICDProfileResult struct{}

type CICDType string

const (
	// CICDTypeJenkins is a profile for use with Jenkins.
	CICDTypeJenkins = CICDType("jenkins")

	// CICDTypeGithubSAAS is a profile for use with Github SaaS.
	CICDTypeGithubSAAS = CICDType("github-saas")

	// CICDTypeGithubSelfHosted is a profile for use self-hosted Github.
	CICDTypeGithubSelfHosted = CICDType("github-self-hosted")

	// CICDTypeGithubHybrid is a profile for use with Github SaaS with
	// self-hosted runners.
	CICDTypeGithubHybrid = CICDType("github-hybrid")

	// CICDTypeGitlabSAAS is a profile for use with Gitlab SaaS.
	CICDTypeGitlabSAAS = CICDType("gitlab-saas")

	// CICDTypeGitlabSelfHosted is a profile for use with self-hosted Gitlab.
	CICDTypeGitlabSelfHosted = CICDType("gitlab-self-hosted")

	// CICDTypeGitlabHybrid is a profile for use with Gitlab SaaS with
	// self-hosted runners.
	CICDTypeGitlabHybrid = CICDType("gitlab-hybrid")
)

type CICDProfile struct {
	// ID identifies the CI/CD profile.
	ID string

	// Type is the CI/CD profile type.
	Type CICDType

	// Name is the human-friendly name.
	Name string

	// Issuer is the CI/CD token issuer.
	Issuer string

	// CreatedBy identifies the user who created the CI/CD profile. Only one
	// of CreatedBy and CreatedBySA will be set.
	CreatedBy string

	// CreatedBy identifies the service account who created the CI/CD profile.
	// Only one of CreatedBy and CreatedBySA will be set.
	CreatedBySA string

	// JWKSURL is the URL for the JWKS used to verify tokens.
	JWKSURL string

	// Claims are additional allowed claims on the token beyond what is already
	// allowed based on the profile type.
	Claims []string
}

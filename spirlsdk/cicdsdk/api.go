package cicdsdk

import "context"

type API interface {
	CreateCICDProfile(ctx context.Context, params CreateCICDProfileParams) (*CreateCICDProfileResult, error)
	ListCICDProfiles(ctx context.Context, params ListCICDProfilesParams) (*ListCICDProfilesResult, error)
	DeleteCICDProfile(ctx context.Context, params DeleteCICDProfileParams) (*DeleteCICDProfileResult, error)
}

type CreateCICDProfileParams struct {
	// Name is the name of the CI/CD profile. Required.
	Name string

	// Issuer is the token issuer. If unset, a default value will be provided
	// based on the profile type. Optional.
	Issuer *string

	// JWKSURL is the URL for the JWKS used to verify tokens. If unset, a
	// default URL is provided based on the profile type. Optional.
	JWKSURL *string
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

type DeleteCICDProfileParams struct {
	// ID identifies the CI/CD profile to delete.
	ID string
}

type DeleteCICDProfileResult struct{}

type CICDProfile struct {
	// ID identifies the CI/CD profile.
	ID string

	// Name is the human-friendly name.
	Name string

	// Issuer is the CI/CD token issuer.
	Issuer string

	// JWKSURL is the URL for the JWKS used to verify tokens.
	JWKSURL string
}

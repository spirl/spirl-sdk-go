package oauth2

import "context"

type (
	Option    = func(*config)
	OrgPicker = func(ctx context.Context, orgNames []string) (string, error)
)

type config struct {
	orgName   string
	hint      string
	orgPicker OrgPicker
}

func WithOrgName(orgName string) Option {
	return func(c *config) {
		c.orgName = orgName
	}
}

func WithHint(hint string) Option {
	return func(c *config) {
		c.hint = hint
	}
}

func WithOrgPicker(orgPicker OrgPicker) Option {
	return func(c *config) {
		c.orgPicker = orgPicker
	}
}

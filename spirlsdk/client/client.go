package client

import (
	"context"
	"log/slog"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/spirl/spirl-sdk-go/spirlsdk/accesssdk"
	"github.com/spirl/spirl-sdk-go/spirlsdk/auth"
	"github.com/spirl/spirl-sdk-go/spirlsdk/cicdsdk"
	"github.com/spirl/spirl-sdk-go/spirlsdk/clustersdk"
	"github.com/spirl/spirl-sdk-go/spirlsdk/devidentitysdk"
	"github.com/spirl/spirl-sdk-go/spirlsdk/federationsdk"
	"github.com/spirl/spirl-sdk-go/spirlsdk/internal/grpcproxy"
	"github.com/spirl/spirl-sdk-go/spirlsdk/internal/options"
	"github.com/spirl/spirl-sdk-go/spirlsdk/providerattestationsdk"
	"github.com/spirl/spirl-sdk-go/spirlsdk/trustdomainsdk"
)

const (
	defaultEndpoint = "api.spirl.com:443"
)

type Client struct {
	access              accesssdk.API
	cicd                cicdsdk.API
	cluster             clustersdk.API
	devIdentity         devidentitysdk.API
	federation          federationsdk.API
	providerAttestation providerattestationsdk.API
	trustDomain         trustdomainsdk.API

	authInterceptor *authInterceptor
	conn            *grpc.ClientConn
}

func New(auth auth.Authenticator, opts ...Option) (*Client, error) {
	var cfg config
	options.Apply(&cfg, opts,
		WithLogger(slog.Default()),
		WithEndpoint(defaultEndpoint),
	)

	authInterceptor := newAuthInterceptor(cfg.log, auth, cfg.tokenStore)

	dialOptions := []grpc.DialOption{
		grpc.WithTransportCredentials(credentials.NewTLS(nil)),
		grpc.WithUnaryInterceptor(authInterceptor.interceptUnary),
	}

	target := cfg.endpoint
	if cfg.endpointProxy != "" {
		proxyOption, err := grpcproxy.HTTPConnectDialOption(cfg.endpointProxy)
		if err != nil {
			return nil, err
		}
		target, err = grpcproxy.HTTPConnectTarget(cfg.endpoint)
		if err != nil {
			return nil, err
		}
		dialOptions = append(dialOptions, proxyOption)
	}

	conn, err := grpc.NewClient(target, dialOptions...)
	if err != nil {
		return nil, err
	}

	return &Client{
		access:              makeAccessAPI(conn),
		cicd:                makeCICDAPI(conn),
		cluster:             makeClusterAPI(conn),
		devIdentity:         makeDevIdentityAPI(conn),
		federation:          makeFederationAPI(conn),
		providerAttestation: makeProviderattestationAPI(conn),
		trustDomain:         makeTrustDomainAPI(conn),

		authInterceptor: authInterceptor,
		conn:            conn,
	}, nil
}

// Authenticate authenticates using the authenticator the client was
// initialized with. The client normally authenticates on-demand.
func (c *Client) Authenticate(ctx context.Context) error {
	_, err := c.authInterceptor.refreshToken(ctx, c.conn, true)
	return err
}

// Access returns the Access SDK API interface.
func (c *Client) Access() accesssdk.API {
	return c.access
}

// ProviderAttestation returns the ProviderAttestation SDK API interface.
func (c *Client) ProviderAttestation() providerattestationsdk.API {
	return c.providerAttestation
}

// CICD returns the CICD SDK API interface.
func (c *Client) CICD() cicdsdk.API {
	return c.cicd
}

// Cluster returns the Cluster SDK API interface.
func (c *Client) Cluster() clustersdk.API {
	return c.cluster
}

// DevIdentity returns the Developer Identity SDK API interface.
func (c *Client) DevIdentity() devidentitysdk.API {
	return c.devIdentity
}

// Federation returns the Federation SDK API interface.
func (c *Client) Federation() federationsdk.API {
	return c.federation
}

// TrustDomain returns the TrustDomain SDK API interface.
func (c *Client) TrustDomain() trustdomainsdk.API {
	return c.trustDomain
}

// Close closes the client and releases resources.
func (c *Client) Close() error {
	return c.conn.Close()
}

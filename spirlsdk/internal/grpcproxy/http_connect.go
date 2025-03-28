package grpcproxy

import (
	"context"
	"fmt"
	"net"
	"net/url"

	"google.golang.org/grpc"
	"google.golang.org/grpc/resolver"
)

// HTTPConnectDialOption returns a DialOption that specifies the HTTP CONNECT
// proxy to use for the transport. If the proxy string is invalid, an error is
// returned.
func HTTPConnectDialOption(proxy string) (grpc.DialOption, error) {
	proxyDialer, err := newDialer(proxy)
	if err != nil {
		return nil, fmt.Errorf("failed to create proxy dialer: %w", err)
	}

	dialOption := grpc.WithContextDialer(func(ctx context.Context, s string) (net.Conn, error) {
		return proxyDialer.DialContext(ctx, "tcp", s)
	})

	return dialOption, nil
}

// HTTPConnectTarget returns the target string to use when calling
// grpc.NewClient and a proxy dialer will be programmatically supplied via the
// DialOption returned by HTTPConnectDialOption. When the dns resolver is being
// used, the target will be converted to the passthrough resolver so the proxy
// sees a request for "CONNECT target:port" which may drive authorization rules.
func HTTPConnectTarget(target string) (string, error) {
	url, err := url.Parse(target)
	if err != nil {
		return "", fmt.Errorf("failed to parse target URL: %w", err)
	}

	rb := resolver.Get(url.Scheme)
	if rb == nil {
		// Target is in the format of "host:port"
		return "passthrough:///" + url.Scheme + ":" + url.Opaque, nil
	}

	switch rb.Scheme() {
	case "passthrough", "dns":
		return "passthrough://" + url.Path, nil
	default:
		return target, nil
	}
}

package client

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// Metadata keys for calling client (x-spirl-client, x-spirl-client-version).
// Must match common/middleware so server audit log attribution works.
const (
	metadataKeyClient        = "x-spirl-client"
	metadataKeyClientVersion = "x-spirl-client-version"
)

// clientUnaryClientInterceptor returns an interceptor that adds x-spirl-client and
// x-spirl-client-version to outgoing metadata for audit log attribution.
func clientUnaryClientInterceptor(client, clientVersion string) grpc.UnaryClientInterceptor {
	return func(
		ctx context.Context,
		method string,
		req, reply any,
		cc *grpc.ClientConn,
		invoker grpc.UnaryInvoker,
		opts ...grpc.CallOption,
	) error {
		return invoker(addClientToMetadata(ctx, client, clientVersion), method, req, reply, cc, opts...)
	}
}

// clientStreamClientInterceptor returns an interceptor that adds x-spirl-client and
// x-spirl-client-version to outgoing metadata for audit log attribution.
func clientStreamClientInterceptor(client, clientVersion string) grpc.StreamClientInterceptor {
	return func(
		ctx context.Context,
		desc *grpc.StreamDesc,
		cc *grpc.ClientConn,
		method string,
		streamer grpc.Streamer,
		opts ...grpc.CallOption,
	) (grpc.ClientStream, error) {
		return streamer(addClientToMetadata(ctx, client, clientVersion), desc, cc, method, opts...)
	}
}

func addClientToMetadata(ctx context.Context, client, clientVersion string) context.Context {
	md, ok := metadata.FromOutgoingContext(ctx)
	if !ok {
		md = metadata.New(nil)
	} else {
		md = md.Copy()
	}
	if client != "" {
		md.Set(metadataKeyClient, client)
	}
	if clientVersion != "" {
		md.Set(metadataKeyClientVersion, clientVersion)
	}
	return metadata.NewOutgoingContext(ctx, md)
}

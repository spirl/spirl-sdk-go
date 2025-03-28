[![GoDoc](https://pkg.dev.org/github.com/spirl/spirl-sdk-go?status.svg)](https://pkg.dev.org/github.com/spirl/spirl-sdk-go)

# SPIRL Go SDK

This repository contains the [SPIRL](spirl.com) SDK for the [Go](golang.org)
programming language.

## Contributions

This repository is "source available". Outside contributions are not accepted.

To report a bug or make a feature request, please file an issue.

## Quick Start

### Installation

To add this module to your project:

```shell
go get github.com/spirl/spirl-sdk-go@latest
```

### Usage

To use the SDK, you must first initialize a client using the `github.com/spirl/spirl-sdk-go/spirlsdk/client` package.

```go
c, err := client.New(auth) // see "Authentication" below
if err != nil {
    // handle error
}
```

Use accessors to get methods for the various APIs. For example, to list trust
domains in your SPIRL account:

```go
result, err := c.TrustDomain().ListTrustDomains(ctx, trustdomainsdk.ListTrustDomainsParams{})
if err != nil {
    // handle error
}
```

The client should be closed when no longer needed:

```go
if err := c.Close(); err != nil {
    // handle error
}
```
### Authentication

The SDK authenticates to SPIRL on-demand. The SDK client is configured with an
authenticator for the purpose of obtaining an authentication token. The SDK
client does not persist authentication tokens by default, implying that newly
initialized SDK clients always need to authenticate. Token persistence can
be configured via the `client.WithTokenStore` option.

The SDK supports authenticating using one of two methods:

1. OAuth2 authentication to an Identity Provider
2. Service Account authentication

#### OAuth2 Authentication

See the [example](./examples/auth-with-oauth2) for a demonstration on
authenticating to SPIRL using OAuth2.

SDK callers are responsible for opening the browser for the user to complete
the login flow. The pairing code should also be conveyed to the user so they
can assert they are logging into the correct session.

#### Service Account Authentication

A service account is an entity in your SPIRL account provisioned with a
specific role. Before you can authenticate with a service account, you need to
create the service account and generate a key for it.

To create a service account:

```shell
spirlctl iam service-account create <name> --role-name <role>
```

For example, to create a service account `sdk-example` with the _admin_ role:

```shell
spirlctl iam service-account create sdk-example --role-name admin
```

Then you can generate a key for the service account:

```shell
spirlctl iam service-account key add --service-account sdk-example
```

The output of these commands will contain the service account key ID as well as
the service account key. See the
[example](./examples/auth-with-service-account) for a demonstration on
authenticating to SPIRL using these values.

## Examples

Browse the [examples](./examples) folder for help doing a few common
operations.

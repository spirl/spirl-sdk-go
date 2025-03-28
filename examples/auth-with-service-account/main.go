package main

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/spirl/spirl-sdk-go/spirlsdk/auth"
	"github.com/spirl/spirl-sdk-go/spirlsdk/auth/serviceaccount"
	"github.com/spirl/spirl-sdk-go/spirlsdk/client"
	"github.com/spirl/spirl-sdk-go/spirlsdk/trustdomainsdk"
)

func main() {
	ctx := context.Background()

	// TODO: replace these values. For example, they could be loaded from
	// disk.
	serviceAccountKeyID := ""
	serviceAccountKeyPEM := ""

	if err := run(ctx, serviceAccountKeyID, serviceAccountKeyPEM); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context, serviceAccountKeyID, serviceAccountKeyPEM string) error {
	serviceAccountKey, err := parseServiceAccountKey(serviceAccountKeyPEM)
	if err != nil {
		return fmt.Errorf("failed to parse service account key: %v", err)
	}

	// Creates a client that authenticates with SPIRL using Google OAuth.
	// The authentication token is stored at $HOME/.spirl-example-token.
	key := serviceaccount.Key{
		ID:         serviceAccountKeyID,
		PrivateKey: serviceAccountKey,
	}
	c, err := client.New(serviceaccount.New(key),
		client.WithTokenStore(auth.TokenFile(os.ExpandEnv("$HOME/.spirl-example-token"))),
	)
	if err != nil {
		return fmt.Errorf("failed to initialize SDK client: %v", err)
	}
	defer c.Close()

	// Obtain a list of trust domains and print out each name.
	result, err := c.TrustDomain().ListTrustDomains(ctx, trustdomainsdk.ListTrustDomainsParams{})
	if err != nil {
		return fmt.Errorf("failed to list trust domains: %v", err)
	}
	for _, trustDomain := range result.TrustDomains {
		fmt.Println(trustDomain.Name)
	}

	return nil
}

func parseServiceAccountKey(serviceAccountKeyPEM string) (crypto.Signer, error) {
	pemBlock, _ := pem.Decode([]byte(serviceAccountKeyPEM))
	if pemBlock == nil {
		return nil, errors.New("invalid service account key PEM")
	}

	serviceAccountKeyRaw, err := x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse service account key: %w", err)
	}

	serviceAccountKey, ok := serviceAccountKeyRaw.(crypto.Signer)
	if !ok {
		// This is purely defensive
		return nil, errors.New("service account key is not a signer")
	}
	return serviceAccountKey, nil
}

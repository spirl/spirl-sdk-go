package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/skratchdot/open-golang/open"

	"github.com/spirl/spirl-sdk-go/spirlsdk/auth"
	"github.com/spirl/spirl-sdk-go/spirlsdk/auth/oauth2"
	"github.com/spirl/spirl-sdk-go/spirlsdk/client"
	"github.com/spirl/spirl-sdk-go/spirlsdk/trustdomainsdk"
)

func main() {
	ctx := context.Background()
	if err := run(ctx); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context) error {
	// Creates a client that authenticates with SPIRL using Google OAuth. The
	// login handler passed to the SDK opens the login URL in the browser. The
	// authentication token is stored at $HOME/.spirl-example-token.
	c, err := client.New(oauth2.New(handleLogin),
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

func handleLogin(_ context.Context, loginInfo oauth2.LoginInfo) error {
	fmt.Printf(`Please compare the following pairing code to the one presented by the browser:
	%s

The browser will now be opened to complete the login.
`, loginInfo.PairingCode)
	return open.Run(loginInfo.URL)
}

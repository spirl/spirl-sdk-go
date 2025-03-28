package serviceaccount

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/spirl/spirl-sdk-go/spirlsdk/internal"
	"github.com/spirl/spirl-sdk-go/spirlsdk/internal/protos/api/v1/sessionapi"
)

const (
	proofNonceSize = 32
)

var signatureOptions = &ed25519.Options{
	Hash:    crypto.SHA512, // key proof hash is pre-computed
	Context: "service-account-key-proof",
}

// Key is the service account key.
type Key struct {
	// ID is the service account key ID.
	ID string

	// PrivateKey is the private key for the service account key. Only
	// ed25519 private keys are currently supported.
	PrivateKey crypto.Signer
}

// GetKey implements KeySource and returns the key itself.
func (k Key) GetKey() (*Key, error) {
	return &k, nil
}

type KeySource interface {
	// GetKey returns the service account key.
	GetKey() (*Key, error)
}

type Auth struct {
	internal.Impl `exhaustruct:"optional"`

	keySource KeySource
}

func New(keySource KeySource) *Auth {
	return &Auth{keySource: keySource}
}

func (a *Auth) Authenticate(ctx context.Context, conn grpc.ClientConnInterface) (string, error) {
	// Ensure the stream is closed on return.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	stream, err := sessionapi.NewAPIClient(conn).AuthenticateServiceAccount(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to open login stream: %v", err)
	}

	saKey, err := a.keySource.GetKey()
	if err != nil {
		return "", fmt.Errorf("failed to load service account key from source: %v", err)
	}

	proofKey, ok := saKey.PrivateKey.(ed25519.PrivateKey)
	if !ok {
		return "", fmt.Errorf("expected key type %T but got %T", proofKey, saKey.PrivateKey)
	}

	if err := stream.Send(&sessionapi.AuthenticateServiceAccountRequest{
		Request: &sessionapi.AuthenticateServiceAccountRequest_Login{
			Login: &sessionapi.ServiceAccountKeyLogin{
				KeyId: saKey.ID,
			},
		},
	}); err != nil {
		return "", fmt.Errorf("failed to send service account login request: %v", err)
	}

	resp, err := stream.Recv()
	if err != nil {
		return "", fmt.Errorf("failed receiving service account challenge response: %v", err)
	}

	challengeResp := resp.GetChallenge()
	if challengeResp == nil {
		return "", fmt.Errorf("expected challenge stream response type %T but got %T", challengeResp, resp.Response)
	}

	clientNonce, signature, err := signProof(proofKey, challengeResp.ServerNonce)
	if err != nil {
		return "", fmt.Errorf("failed to create key proof: %v", err)
	}

	if err := stream.Send(&sessionapi.AuthenticateServiceAccountRequest{
		Request: &sessionapi.AuthenticateServiceAccountRequest_Authorization{
			Authorization: &sessionapi.ServiceAccountKeyAuthorization{
				ServiceAccountKeyProof: &sessionapi.ServiceAccountKeyProof{
					Signature: signature,
					Nonce:     clientNonce,
				},
			},
		},
	}); err != nil {
		return "", fmt.Errorf("failed to send service account login request: %v", err)
	}

	resp, err = stream.Recv()
	if err != nil {
		if status.Code(err) == codes.DeadlineExceeded {
			return "", errors.New("session timed out")
		}
		return "", fmt.Errorf("failed receiving finish login stream response: %v", err)
	}

	sessionResp := resp.GetSession()
	switch {
	case sessionResp == nil:
		return "", fmt.Errorf("expected login stream response type %T but got %T", sessionResp, resp.Response)
	case sessionResp.Token == "":
		return "", errors.New("finish login response missing token")
	}

	return sessionResp.Token, nil
}

func signProof(privateKey ed25519.PrivateKey, serverNonce []byte) ([]byte, []byte, error) {
	if len(privateKey) == 0 {
		return nil, nil, errors.New("invalid private key")
	}
	if err := checkNonceSize(serverNonce); err != nil {
		return nil, nil, fmt.Errorf("invalid server nonce: %v", err)
	}

	clientNonce, err := newProofNonce()
	if err != nil {
		return nil, nil, err
	}

	proofHash := computeProofHash(clientNonce, serverNonce)

	signature, err := privateKey.Sign(rand.Reader, proofHash, signatureOptions)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign key proof: %v", err)
	}
	return clientNonce, signature, nil
}

func newProofNonce() ([]byte, error) {
	nonce := make([]byte, proofNonceSize)
	_, err := rand.Read(nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to generate proof nonce: %v", err)
	}
	return nonce, nil
}

func checkNonceSize(nonce []byte) error {
	if len(nonce) == 0 {
		return errors.New("nonce is empty")
	}
	if len(nonce) != proofNonceSize {
		return fmt.Errorf("expected nonce length %d but got %d", proofNonceSize, len(nonce))
	}
	return nil
}

func computeProofHash(clientNonce, serverNonce []byte) []byte {
	h := sha512.New()
	_, _ = h.Write(clientNonce)
	_, _ = h.Write(serverNonce)
	return h.Sum(nil)
}

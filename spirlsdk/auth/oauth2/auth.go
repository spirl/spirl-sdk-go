package oauth2

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/spirl/spirl-sdk-go/spirlsdk/internal"
	"github.com/spirl/spirl-sdk-go/spirlsdk/internal/options"
	"github.com/spirl/spirl-sdk-go/spirlsdk/internal/protos/api/v1/sessionapi"
	"github.com/spirl/spirl-sdk-go/spirlsdk/internal/xerrors"
)

type LoginInfo struct {
	// URL is the login URL used to complete the login. The handler is in
	// charge of directing the user to this URL (e.g. opening the browser)
	URL string

	// PairingCode identifies the login attempt. Users should compare this
	// pairing code to the one shown when logging in. To facilitate this
	// comparison, the handler should provide this value to the user (e.g.
	// printing it to the terminal).
	PairingCode string
}

type LoginHandler func(ctx context.Context, loginInfo LoginInfo) error

type Auth struct {
	internal.Impl `exhaustruct:"optional"`

	loginHandler LoginHandler
	config
}

func New(loginHandler LoginHandler, opts ...Option) *Auth {
	var c config
	options.Apply(&c, opts,
		WithOrgPicker(pickNone),
	)
	return &Auth{
		loginHandler: loginHandler,
		config:       c,
	}
}

func (o *Auth) Authenticate(ctx context.Context, conn grpc.ClientConnInterface) (string, error) {
	// Ensure the stream is closed on return.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	stream, err := sessionapi.NewAPIClient(conn).Login(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to open login stream: %v", err)
	}

	if err := stream.Send(&sessionapi.LoginRequest{
		Request: &sessionapi.LoginRequest_Start{
			Start: &sessionapi.StartLoginRequest{
				OrgName:             o.orgName,
				Hint:                o.hint,
				SupportsPairingCode: true,
			},
		},
	}); err != nil {
		return "", fmt.Errorf("failed to send start login request: %v", err)
	}

	resp, err := stream.Recv()
	if err != nil {
		return "", fmt.Errorf("failed to receive start login stream response: %v", err)
	}

	startResp := resp.GetStart()
	if startResp == nil {
		return "", fmt.Errorf("expected login stream response type %T but got %T", startResp, resp.Response)
	}

	if err := o.loginHandler(ctx, LoginInfo{
		URL:         startResp.LoginUrl,
		PairingCode: startResp.PairingCode,
	}); err != nil {
		return "", fmt.Errorf("failed to handle login: %v", err)
	}

	if err := stream.Send(&sessionapi.LoginRequest{
		Request: &sessionapi.LoginRequest_Finish{
			Finish: &sessionapi.FinishLoginRequest{},
		},
	}); err != nil {
		return "", fmt.Errorf("failed to send finish login request: %v", err)
	}

	resp, err = stream.Recv()
	if err != nil {
		if status.Code(err) == codes.DeadlineExceeded {
			return "", errors.New("session timed out")
		}
		return "", fmt.Errorf("failed to receive finish login stream response: %v", err)
	}

	if chooseOrgResp := resp.GetChooseOrg(); chooseOrgResp != nil {
		orgName, err := o.orgPicker(ctx, chooseOrgResp.Orgs)
		if err != nil {
			return "", fmt.Errorf("failed to pick org: %v", err)
		}

		if err := stream.Send(&sessionapi.LoginRequest{
			Request: &sessionapi.LoginRequest_ChooseOrg{
				ChooseOrg: &sessionapi.ChooseOrgRequest{
					OrgName: orgName,
				},
			},
		}); err != nil {
			return "", fmt.Errorf("failed to send choose org request: %v", err)
		}

		resp, err = stream.Recv()
		if err != nil {
			if status.Code(err) == codes.DeadlineExceeded {
				return "", errors.New("session timed out")
			}
			return "", fmt.Errorf("failed to receive finish login stream response: %v", err)
		}
	}

	finishResp := resp.GetFinish()
	switch {
	case finishResp == nil:
		return "", fmt.Errorf("expected login stream response type %T but got %T", finishResp, resp.Response)
	case finishResp.Token == "":
		return "", errors.New("finish login response missing token")
	}

	return finishResp.Token, nil
}

func pickNone(_ context.Context, orgs []string) (string, error) {
	return "", xerrors.AmbiguousOrgError{Orgs: orgs}
}

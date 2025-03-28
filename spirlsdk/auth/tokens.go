package auth

import (
	"bufio"
	"context"
	"errors"
	"io/fs"
	"os"
	"strings"
)

// ErrNoToken is returned from token sources when there is no token available.
var ErrNoToken = errors.New("no token")

// TokenStore is used to load and store authentication tokens.
type TokenStore interface {
	// LoadToken loads the token from the store. If the store does not have
	// a token, then ErrNoToken is returned.
	LoadToken(ctx context.Context) (token string, err error)

	// SaveToken saves the given token in the store.
	SaveToken(ctx context.Context, token string) (err error)
}

// TokenFile is a token store backed by a file on disk. The value is the
// path on disk to the token file.
type TokenFile string

func (path TokenFile) LoadToken(ctx context.Context) (string, error) {
	token, err := readFirstLine(string(path))
	switch {
	case err == nil:
		if token == "" {
			return "", ErrNoToken
		}
		return token, nil
	case errors.Is(err, fs.ErrNotExist):
		return "", ErrNoToken
	default:
		return "", err
	}
}

func (path TokenFile) SaveToken(ctx context.Context, token string) (err error) {
	return writeLine(string(path), token)
}

func writeLine(path, line string) error {
	if !strings.HasSuffix(line, "\n") {
		line += "\n"
	}
	return os.WriteFile(path, []byte(line), 0o600)
}

func readFirstLine(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	scanner := bufio.NewScanner(f)
	scanner.Scan()
	return scanner.Text(), scanner.Err()
}

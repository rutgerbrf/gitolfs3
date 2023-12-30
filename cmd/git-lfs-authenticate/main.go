package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func die(msg string, args ...any) {
	fmt.Fprint(os.Stderr, "Error: ")
	fmt.Fprintf(os.Stderr, msg, args...)
	fmt.Fprint(os.Stderr, "\n")
	os.Exit(1)
}

func getGitoliteAccess(path, user, gitolitePerm string) bool {
	// gitolite access -q: returns only exit code
	cmd := exec.Command("gitolite", "access", "-q", path, user, gitolitePerm)
	err := cmd.Run()
	permGranted := err == nil
	var exitErr *exec.ExitError
	if err != nil && !errors.As(err, &exitErr) {
		die("failed to query access information")
	}
	return permGranted
}

type gitolfs3Claims struct {
	Repository string `json:"repository"`
	Permission string `json:"permission"`
}

type customClaims struct {
	Gitolfs3 gitolfs3Claims `json:"gitolfs3"`
	*jwt.RegisteredClaims
}

type authenticateResponse struct {
	Header map[string]string `json:"header"`
	// In seconds.
	ExpiresIn int64 `json:"expires_in,omitempty"`
	// expires_at (RFC3339) could also be used, but we leave it out since we
	// don't use it.
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func main() {
	// Even though not explicitly described in the Git LFS documentation, the
	// git-lfs-authenticate command is expected to either exit succesfully with
	// exit code 0 and to then print credentials in the prescribed JSON format
	// to standard out. On errors, the command should exit with a non-zero exit
	// code and print the error message in plain text to standard error. See
	// https://github.com/git-lfs/git-lfs/blob/baf40ac99850a62fe98515175d52df5c513463ec/lfshttp/ssh.go#L76-L117

	if len(os.Args) != 3 {
		die("expected 2 arguments (path, operation), got %d", len(os.Args)-1)
	}

	path := strings.TrimPrefix(strings.TrimSuffix(os.Args[1], ".git"), "/")
	operation := os.Args[2]
	if operation != "download" && operation != "upload" {
		die("expected operation to be upload or download, got %s", operation)
	}

	user := os.Getenv("GL_USER")
	if user == "" {
		die("internal error")
	}
	keyPath := os.Getenv("GITOLFS3_KEY_PATH")
	if keyPath == "" {
		die("internal error")
	}
	keyStr, err := os.ReadFile(keyPath)
	if err != nil {
		die("internal error")
	}
	keyStr = bytes.TrimSpace(keyStr)
	defer wipe(keyStr)

	if hex.DecodedLen(len(keyStr)) != ed25519.SeedSize {
		die("internal error")
	}

	seed := make([]byte, ed25519.SeedSize)
	defer wipe(seed)
	if _, err = hex.Decode(seed, keyStr); err != nil {
		die("internal error")
	}
	privateKey := ed25519.NewKeyFromSeed(seed)

	if !getGitoliteAccess(path, user, "R") {
		die("repository not found")
	}
	if operation == "upload" && !getGitoliteAccess(path, user, "W") {
		// User has read access but not write access
		die("forbidden")
	}

	expiresIn := time.Hour * 24
	claims := customClaims{
		Gitolfs3: gitolfs3Claims{
			Repository: path,
			Permission: operation,
		},
		RegisteredClaims: &jwt.RegisteredClaims{
			Subject:   user,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiresIn)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	ss, err := token.SignedString(privateKey)
	if err != nil {
		die("failed to generate token")
	}

	response := authenticateResponse{
		Header: map[string]string{
			"Authorization": "Bearer " + ss,
		},
		ExpiresIn: int64(expiresIn.Seconds()),
	}
	json.NewEncoder(os.Stdout).Encode(response)
}

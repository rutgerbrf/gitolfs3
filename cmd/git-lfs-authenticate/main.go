package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/xid"
)

type logger struct {
	reqID string
	time  time.Time
	wc    io.WriteCloser
}

func newLogger(reqID string) *logger {
	return &logger{reqID: reqID, time: time.Now()}
}

func (l *logger) writer() io.WriteCloser {
	if l.wc == nil {
		os.MkdirAll(".gitolfs3/logs/", 0o700) // Mode: drwx------
		ts := l.time.Format("2006-01-02")
		path := fmt.Sprintf(".gitolfs3/logs/gitolfs3-%s-%s.log", ts, l.reqID)
		l.wc, _ = os.Create(path)
	}
	return l.wc
}

func (l *logger) logf(msg string, args ...any) {
	fmt.Fprintf(l.writer(), msg, args...)
}

func (l *logger) close() {
	if l.wc != nil {
		l.wc.Close()
	}
}

func die(msg string, args ...any) {
	fmt.Fprint(os.Stderr, "Error: ")
	fmt.Fprintf(os.Stderr, msg, args...)
	fmt.Fprint(os.Stderr, "\n")
	os.Exit(1)
}

func dieReqID(reqID string, msg string, args ...any) {
	fmt.Fprint(os.Stderr, "Error: ")
	fmt.Fprintf(os.Stderr, msg, args...)
	fmt.Fprintf(os.Stderr, " (request ID: %s)\n", reqID)
	os.Exit(1)
}

func getGitoliteAccess(logger *logger, reqID, path, user, gitolitePerm string) bool {
	// gitolite access -q: returns only exit code
	cmd := exec.Command("gitolite", "access", "-q", path, user, gitolitePerm)
	err := cmd.Run()
	permGranted := err == nil
	var exitErr *exec.ExitError
	if err != nil && !errors.As(err, &exitErr) {
		logger.logf("Failed to query access information (%s): %s", cmd, err)
		dieReqID(reqID, "failed to query access information")
	}
	return permGranted
}

type gitolfs3Claims struct {
	Type       string `json:"type"`
	Repository string `json:"repository"`
	Permission string `json:"permission"`
}

type customClaims struct {
	Gitolfs3 gitolfs3Claims `json:"gitolfs3"`
	*jwt.RegisteredClaims
}

type authenticateResponse struct {
	// When providing href, the Git LFS client will use href as the base URL
	// instead of building the base URL using the Service Discovery mechanism.
	// It should end with /info/lfs. See
	// https://github.com/git-lfs/git-lfs/blob/baf40ac99850a62fe98515175d52df5c513463ec/docs/api/server-discovery.md#ssh
	HRef   string            `json:"href,omitempty"`
	Header map[string]string `json:"header"`
	// In seconds.
	ExpiresIn int64 `json:"expires_in,omitempty"`
	// The expires_at (RFC3339) property could also be used, but we leave it
	// out since we don't use it.
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

const usage = "Usage: git-lfs-authenticate <REPO> <OPERATION (upload/download)>"

func main() {
	// Even though not explicitly described in the Git LFS documentation, the
	// git-lfs-authenticate command is expected to either exit succesfully with
	// exit code 0 and to then print credentials in the prescribed JSON format
	// to standard out. On errors, the command should exit with a non-zero exit
	// code and print the error message in plain text to standard error. See
	// https://github.com/git-lfs/git-lfs/blob/baf40ac99850a62fe98515175d52df5c513463ec/lfshttp/ssh.go#L76-L117

	reqID := xid.New().String()
	logger := newLogger(reqID)

	if len(os.Args) != 3 {
		die(usage)
	}

	repo := strings.TrimPrefix(strings.TrimSuffix(os.Args[1], ".git"), "/")
	operation := os.Args[2]
	if operation != "download" && operation != "upload" {
		die(usage)
	}

	repoHRefBaseStr := os.Getenv("REPO_HREF_BASE")
	var repoHRefBase *url.URL
	var err error
	if repoHRefBaseStr != "" {
		if repoHRefBase, err = url.Parse(repoHRefBaseStr); err != nil {
			logger.logf("Failed to parse URL in environment variable REPO_HREF_BASE: %s", err)
			dieReqID(reqID, "internal error")
		}
	}

	user := os.Getenv("GL_USER")
	if user == "" {
		logger.logf("Environment variable GL_USER is not set")
		dieReqID(reqID, "internal error")
	}
	keyPath := os.Getenv("GITOLFS3_KEY_PATH")
	if keyPath == "" {
		logger.logf("Environment variable GITOLFS3_KEY_PATH is not set")
		dieReqID(reqID, "internal error")
	}
	keyStr, err := os.ReadFile(keyPath)
	if err != nil {
		logger.logf("Cannot read key in GITOLFS3_KEY_PATH: %s", err)
		dieReqID(reqID, "internal error")
	}
	keyStr = bytes.TrimSpace(keyStr)
	defer wipe(keyStr)

	if hex.DecodedLen(len(keyStr)) != ed25519.SeedSize {
		logger.logf("Fatal: provided private key (seed) is invalid: does not have expected length")
		dieReqID(reqID, "internal error")
	}

	seed := make([]byte, ed25519.SeedSize)
	defer wipe(seed)
	if _, err = hex.Decode(seed, keyStr); err != nil {
		logger.logf("Fatal: cannot decode provided private key (seed): %s", err)
		dieReqID(reqID, "internal error")
	}
	privateKey := ed25519.NewKeyFromSeed(seed)

	if !getGitoliteAccess(logger, reqID, repo, user, "R") {
		die("repository not found")
	}
	if operation == "upload" && !getGitoliteAccess(logger, reqID, repo, user, "W") {
		// User has read access but no write access
		die("forbidden")
	}

	expiresIn := time.Hour * 24
	claims := customClaims{
		Gitolfs3: gitolfs3Claims{
			Type:       "batch-api",
			Repository: repo,
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
		logger.logf("Fatal: failed to generate JWT: %s", err)
		die("failed to generate token")
	}

	response := authenticateResponse{
		Header: map[string]string{
			"Authorization": "Bearer " + ss,
		},
		ExpiresIn: int64(expiresIn.Seconds()),
	}
	if repoHRefBase != nil {
		response.HRef = repoHRefBase.ResolveReference(&url.URL{
			Path: path.Join(repo+".git", "/info/lfs"),
		}).String()
	}
	json.NewEncoder(os.Stdout).Encode(response)
}

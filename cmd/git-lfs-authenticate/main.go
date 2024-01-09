package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
	"time"
)

func die(msg string, args ...any) {
	fmt.Fprint(os.Stderr, "Fatal: ")
	fmt.Fprintf(os.Stderr, msg, args...)
	fmt.Fprint(os.Stderr, "\n")
	os.Exit(1)
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
	// out since we don't use it. The Git LFS docs recommend using expires_in
	// instead (???)
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

const usage = "Usage: git-lfs-authenticate <REPO> upload/download"

func main() {
	// Even though not explicitly described in the Git LFS documentation, the
	// git-lfs-authenticate command is expected to either exit succesfully with
	// exit code 0 and to then print credentials in the prescribed JSON format
	// to standard out. On errors, the command should exit with a non-zero exit
	// code and print the error message in plain text to standard error. See
	// https://github.com/git-lfs/git-lfs/blob/baf40ac99850a62fe98515175d52df5c513463ec/lfshttp/ssh.go#L76-L117

	if len(os.Args) != 3 {
		fmt.Println(usage)
		os.Exit(1)
	}

	repo := strings.TrimPrefix(path.Clean(strings.TrimSuffix(os.Args[1], ".git")), "/")
	operation := os.Args[2]
	if operation != "download" && operation != "upload" {
		fmt.Println(usage)
		os.Exit(1)
	}
	if repo == ".." || strings.HasPrefix(repo, "../") {
		die("highly illegal repo name (Anzeige ist raus)")
	}

	repoDir := path.Join(repo + ".git")
	finfo, err := os.Stat(repoDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			die("repo not found")
		}
		die("could not stat repo: %s", err)
	}
	if !finfo.IsDir() {
		die("repo not found")
	}

	hrefBase := os.Getenv("GITOLFS3_HREF_BASE")
	if hrefBase == "" {
		die("incomplete configuration: base URL not provided")
	}
	if !strings.HasSuffix(hrefBase, "/") {
		hrefBase += "/"
	}

	keyPath := os.Getenv("GITOLFS3_KEY_PATH")
	if keyPath == "" {
		die("incomplete configuration: key path not provided")
	}

	keyStr, err := os.ReadFile(keyPath)
	if err != nil {
		wipe(keyStr)
		die("cannot read key")
	}
	keyStr = bytes.TrimSpace(keyStr)
	defer wipe(keyStr)
	if hex.DecodedLen(len(keyStr)) != 64 {
		die("bad key length")
	}
	key := make([]byte, 64)
	defer wipe(key)
	if _, err = hex.Decode(key, keyStr); err != nil {
		die("cannot decode key")
	}

	expiresIn := time.Minute * 5
	expiresAtUnix := time.Now().Add(expiresIn).Unix()

	tag := hmac.New(sha256.New, key)
	io.WriteString(tag, "git-lfs-authenticate")
	tag.Write([]byte{0})
	io.WriteString(tag, repo)
	tag.Write([]byte{0})
	io.WriteString(tag, operation)
	tag.Write([]byte{0})
	binary.Write(tag, binary.BigEndian, &expiresAtUnix)
	tagStr := hex.EncodeToString(tag.Sum(nil))

	response := authenticateResponse{
		Header: map[string]string{
			"Authorization": "Tag " + tagStr,
		},
		ExpiresIn: int64(expiresIn.Seconds()),
		HRef: fmt.Sprintf("%s%s?p=1&te=%d",
			hrefBase,
			path.Join(repo+".git", "/info/lfs"),
			expiresAtUnix,
		),
	}
	json.NewEncoder(os.Stdout).Encode(response)
}

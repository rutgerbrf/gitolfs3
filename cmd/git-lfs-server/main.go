package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"net/http/cgi"
	"net/url"
	"os"
	"os/exec"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/golang-jwt/jwt/v5"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/rs/xid"
)

type operation string
type transferAdapter string
type hashAlgo string

const (
	operationDownload    operation       = "download"
	operationUpload      operation       = "upload"
	transferAdapterBasic transferAdapter = "basic"
	hashAlgoSHA256       hashAlgo        = "sha256"
)

const lfsMIME = "application/vnd.git-lfs+json"

type batchRef struct {
	Name string `json:"name"`
}

type batchRequestObject struct {
	OID  string `json:"oid"`
	Size uint64 `json:"size"`
}

type batchRequest struct {
	Operation operation            `json:"operation"`
	Transfers []transferAdapter    `json:"transfers,omitempty"`
	Ref       *batchRef            `json:"ref,omitempty"`
	Objects   []batchRequestObject `json:"objects"`
	HashAlgo  hashAlgo             `json:"hash_algo,omitempty"`
}

type batchAction struct {
	HRef   string            `json:"href"`
	Header map[string]string `json:"header,omitempty"`
	// In seconds.
	ExpiresIn int64 `json:"expires_in,omitempty"`
	// expires_at (RFC3339) could also be used, but we leave it out since we
	// don't use it.
}

type batchError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type batchResponseObject struct {
	OID           string                    `json:"oid"`
	Size          uint64                    `json:"size"`
	Authenticated *bool                     `json:"authenticated"`
	Actions       map[operation]batchAction `json:"actions,omitempty"`
	Error         *batchError               `json:"error,omitempty"`
}

type batchResponse struct {
	Transfer transferAdapter       `json:"transfer,omitempty"`
	Objects  []batchResponseObject `json:"objects"`
	HashAlgo hashAlgo              `json:"hash_algo,omitempty"`
}

type handler struct {
	mc           *minio.Client
	bucket       string
	anonUser     string
	gitolitePath string
	publicKey    ed25519.PublicKey
}

// Requires lowercase hash
func isValidSHA256Hash(hash string) bool {
	if len(hash) != 64 {
		return false
	}
	for _, c := range hash {
		if !unicode.Is(unicode.ASCII_Hex_Digit, c) {
			return false
		}
	}
	return true
}

type lfsError struct {
	Message          string `json:"message"`
	DocumentationURL string `json:"documentation_url,omitempty"`
	RequestID        string `json:"request_id,omitempty"`
}

func makeRespError(ctx context.Context, w http.ResponseWriter, message string, code int) {
	err := lfsError{Message: message}
	if val := ctx.Value(requestIDKey); val != nil {
		err.RequestID = val.(string)
	}
	w.Header().Set("Content-Type", lfsMIME+"; charset=utf-8")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(err)
}

func makeObjError(obj parsedBatchObject, message string, code int) batchResponseObject {
	return batchResponseObject{
		OID:  obj.fullHash,
		Size: obj.size,
		Error: &batchError{
			Message: message,
			Code:    code,
		},
	}
}

func sha256AsBase64(hash string) string {
	raw, err := hex.DecodeString(hash)
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func (h *handler) handleDownloadObject(ctx context.Context, repo string, obj parsedBatchObject) batchResponseObject {
	fullPath := path.Join(repo+".git", "lfs/objects", obj.firstByte, obj.secondByte, obj.fullHash)
	expiresIn := time.Hour * 24

	info, err := h.mc.StatObject(ctx, h.bucket, fullPath, minio.StatObjectOptions{Checksum: true})
	if err != nil {
		var resp minio.ErrorResponse
		if errors.As(err, &resp) && resp.StatusCode == http.StatusNotFound {
			return makeObjError(obj, "Object does not exist", http.StatusNotFound)
		}
		// TODO: consider not making this an object-specific, but rather a
		// generic error such that the entire Batch API request fails.
		reqlog(ctx, "Failed to query object information (full path: %s): %s", fullPath, err)
		return makeObjError(obj, "Failed to query object information", http.StatusInternalServerError)
	}
	if info.ChecksumSHA256 != "" && strings.ToLower(info.ChecksumSHA256) != obj.fullHash {
		return makeObjError(obj, "Corrupted file", http.StatusUnprocessableEntity)
	}
	if uint64(info.Size) != obj.size {
		return makeObjError(obj, "Incorrect size specified for object", http.StatusUnprocessableEntity)
	}

	presigned, err := h.mc.PresignedGetObject(ctx, h.bucket, fullPath, expiresIn, url.Values{})
	if err != nil {
		// TODO: consider not making this an object-specific, but rather a
		// generic error such that the entire Batch API request fails.
		reqlog(ctx, "Failed to generate action href (full path: %s): %s", fullPath, err)
		return makeObjError(obj, "Failed to generate action href", http.StatusInternalServerError)
	}

	authenticated := true
	return batchResponseObject{
		OID:           obj.fullHash,
		Size:          obj.size,
		Authenticated: &authenticated,
		Actions: map[operation]batchAction{
			operationDownload: {
				HRef:      presigned.String(),
				ExpiresIn: int64(expiresIn.Seconds()),
			},
		},
	}
}

func (h *handler) handleUploadObject(ctx context.Context, repo string, obj parsedBatchObject) batchResponseObject {
	fullPath := path.Join(repo+".git", "lfs/objects", obj.firstByte, obj.secondByte, obj.fullHash)
	expiresIn := time.Hour * 24

	presigned, err := h.mc.Presign(ctx, http.MethodPut, h.bucket, fullPath, expiresIn, url.Values{
		"x-amz-sdk-checksum-algorithm": {"sha256"},
		"x-amz-checksum-sha256":        {sha256AsBase64(obj.fullHash)},
		"x-amz-content-sha256":         {obj.fullHash},
		"Content-Length":               {strconv.FormatUint(obj.size, 10)},
	})
	if err != nil {
		// TODO: consider not making this an object-specific, but rather a
		// generic error such that the entire Batch API request fails.
		reqlog(ctx, "Failed to generate action href (full path: %s): %s", fullPath, err)
		return makeObjError(obj, "Failed to generate action href", http.StatusInternalServerError)
	}

	authenticated := true
	return batchResponseObject{
		OID:           obj.fullHash,
		Size:          obj.size,
		Authenticated: &authenticated,
		Actions: map[operation]batchAction{
			operationUpload: {
				HRef:      presigned.String(),
				ExpiresIn: int64(expiresIn.Seconds()),
			},
		},
	}
}

type parsedBatchObject struct {
	firstByte  string
	secondByte string
	fullHash   string
	size       uint64
}

func isLFSMediaType(t string) bool {
	if mediaType, params, err := mime.ParseMediaType(t); err == nil {
		if mediaType == lfsMIME {
			if params["charset"] == "" || strings.ToLower(params["charset"]) == "utf-8" {
				return true
			}
		}
	}
	return false
}

var re = regexp.MustCompile(`^([a-zA-Z0-9-_/]+)\.git/info/lfs/objects/batch$`)

type requestID struct{}

var requestIDKey requestID

// TODO: make a shared package for this
type gitolfs3Claims struct {
	Repository string    `json:"repository"`
	Permission operation `json:"permission"`
}

type customClaims struct {
	Gitolfs3 gitolfs3Claims `json:"gitolfs3"`
	*jwt.RegisteredClaims
}

// Request to perform <operation> in <repository> [on reference <refspec>]
type operationRequest struct {
	operation  operation
	repository string
	refspec    *string
}

func (h *handler) getGitoliteAccess(repo, user, gitolitePerm string, refspec *string) (bool, error) {
	// gitolite access -q: returns only exit code
	gitoliteArgs := []string{"access", "-q", repo, user, gitolitePerm}
	if refspec != nil {
		gitoliteArgs = append(gitoliteArgs, *refspec)
	}
	cmd := exec.Command(h.gitolitePath, gitoliteArgs...)
	err := cmd.Run()
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			return false, fmt.Errorf("(running %s): %w", cmd, err)
		}
		return false, nil
	}
	return true, nil
}

func (h *handler) authorize(ctx context.Context, w http.ResponseWriter, r *http.Request, or operationRequest) bool {
	user := h.anonUser

	if authz := r.Header.Get("Authorization"); authz != "" {
		if !strings.HasPrefix(authz, "Bearer ") {
			makeRespError(ctx, w, "Invalid Authorization header", http.StatusBadRequest)
			return false
		}
		authz = strings.TrimPrefix(authz, "Bearer ")

		var claims customClaims
		_, err := jwt.ParseWithClaims(authz, &claims, func(token *jwt.Token) (any, error) {
			if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
				return nil, fmt.Errorf("expected signing method EdDSA, got %s", token.Header["alg"])
			}
			return h.publicKey, nil
		})
		if err != nil {
			makeRespError(ctx, w, "Invalid token", http.StatusUnauthorized)
			return false
		}

		if claims.Gitolfs3.Repository != or.repository {
			makeRespError(ctx, w, "Invalid token", http.StatusUnauthorized)
			return false
		}
		if claims.Gitolfs3.Permission == operationDownload && or.operation == operationUpload {
			makeRespError(ctx, w, "Forbidden", http.StatusForbidden)
			return false
		}

		user = claims.Subject
	}

	readAccess, err := h.getGitoliteAccess(or.repository, user, "R", or.refspec)
	if err != nil {
		reqlog(ctx, "Error checking access info: %s", err)
		makeRespError(ctx, w, "Failed to query access information", http.StatusInternalServerError)
		return false
	}
	if !readAccess {
		makeRespError(ctx, w, "Repository not found", http.StatusNotFound)
		return false
	}
	if or.operation == operationUpload {
		writeAccess, err := h.getGitoliteAccess(or.repository, user, "W", or.refspec)
		if err != nil {
			reqlog(ctx, "Error checking access info: %s", err)
			makeRespError(ctx, w, "Failed to query access information", http.StatusInternalServerError)
			return false
		}
		// User has read access but no write access
		if !writeAccess {
			makeRespError(ctx, w, "Forbidden", http.StatusForbidden)
			return false
		}
	}

	return true
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := context.WithValue(r.Context(), requestIDKey, xid.New().String())

	if r.Method != http.MethodPost {
		makeRespError(ctx, w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	reqPath := os.Getenv("PATH_INFO")
	if reqPath == "" {
		reqPath = r.URL.Path
	}
	reqlog(ctx, "reqPath: %s", reqPath)
	reqPath = strings.TrimPrefix(path.Clean(reqPath), "/")
	reqlog(ctx, "Cleaned reqPath: %s", reqPath)
	submatches := re.FindStringSubmatch(reqPath)
	if len(submatches) != 2 {
		reqlog(ctx, "Got path: %s, did not match regex", reqPath)
		makeRespError(ctx, w, "Not found", http.StatusNotFound)
		return
	}
	repo := strings.TrimPrefix(path.Clean(submatches[1]), "/")
	reqlog(ctx, "Repository: %s", repo)

	if !slices.ContainsFunc(r.Header.Values("Accept"), isLFSMediaType) {
		makeRespError(ctx, w, "Expected "+lfsMIME+" (with UTF-8 charset) in list of acceptable response media types", http.StatusNotAcceptable)
		return
	}
	if !isLFSMediaType(r.Header.Get("Content-Type")) {
		makeRespError(ctx, w, "Expected request Content-Type to be "+lfsMIME+" (with UTF-8 charset)", http.StatusUnsupportedMediaType)
		return
	}

	var body batchRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		makeRespError(ctx, w, "Failed to parse request body as JSON", http.StatusBadRequest)
		return
	}
	if body.Operation != operationDownload && body.Operation != operationUpload {
		makeRespError(ctx, w, "Invalid operation specified", http.StatusBadRequest)
		return
	}

	or := operationRequest{
		operation:  body.Operation,
		repository: repo,
	}
	if body.Ref != nil {
		or.refspec = &body.Ref.Name
	}
	if !h.authorize(ctx, w, r, or) {
		return
	}

	if body.HashAlgo != hashAlgoSHA256 {
		makeRespError(ctx, w, "Unsupported hash algorithm specified", http.StatusConflict)
		return
	}

	if len(body.Transfers) != 0 && !slices.Contains(body.Transfers, transferAdapterBasic) {
		makeRespError(ctx, w, "Unsupported transfer adapter specified (supported: basic)", http.StatusConflict)
		return
	}

	var objects []parsedBatchObject
	for _, obj := range body.Objects {
		oid := strings.ToLower(obj.OID)
		if !isValidSHA256Hash(oid) {
			makeRespError(ctx, w, "Invalid hash format in object ID", http.StatusBadRequest)
			return
		}
		objects = append(objects, parsedBatchObject{
			firstByte:  oid[:2],
			secondByte: oid[2:4],
			fullHash:   oid,
			size:       obj.Size,
		})
	}

	resp := batchResponse{
		Transfer: transferAdapterBasic,
		HashAlgo: hashAlgoSHA256,
	}
	for _, obj := range objects {
		switch body.Operation {
		case operationDownload:
			resp.Objects = append(resp.Objects, h.handleDownloadObject(ctx, repo, obj))
		case operationUpload:
			resp.Objects = append(resp.Objects, h.handleUploadObject(ctx, repo, obj))
		}
	}

	w.Header().Set("Content-Type", lfsMIME)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

func reqlog(ctx context.Context, msg string, args ...any) {
	fmt.Fprint(os.Stderr, "[gitolfs3] ")
	if val := ctx.Value(requestIDKey); val != nil {
		fmt.Fprintf(os.Stderr, "[%s] ", val.(string))
	}
	fmt.Fprintf(os.Stderr, msg, args...)
	fmt.Fprint(os.Stderr, "\n")
}

func log(msg string, args ...any) {
	fmt.Fprint(os.Stderr, "[gitolfs3] ")
	fmt.Fprintf(os.Stderr, msg, args...)
	fmt.Fprint(os.Stderr, "\n")
}

func die(msg string, args ...any) {
	log("Environment variables: (dying)")
	for _, s := range os.Environ() {
		log("  %s", s)
	}
	log(msg, args...)
	os.Exit(1)
}

func loadPublicKey(path string) ed25519.PublicKey {
	raw, err := os.ReadFile(path)
	if err != nil {
		die("Failed to open specified public key: %s", err)
	}
	raw = bytes.TrimSpace(raw)

	if hex.DecodedLen(len(raw)) != ed25519.PublicKeySize {
		die("Specified public key file does not contain key of appropriate length")
	}
	decoded := make([]byte, hex.DecodedLen(len(raw)))
	if _, err = hex.Decode(decoded, raw); err != nil {
		die("Failed to decode specified public key: %s", err)
	}
	return decoded
}

func main() {
	anonUser := os.Getenv("ANON_USER")
	publicKeyPath := os.Getenv("GITOLFS3_PUBLIC_KEY_PATH")
	endpoint := os.Getenv("S3_ENDPOINT")
	bucket := os.Getenv("S3_BUCKET")
	accessKeyIDFile := os.Getenv("S3_ACCESS_KEY_ID_FILE")
	secretAccessKeyFile := os.Getenv("S3_SECRET_ACCESS_KEY_FILE")
	gitolitePath := os.Getenv("GITOLITE_PATH")

	if gitolitePath == "" {
		gitolitePath = "gitolite"
	}

	if anonUser == "" {
		die("Fatal: expected environment variable ANON_USER to be set")
	}
	if publicKeyPath == "" {
		die("Fatal: expected environment variable GITOLFS3_PUBLIC_KEY_PATH to be set")
	}
	if endpoint == "" {
		die("Fatal: expected environment variable S3_ENDPOINT to be set")
	}
	if bucket == "" {
		die("Fatal: expected environment variable S3_BUCKET to be set")
	}

	if accessKeyIDFile == "" {
		die("Fatal: expected environment variable S3_ACCESS_KEY_ID_FILE to be set")
	}
	if secretAccessKeyFile == "" {
		die("Fatal: expected environment variable S3_SECRET_ACCESS_KEY_FILE to be set")
	}

	accessKeyID, err := os.ReadFile(accessKeyIDFile)
	if err != nil {
		die("Fatal: failed to read access key ID from specified file: %s", err)
	}
	secretAccessKey, err := os.ReadFile(secretAccessKeyFile)
	if err != nil {
		die("Fatal: failed to read secret access key from specified file: %s", err)
	}

	publicKey := loadPublicKey(publicKeyPath)

	mc, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(string(accessKeyID), string(secretAccessKey), ""),
		Secure: true,
	})
	if err != nil {
		die("Fatal: failed to create S3 client: %s", err)
	}

	if err = cgi.Serve(&handler{mc, bucket, anonUser, gitolitePath, publicKey}); err != nil {
		die("Fatal: failed to serve CGI: %s", err)
	}
}

// Directory stucture:
// - lfs/
//   - locks/
//   - objects/
//     - <1st OID byte>
//       - <2nd OID byte>
//         - <OID hash> <- this is the object

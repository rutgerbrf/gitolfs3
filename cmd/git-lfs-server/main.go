package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
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
	Size int64  `json:"size"`
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
	Size          int64                     `json:"size"`
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
	privateKey   ed25519.PrivateKey
	baseURL      *url.URL
}

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
	if info.Size != obj.size {
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

type uploadObjectGitolfs3Claims struct {
	Repository string `json:"repository"`
	OID        string `json:"oid"`
	Size       int64  `json:"size"`
}

type uploadObjectCustomClaims struct {
	Gitolfs3 uploadObjectGitolfs3Claims `json:"gitolfs3"`
	*jwt.RegisteredClaims
}

// Return nil when the object already exists
func (h *handler) handleUploadObject(ctx context.Context, repo string, obj parsedBatchObject) *batchResponseObject {
	fullPath := path.Join(repo+".git", "lfs/objects", obj.firstByte, obj.secondByte, obj.fullHash)
	_, err := h.mc.StatObject(ctx, h.bucket, fullPath, minio.GetObjectOptions{})
	if err == nil {
		// The object exists
		return nil
	}

	var resp minio.ErrorResponse
	if !errors.As(err, &resp) || resp.StatusCode != http.StatusNotFound {
		// TODO: consider not making this an object-specific, but rather a
		// generic error such that the entire Batch API request fails.
		reqlog(ctx, "Failed to generate action href (full path: %s): %s", fullPath, err)
		objErr := makeObjError(obj, "Failed to generate action href", http.StatusInternalServerError)
		return &objErr
	}

	expiresIn := time.Hour * 24
	claims := uploadObjectCustomClaims{
		Gitolfs3: uploadObjectGitolfs3Claims{
			Repository: repo,
			OID:        obj.fullHash,
			Size:       obj.size,
		},
		RegisteredClaims: &jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiresIn)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	ss, err := token.SignedString(h.privateKey)
	if err != nil {
		// TODO: consider not making this an object-specific, but rather a
		// generic error such that the entire Batch API request fails.
		reqlog(ctx, "Fatal: failed to generate JWT: %s", err)
		objErr := makeObjError(obj, "Failed to generate token", http.StatusInternalServerError)
		return &objErr
	}

	uploadPath := path.Join(repo+".git", "info/lfs/objects", obj.firstByte, obj.secondByte, obj.fullHash)
	uploadHRef := h.baseURL.ResolveReference(&url.URL{Path: uploadPath}).String()
	// The object does not exist.
	authenticated := true
	return &batchResponseObject{
		OID:           obj.fullHash,
		Size:          obj.size,
		Authenticated: &authenticated,
		Actions: map[operation]batchAction{
			operationUpload: {
				Header: map[string]string{
					"Authorization": "Bearer " + ss,
				},
				HRef:      uploadHRef,
				ExpiresIn: int64(expiresIn.Seconds()),
			},
		},
	}
}

type validatingReader struct {
	promisedSize   int64
	promisedSha256 []byte

	reader    io.Reader
	bytesRead int64
	current   hash.Hash
	err       error
}

func newValidatingReader(promisedSize int64, promisedSha256 []byte, r io.Reader) *validatingReader {
	return &validatingReader{
		promisedSize:   promisedSize,
		promisedSha256: promisedSha256,
		reader:         r,
		current:        sha256.New(),
	}
}

var errTooBig = errors.New("validator: uploaded file bigger than indicated")
var errTooSmall = errors.New("validator: uploaded file smaller than indicated")
var errBadSum = errors.New("validator: bad checksum provided or file corrupted")

func (i *validatingReader) Read(b []byte) (int, error) {
	if i.err != nil {
		return 0, i.err
	}
	n, err := i.reader.Read(b)
	i.bytesRead += int64(n)
	if i.bytesRead > i.promisedSize {
		i.err = errTooBig
		return 0, i.err
	}
	if err != nil && errors.Is(err, io.EOF) {
		if i.bytesRead < i.promisedSize {
			i.err = errTooSmall
			return n, i.err
		}
	}
	// According to the documentation, Hash.Write never returns an error
	i.current.Write(b[:n])
	if i.bytesRead == i.promisedSize {
		if !bytes.Equal(i.promisedSha256, i.current.Sum(nil)) {
			i.err = errBadSum
			return 0, i.err
		}
	}
	return n, err
}

func (h *handler) handlePutObject(w http.ResponseWriter, r *http.Request, repo, oid string) {
	ctx := r.Context()

	authz := r.Header.Get("Authorization")
	if authz == "" {
		makeRespError(ctx, w, "Missing Authorization header", http.StatusBadRequest)
		return
	}
	if !strings.HasPrefix(authz, "Bearer ") {
		makeRespError(ctx, w, "Invalid Authorization header", http.StatusBadRequest)
		return
	}
	authz = strings.TrimPrefix(authz, "Bearer ")

	var claims uploadObjectCustomClaims
	_, err := jwt.ParseWithClaims(authz, &claims, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, fmt.Errorf("expected signing method EdDSA, got %s", token.Header["alg"])
		}
		return h.privateKey.Public(), nil
	})
	if err != nil {
		makeRespError(ctx, w, "Invalid token", http.StatusUnauthorized)
		return
	}
	if claims.Gitolfs3.Repository != repo {
		makeRespError(ctx, w, "Invalid token", http.StatusUnauthorized)
		return
	}
	if claims.Gitolfs3.OID != oid {
		makeRespError(ctx, w, "Invalid token", http.StatusUnauthorized)
		return
	}

	// Check with claims
	if lengthStr := r.Header.Get("Content-Length"); lengthStr != "" {
		length, err := strconv.ParseInt(lengthStr, 10, 64)
		if err != nil {
			makeRespError(ctx, w, "Bad Content-Length format", http.StatusBadRequest)
			return
		}
		if length != claims.Gitolfs3.Size {
			makeRespError(ctx, w, "Invalid token", http.StatusUnauthorized)
			return
		}
	}

	sha256Raw, err := hex.DecodeString(oid)
	if err != nil || len(sha256Raw) != sha256.Size {
		makeRespError(ctx, w, "Invalid OID", http.StatusBadRequest)
		return
	}

	reader := newValidatingReader(claims.Gitolfs3.Size, sha256Raw, r.Body)

	fullPath := path.Join(repo+".git", "lfs/objects", oid[:2], oid[2:4], oid)
	_, err = h.mc.PutObject(ctx, h.bucket, fullPath, reader, int64(claims.Gitolfs3.Size), minio.PutObjectOptions{
		SendContentMd5: true,
	})
	if err != nil {
		makeRespError(ctx, w, "Failed to upload object", http.StatusInternalServerError)
		return
	}
}

type parsedBatchObject struct {
	firstByte  string
	secondByte string
	fullHash   string
	size       int64
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

var reBatchAPI = regexp.MustCompile(`^([a-zA-Z0-9-_/]+)\.git/info/lfs/objects/batch$`)
var reObjUpload = regexp.MustCompile(`^([a-zA-Z0-9-_/]+)\.git/info/lfs/objects/([0-9a-f]{2})/([0-9a-f]{2})/([0-9a-f]{2}){64}$`)

type requestID struct{}

var requestIDKey requestID

// TODO: make a shared package for this
type lfsAuthGitolfs3Claims struct {
	Repository string    `json:"repository"`
	Permission operation `json:"permission"`
}

type lfsAuthCustomClaims struct {
	Gitolfs3 lfsAuthGitolfs3Claims `json:"gitolfs3"`
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

func (h *handler) authorize(w http.ResponseWriter, r *http.Request, or operationRequest) bool {
	user := h.anonUser
	ctx := r.Context()

	if authz := r.Header.Get("Authorization"); authz != "" {
		if !strings.HasPrefix(authz, "Bearer ") {
			makeRespError(ctx, w, "Invalid Authorization header", http.StatusBadRequest)
			return false
		}
		authz = strings.TrimPrefix(authz, "Bearer ")

		var claims lfsAuthCustomClaims
		_, err := jwt.ParseWithClaims(authz, &claims, func(token *jwt.Token) (any, error) {
			if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
				return nil, fmt.Errorf("expected signing method EdDSA, got %s", token.Header["alg"])
			}
			return h.privateKey.Public(), nil
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

func (h *handler) handleBatchAPI(w http.ResponseWriter, r *http.Request, repo string) {
	ctx := r.Context()

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
	if !h.authorize(w, r.WithContext(ctx), or) {
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
			if respObj := h.handleUploadObject(ctx, repo, obj); respObj != nil {
				resp.Objects = append(resp.Objects, *respObj)
			}
		}
	}

	w.Header().Set("Content-Type", lfsMIME)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := context.WithValue(r.Context(), requestIDKey, xid.New().String())

	reqPath := os.Getenv("PATH_INFO")
	if reqPath == "" {
		reqPath = r.URL.Path
	}
	reqPath = strings.TrimPrefix(path.Clean(reqPath), "/")

	if submatches := reBatchAPI.FindStringSubmatch(reqPath); len(submatches) == 2 {
		repo := strings.TrimPrefix(path.Clean(submatches[1]), "/")
		reqlog(ctx, "Repository: %s", repo)

		if r.Method != http.MethodPost {
			makeRespError(ctx, w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		h.handleBatchAPI(w, r.WithContext(ctx), repo)
		return
	}

	if submatches := reObjUpload.FindStringSubmatch(reqPath); len(submatches) == 5 {
		repo := strings.TrimPrefix(path.Clean(submatches[1]), "/")
		oid0, oid1, oid := submatches[2], submatches[3], submatches[4]

		if !isValidSHA256Hash(oid) {
			panic("Regex should only allow valid SHA256 hashes")
		}
		if oid0 != oid[:2] || oid1 != oid[2:4] {
			makeRespError(ctx, w, "Bad URL format: malformed OID pattern", http.StatusBadRequest)
			return
		}
		reqlog(ctx, "Repository: %s; OID: %s", repo, oid)

		if r.Method != http.MethodPost {
			makeRespError(ctx, w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		h.handleBatchAPI(w, r.WithContext(ctx), repo)
		return
	}

	makeRespError(ctx, w, "Not found", http.StatusNotFound)
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

func loadPrivateKey(path string) ed25519.PrivateKey {
	raw, err := os.ReadFile(path)
	if err != nil {
		die("Failed to open specified public key: %s", err)
	}
	raw = bytes.TrimSpace(raw)

	if hex.DecodedLen(len(raw)) != ed25519.SeedSize {
		die("Specified public key file does not contain key (seed) of appropriate length")
	}
	decoded := make([]byte, hex.DecodedLen(len(raw)))
	if _, err = hex.Decode(decoded, raw); err != nil {
		die("Failed to decode specified public key: %s", err)
	}
	return ed25519.NewKeyFromSeed(decoded)
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func main() {
	anonUser := os.Getenv("ANON_USER")
	privateKeyPath := os.Getenv("GITOLFS3_PRIVATE_KEY_PATH")
	endpoint := os.Getenv("S3_ENDPOINT")
	bucket := os.Getenv("S3_BUCKET")
	accessKeyIDFile := os.Getenv("S3_ACCESS_KEY_ID_FILE")
	secretAccessKeyFile := os.Getenv("S3_SECRET_ACCESS_KEY_FILE")
	gitolitePath := os.Getenv("GITOLITE_PATH")
	baseURLStr := os.Getenv("BASE_URL")

	if gitolitePath == "" {
		gitolitePath = "gitolite"
	}

	if anonUser == "" {
		die("Fatal: expected environment variable ANON_USER to be set")
	}
	if privateKeyPath == "" {
		die("Fatal: expected environment variable GITOLFS3_PRIVATE_KEY_PATH to be set")
	}
	if baseURLStr == "" {
		die("Fatal: expected environment variable BASE_URL to be set")
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

	privateKey := loadPrivateKey(privateKeyPath)
	defer wipe(privateKey)

	baseURL, err := url.Parse(baseURLStr)
	if err != nil {
		die("Fatal: provided BASE_URL has bad format: %s", err)
	}

	mc, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(string(accessKeyID), string(secretAccessKey), ""),
		Secure: true,
	})
	if err != nil {
		die("Fatal: failed to create S3 client: %s", err)
	}

	if err = cgi.Serve(&handler{mc, bucket, anonUser, gitolitePath, privateKey, baseURL}); err != nil {
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

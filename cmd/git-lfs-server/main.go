package main

import (
	"context"
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

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
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

type RFC3339SecondsTime time.Time

func (t RFC3339SecondsTime) MarshalJSON() ([]byte, error) {
	b := make([]byte, 0, len(time.RFC3339)+len(`""`))
	b = append(b, '"')
	b = time.Time(t).AppendFormat(b, time.RFC3339)
	b = append(b, '"')
	return b, nil
}

type SecondDuration time.Duration

func (d SecondDuration) MarshalJSON() ([]byte, error) {
	var b []byte
	b = strconv.AppendInt(b, int64(time.Duration(d).Seconds()), 10)
	return b, nil
}

type batchAction struct {
	HRef      *url.URL            `json:"href"`
	Header    map[string]string   `json:"header,omitempty"`
	ExpiresIn *SecondDuration     `json:"expires_in,omitempty"`
	ExpiresAt *RFC3339SecondsTime `json:"expires_at,omitempty"`
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
	mc       *minio.Client
	bucket   string
	anonUser string
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

func makeRespError(w http.ResponseWriter, message string, code int) {
	w.Header().Set("Content-Type", lfsMIME+"; charset=utf-8")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(lfsError{Message: message})
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

func (h *handler) handleDownloadObject(ctx context.Context, repo string, obj parsedBatchObject) batchResponseObject {
	fullPath := path.Join(repo, "lfs/objects", obj.firstByte, obj.secondByte, obj.fullHash)
	expiresIn := time.Hour * 24
	expiresInSeconds := SecondDuration(expiresIn)

	info, err := h.mc.StatObject(ctx, h.bucket, fullPath, minio.StatObjectOptions{Checksum: true})
	if err != nil {
		var resp minio.ErrorResponse
		if errors.As(err, &resp) && resp.StatusCode == http.StatusNotFound {
			return makeObjError(obj, "Object does not exist", http.StatusNotFound)
		}
		// TODO: consider not making this an object-specific, but rather a
		// generic error such that the entire Batch API request fails.
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
		return makeObjError(obj, "Failed to generate action href", http.StatusInternalServerError)
	}

	authenticated := true
	return batchResponseObject{
		OID:           obj.fullHash,
		Size:          obj.size,
		Authenticated: &authenticated,
		Actions: map[operation]batchAction{
			operationDownload: {
				HRef:      presigned,
				ExpiresIn: &expiresInSeconds,
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

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	reqPath := os.Getenv("PATH_INFO")
	if reqPath == "" {
		reqPath = r.URL.Path
	}
	reqPath = strings.TrimPrefix("/", path.Clean(reqPath))
	submatches := re.FindStringSubmatch(reqPath)
	if len(submatches) != 2 {
		log("Got path: %s, did not match regex", reqPath)
		makeRespError(w, "Not found", http.StatusNotFound)
		return
	}
	repo := strings.TrimPrefix("/", path.Clean(submatches[1]))
	log("Repository: %s", repo)

	if !slices.ContainsFunc(r.Header.Values("Accept"), isLFSMediaType) {
		makeRespError(w, "Expected "+lfsMIME+" (with UTF-8 charset) in list of acceptable response media types", http.StatusNotAcceptable)
		return
	}
	if !isLFSMediaType(r.Header.Get("Content-Type")) {
		makeRespError(w, "Expected request Content-Type to be "+lfsMIME+" (with UTF-8 charset)", http.StatusUnsupportedMediaType)
		return
	}

	var body batchRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		makeRespError(w, "Failed to parse request body as JSON", http.StatusBadRequest)
		return
	}

	if body.HashAlgo != hashAlgoSHA256 {
		makeRespError(w, "Unsupported hash algorithm specified", http.StatusConflict)
		return
	}

	// TODO: handle authentication
	// right now, we're just trying to make everything publically accessible
	if body.Operation == operationUpload {
		makeRespError(w, "Upload operations are currently not supported", http.StatusForbidden)
		return
	}

	if len(body.Transfers) != 0 && !slices.Contains(body.Transfers, transferAdapterBasic) {
		makeRespError(w, "Unsupported transfer adapter specified (supported: basic)", http.StatusConflict)
		return
	}

	gitoliteArgs := []string{"access", "-q", repo, h.anonUser, "R"}
	if body.Ref != nil && body.Ref.Name != "" {
		gitoliteArgs = append(gitoliteArgs, body.Ref.Name)
	}
	cmd := exec.Command("gitolite", gitoliteArgs...)
	err := cmd.Run()
	permGranted := err == nil
	var exitErr *exec.ExitError
	if err != nil && !errors.As(err, &exitErr) {
		makeRespError(w, "Failed to query access information", http.StatusInternalServerError)
		return
	}
	if !permGranted {
		// TODO: when handling authorization, make sure to return 403 Forbidden
		// here when the user *does* have read permissions, but is not allowed
		// to write when requesting an upload operation.
		makeRespError(w, "Repository not found", http.StatusNotFound)
		return
	}

	var objects []parsedBatchObject
	for _, obj := range body.Objects {
		oid := strings.ToLower(obj.OID)
		if !isValidSHA256Hash(oid) {
			makeRespError(w, "Invalid hash format in object ID", http.StatusBadRequest)
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
		resp.Objects = append(resp.Objects, h.handleDownloadObject(r.Context(), repo, obj))
	}

	w.Header().Set("Content-Type", lfsMIME)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

func log(msg string, args ...any) {
	fmt.Fprint(os.Stderr, "[gitolfs3] ")
	fmt.Fprintf(os.Stderr, msg, args...)
	fmt.Fprint(os.Stderr, "\n")
}

func die(msg string, args ...any) {
	log(msg, args...)
	os.Exit(1)
}

func main() {
	anonUser := os.Getenv("ANON_USER")
	endpoint := os.Getenv("S3_ENDPOINT")
	bucket := os.Getenv("S3_BUCKET")
	accessKeyIDFile := os.Getenv("S3_ACCESS_KEY_ID_FILE")
	secretAccessKeyFile := os.Getenv("S3_SECRET_ACCESS_KEY_FILE")

	log("Environment variables:")
	for _, s := range os.Environ() {
		log("  %s", s)
	}

	if anonUser == "" {
		die("Fatal: expected environment variable ANON_USER to be set")
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

	mc, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(string(accessKeyID), string(secretAccessKey), ""),
		Secure: true,
	})
	if err != nil {
		die("Fatal: failed to create S3 client: %s", err)
	}

	if err = cgi.Serve(&handler{mc, bucket, anonUser}); err != nil {
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

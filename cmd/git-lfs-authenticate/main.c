#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <sys/stat.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>

void die(const char *format, ...) {
	fputs("Fatal: ", stderr);
	va_list ap;
	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);
	fputc('\n', stderr);
	exit(EXIT_FAILURE);
}

#define USAGE "Usage: git-lfs-authenticate <REPO> upload/download"

bool hasprefix(const char *str, const char *prefix) {
	if (strlen(prefix) > strlen(str))
		return false;
	return !strncmp(str, prefix, strlen(prefix));
}

bool hassuffix(const char *str, const char *suffix) {
	if (strlen(suffix) > strlen(str))
		return false;
	str += strlen(str) - strlen(suffix);
	return !strcmp(str, suffix);
}

const char *trimspace(const char *str, size_t *length) {
	while (*length > 0 && isspace(str[0])) {
		str++; (*length)--;
	}
	while (*length > 0 && isspace(str[*length - 1]))
		(*length)--;
	return str;
}

void printescjson(const char *str) {
	for (size_t i = 0; i < strlen(str); i++) {
		switch (str[i]) {
		case '"':  fputs("\\\"", stdout); break;
		case '\\': fputs("\\\\", stdout); break;
		case '\b': fputs("\\b",  stdout); break;
		case '\f': fputs("\\f",  stdout); break;
		case '\n': fputs("\\n",  stdout); break;
		case '\r': fputs("\\r",  stdout); break;
		case '\t': fputs("\\t",  stdout); break;
		default:   fputc(str[i], stdout);
		}
	}
}

void checkrepopath(const char *path) {
	if (strstr(path, "//") || strstr(path, "/./") || strstr(path, "/../")
	 || hasprefix(path, "./") || hasprefix(path, "../") || hasprefix(path, "/../"))
		die("Bad repository name: is unresolved path");
	if (strlen(path) > 100)
		die("Bad repository name: longer than 100 characters");
	if (hassuffix(path, "/"))
		die("Bad repositry name: unexpected trailing slash");
	if (hasprefix(path, "/"))
		die("Bad repository name: unexpected absolute path");
	if (!hassuffix(path, ".git"))
		die("Bad repository name: expected '.git' repo path suffix");

	struct stat statbuf;
	if (stat(path, &statbuf)) {
		if (errno == ENOENT)
			die("Repo not found");
		die("Could not stat repo: %s", strerror(errno));
	}
	if (!S_ISDIR(statbuf.st_mode)) {
		die("Repo not found");
	}
}

char *readkeyfile(const char *path, size_t *len) {
	FILE *f = fopen(path, "r");
	if (!f)
		die("Cannot read key file: %s", strerror(errno));
	*len = 0;
	size_t bufcap = 4096;
	char *buf = malloc(bufcap);
	while (!feof(f) && !ferror(f)) {
		if (*len + 4096 > bufcap) {
			bufcap *= 2;
			buf = realloc(buf, bufcap);
		}
		*len += fread(buf + *len, sizeof(char), 4096, f);
	}
	if (ferror(f) && !feof(f)) {
		OPENSSL_cleanse(buf, *len);
		die("Failed to read key file (length: %lu)", *len);
	}
	fclose(f);
	return buf;
}

#define KEYSIZE 64

void readkey(const char *path, uint8_t dest[KEYSIZE]) {
	size_t keybuf_len = 0;
	char *keybuf = readkeyfile(path, &keybuf_len);

	size_t keystr_len = keybuf_len;
	const char *keystr = trimspace(keybuf, &keystr_len);
	if (keystr_len != 2 * KEYSIZE) {
		OPENSSL_cleanse(keybuf, keybuf_len);
		die("Bad key length");
	}

	for (size_t i = 0; i < KEYSIZE; i++) {
		const char c = keystr[i];
		uint8_t nibble = 0;
		if (c >= '0' && c <= '9')
			nibble = c - '0';
		else if (c >= 'a' && c <= 'f')
			nibble = c - 'a' + 10;
		else if (c >= 'A' && c <= 'F')
			nibble = c - 'A' + 10;
		else {
			OPENSSL_cleanse(keybuf, keybuf_len);
			OPENSSL_cleanse(dest, KEYSIZE);
			die("Cannot decode key");
		}
		size_t ikey = i / 2;
		if (i % 2) dest[ikey] |= nibble;
		else dest[ikey] = nibble << 4;
	}

	OPENSSL_cleanse(keybuf, keybuf_len);
	free(keybuf);
}

void u64tobe(uint64_t x, uint8_t b[8]) {
	b[0] = (uint8_t)(x >> 56);
	b[1] = (uint8_t)(x >> 48);
	b[2] = (uint8_t)(x >> 40);
	b[3] = (uint8_t)(x >> 32);
	b[4] = (uint8_t)(x >> 24);
	b[5] = (uint8_t)(x >> 16);
	b[6] = (uint8_t)(x >>  8);
	b[7] = (uint8_t)(x >>  0);
}

#define MAX_TAG_SIZE EVP_MAX_MD_SIZE

typedef struct taginfo {
	const char    *authtype;
	const char    *repopath;
	const char    *operation;
	const int64_t  expiresat_s;
} taginfo_t;

void *memcat(void *dest, const void *src, size_t n) {
	return memcpy(dest, src, n) + n;
}

void maketag(const taginfo_t info, uint8_t key[KEYSIZE], uint8_t dest[MAX_TAG_SIZE], uint32_t *len) {
	uint8_t expiresat_b[8];
	u64tobe(info.expiresat_s, expiresat_b);

	const uint8_t zero[1] = { 0 };
	const size_t fullsize = strlen(info.authtype) +
		1 + strlen(info.repopath) +
		1 + strlen(info.operation) +
		1 + sizeof(expiresat_b);
	uint8_t *claimbuf = alloca(fullsize);
	uint8_t *head = claimbuf;
	head = memcat(head, info.authtype, strlen(info.authtype));
	head = memcat(head, zero, 1);
	head = memcat(head, info.repopath, strlen(info.repopath));
	head = memcat(head, zero, 1);
	head = memcat(head, info.operation, strlen(info.operation));
	head = memcat(head, zero, 1);
	head = memcat(head, expiresat_b, sizeof(expiresat_b));
	assert(head == claimbuf + fullsize);

	memset(dest, 0, MAX_TAG_SIZE);
	*len = 0;
	if (!HMAC(EVP_sha256(), key, KEYSIZE, claimbuf, fullsize, dest, len)) {
		OPENSSL_cleanse(key, KEYSIZE);
		die("Failed to generate tag");
	}
}

#define MAX_HEXTAG_STRLEN MAX_TAG_SIZE * 2

void makehextag(const taginfo_t info, uint8_t key[KEYSIZE], char dest[MAX_HEXTAG_STRLEN + 1]) {
	uint8_t rawtag[MAX_TAG_SIZE];
	uint32_t rawtag_len;
	maketag(info, key, rawtag, &rawtag_len);

	memset(dest, 0, MAX_HEXTAG_STRLEN + 1);
	for (size_t i = 0; i < rawtag_len; i++) {
		uint8_t b = rawtag[i];
		dest[i] = (b >> 4) + ((b >> 4) < 10 ? '0' : 'a');
		dest[i + 1] = (b & 0x0F) + ((b & 0x0F) < 10 ? '0' : 'a');
	}
}

int main(int argc, char *argv[]) {
	if (argc != 3) {
		puts(USAGE);
		exit(EXIT_FAILURE);
	}

	const char *repopath  = argv[1];
	const char *operation = argv[2];
	if (strcmp(operation, "download") && strcmp(operation, "upload")) {
		puts(USAGE);
		exit(EXIT_FAILURE);
	}
	checkrepopath(repopath);

	const char *hrefbase = getenv("GITOLFS3_HREF_BASE");
	const char *keypath = getenv("GITOLFS3_KEY_PATH");
	
	if (!hrefbase || strlen(hrefbase) == 0)
		die("Incomplete configuration: base URL not provided");
	if (hrefbase[strlen(hrefbase) - 1] != '/')
		die("Bad configuration: base URL should end with slash");
	if (!keypath || strlen(keypath) == 0)
		die("Incomplete configuration: key path not provided");

	uint8_t key[64];
	readkey(keypath, key);

	int64_t expiresin_s = 5 * 60;
	int64_t expiresat_s = (int64_t)time(NULL) + expiresin_s;

	taginfo_t taginfo = {
		.authtype    = "git-lfs-authenticate",
		.repopath    = repopath,
		.operation   = operation,
		.expiresat_s = expiresat_s,
	};
	char hextag[MAX_HEXTAG_STRLEN + 1];
	makehextag(taginfo, key, hextag);

	printf("{\"header\":{\"Authorization\":\"Gitolfs3-Hmac-Sha256 %s\"},\"expires_in\":%ld,\"href\":\"", hextag, expiresin_s);
	printescjson(hrefbase);
	printescjson(repopath);
	printf("/info/lfs?p=1&te=%ld\"}\n", expiresat_s);
}

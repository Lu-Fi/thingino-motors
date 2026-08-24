#ifndef MOTORS_SHA256_H
#define MOTORS_SHA256_H

#include <stddef.h>
#include <stdint.h>

/* Minimal SHA-256 (FIPS 180-4). Deliberately a separate translation unit from
 * sha1.c: this one IS on a security path (it hashes the /ws access token so
 * the plaintext secret never has to sit in the daemon's memory or be compared
 * byte-for-byte), sha1.c is not (it only proves a peer speaks WebSocket).
 * Keeping them apart means the answer to "is this hash load-bearing?" is
 * visible from the caller's #include line alone. See ws_token.c for why a
 * plain hash - and not a password KDF - is the right tool for this input. */

#define SHA256_DIGEST_LEN 32

typedef struct {
  uint32_t state[8];
  uint64_t bitlen;
  unsigned char buf[64];
  size_t buf_len;
} sha256_ctx;

void sha256_init(sha256_ctx *ctx);
void sha256_update(sha256_ctx *ctx, const unsigned char *data, size_t len);
void sha256_final(sha256_ctx *ctx, unsigned char digest[SHA256_DIGEST_LEN]);

/* one-shot convenience wrapper */
void sha256(const void *data, size_t len, unsigned char digest[SHA256_DIGEST_LEN]);

#endif /* MOTORS_SHA256_H */

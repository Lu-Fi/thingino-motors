#ifndef MOTORS_SHA1_H
#define MOTORS_SHA1_H

#include <stddef.h>
#include <stdint.h>

/* Minimal SHA-1 (RFC 3174). Used ONLY for the WebSocket handshake's
 * Sec-WebSocket-Accept computation (RFC 6455 section 1.3) - a non-adversarial
 * proof that the peer speaks WebSocket, not a security boundary. Never use
 * this for anything that actually needs collision resistance (passwords,
 * signatures, token storage) - for those see ws_token.h, which never hashes
 * with this. */

#ifdef MOTORS_WS_TLS
/* A TLS build links mbedcrypto, which already carries SHA-1; the functions
 * below are then thin wrappers over it and the hand-rolled rounds in sha1.c
 * are compiled out. The self-test builds without MOTORS_WS_TLS and keeps
 * checking the hand-rolled path. */
#include <mbedtls/sha1.h>
typedef mbedtls_sha1_context sha1_ctx;
#else
typedef struct {
  uint32_t state[5];
  uint64_t bitlen;
  unsigned char buf[64];
  size_t buf_len;
} sha1_ctx;
#endif

void sha1_init(sha1_ctx *ctx);
void sha1_update(sha1_ctx *ctx, const unsigned char *data, size_t len);
void sha1_final(sha1_ctx *ctx, unsigned char digest[20]);

#endif /* MOTORS_SHA1_H */

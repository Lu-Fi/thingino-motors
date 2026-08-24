/* Minimal SHA-256 (FIPS 180-4), used only by ws_token.c. See sha256.h for
 * why this lives apart from sha1.c. */

#include <string.h>

#include "sha256.h"

static const uint32_t K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu,
    0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u,
    0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u,
    0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u,
    0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
    0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
    0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u,
    0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u, 0x1e376c08u,
    0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu,
    0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u};

static uint32_t ror32(uint32_t v, int n) { return (v >> n) | (v << (32 - n)); }

#define BSIG0(x) (ror32(x, 2) ^ ror32(x, 13) ^ ror32(x, 22))
#define BSIG1(x) (ror32(x, 6) ^ ror32(x, 11) ^ ror32(x, 25))
#define SSIG0(x) (ror32(x, 7) ^ ror32(x, 18) ^ ((x) >> 3))
#define SSIG1(x) (ror32(x, 17) ^ ror32(x, 19) ^ ((x) >> 10))

static void sha256_block(sha256_ctx *ctx, const unsigned char block[64]) {
  uint32_t w[64];
  uint32_t a, b, c, d, e, f, g, h;
  int i;

  /* big-endian word assembly, same reasoning as sha1_block() */
  for (i = 0; i < 16; i++) {
    w[i] = ((uint32_t)block[i * 4] << 24) | ((uint32_t)block[i * 4 + 1] << 16) |
           ((uint32_t)block[i * 4 + 2] << 8) | ((uint32_t)block[i * 4 + 3]);
  }
  for (i = 16; i < 64; i++)
    w[i] = SSIG1(w[i - 2]) + w[i - 7] + SSIG0(w[i - 15]) + w[i - 16];

  a = ctx->state[0];
  b = ctx->state[1];
  c = ctx->state[2];
  d = ctx->state[3];
  e = ctx->state[4];
  f = ctx->state[5];
  g = ctx->state[6];
  h = ctx->state[7];

  for (i = 0; i < 64; i++) {
    uint32_t t1 = h + BSIG1(e) + ((e & f) ^ ((~e) & g)) + K[i] + w[i];
    uint32_t t2 = BSIG0(a) + ((a & b) ^ (a & c) ^ (b & c));
    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }

  ctx->state[0] += a;
  ctx->state[1] += b;
  ctx->state[2] += c;
  ctx->state[3] += d;
  ctx->state[4] += e;
  ctx->state[5] += f;
  ctx->state[6] += g;
  ctx->state[7] += h;
}

void sha256_init(sha256_ctx *ctx) {
  ctx->state[0] = 0x6a09e667u;
  ctx->state[1] = 0xbb67ae85u;
  ctx->state[2] = 0x3c6ef372u;
  ctx->state[3] = 0xa54ff53au;
  ctx->state[4] = 0x510e527fu;
  ctx->state[5] = 0x9b05688cu;
  ctx->state[6] = 0x1f83d9abu;
  ctx->state[7] = 0x5be0cd19u;
  ctx->bitlen = 0;
  ctx->buf_len = 0;
}

void sha256_update(sha256_ctx *ctx, const unsigned char *data, size_t len) {
  size_t i = 0;

  ctx->bitlen += (uint64_t)len * 8u;

  if (ctx->buf_len > 0) {
    size_t need = 64 - ctx->buf_len;
    size_t take = (len < need) ? len : need;
    memcpy(ctx->buf + ctx->buf_len, data, take);
    ctx->buf_len += take;
    i += take;
    if (ctx->buf_len == 64) {
      sha256_block(ctx, ctx->buf);
      ctx->buf_len = 0;
    }
  }

  for (; i + 64 <= len; i += 64)
    sha256_block(ctx, data + i);

  if (i < len) {
    memcpy(ctx->buf, data + i, len - i);
    ctx->buf_len = len - i;
  }
}

void sha256_final(sha256_ctx *ctx, unsigned char digest[SHA256_DIGEST_LEN]) {
  uint64_t bitlen = ctx->bitlen;
  int i;

  ctx->buf[ctx->buf_len++] = 0x80;
  if (ctx->buf_len > 56) {
    memset(ctx->buf + ctx->buf_len, 0, 64 - ctx->buf_len);
    sha256_block(ctx, ctx->buf);
    ctx->buf_len = 0;
  }
  memset(ctx->buf + ctx->buf_len, 0, 56 - ctx->buf_len);

  for (i = 0; i < 8; i++)
    ctx->buf[56 + i] = (unsigned char)(bitlen >> (56 - 8 * i));
  sha256_block(ctx, ctx->buf);

  for (i = 0; i < 8; i++) {
    digest[i * 4] = (unsigned char)(ctx->state[i] >> 24);
    digest[i * 4 + 1] = (unsigned char)(ctx->state[i] >> 16);
    digest[i * 4 + 2] = (unsigned char)(ctx->state[i] >> 8);
    digest[i * 4 + 3] = (unsigned char)(ctx->state[i]);
  }

  /* the context still holds up to 63 bytes of the token that was just
   * hashed - wipe it, that is half the point of hashing at all */
  memset(ctx, 0, sizeof(*ctx));
}

void sha256(const void *data, size_t len,
            unsigned char digest[SHA256_DIGEST_LEN]) {
  sha256_ctx ctx;
  sha256_init(&ctx);
  sha256_update(&ctx, (const unsigned char *)data, len);
  sha256_final(&ctx, digest);
}

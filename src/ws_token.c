/* /ws access token store. See ws_token.h for the model this follows. */

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "sha256.h"
#include "ws_token.h"

/* Only the DIGESTS live here, never the plaintext.
 *
 * Why hash at all, when both secrets are already high-entropy random strings
 * and this is not a password store:
 *
 *   1. Lifetime. motors-daemon runs as root for the life of the camera. A
 *      persistent motors.ws_token sits in its address space for months. Any
 *      accidental disclosure of that memory - a core dump landing in /tmp, a
 *      /proc/<pid>/mem read by another root tool, a future debug dump that
 *      prints a config struct - hands over a credential that still works.
 *      A SHA-256 digest discloses nothing reusable.
 *   2. Comparison shape. Comparing two variable-length plaintexts in
 *      constant time is subtly awkward: the loop bound is min(la, lb), so
 *      the timing leaks the length of the secret even when the content
 *      comparison is branch-free (timps's auth_token_eq() has exactly this
 *      property and accepts it). Comparing two fixed 32-byte digests removes
 *      the question entirely - every comparison executes identical work
 *      regardless of what the client sent.
 *
 * Why a plain hash and NOT a password KDF (PBKDF2/scrypt/argon2): those exist
 * to slow down guessing of LOW-entropy inputs. Both credentials here are
 * 128-bit random values, so offline guessing is not the threat, and the
 * digest is never written to disk where an attacker could grind it. A KDF
 * would only buy per-connection CPU burn on a 1 GHz MIPS core that is also
 * encoding video. Likewise no salt: there is no password-reuse story to
 * protect and no rainbow table for 128-bit random hex.
 *
 * The handshake's SHA-1 (sha1.c) is never used for any of this. */
static struct {
  bool have_boot;
  unsigned char boot_hash[SHA256_DIGEST_LEN];
  bool have_persistent;
  unsigned char persistent_hash[SHA256_DIGEST_LEN];
} g_tok;

static void hex_encode(const unsigned char *in, size_t len, char *out) {
  static const char hx[] = "0123456789abcdef";
  for (size_t i = 0; i < len; i++) {
    out[i * 2] = hx[in[i] >> 4];
    out[i * 2 + 1] = hx[in[i] & 0x0F];
  }
  out[len * 2] = '\0';
}

/* Fill out[WS_TOKEN_HEX_LEN + 1] with a fresh hex-encoded 128-bit token.
 * Returns false if no acceptable entropy source was available - and in that
 * case the caller must NOT fall back to a weak token. timps degrades to an
 * md5 of time/pid here; this daemon does not, because a motor listener with a
 * guessable token is strictly worse than a motor listener with no per-boot
 * token at all (the operator then has to configure a persistent secret, and
 * the failure is loud in syslog instead of silent). */
static bool gen_token_hex(char *out) {
  unsigned char rnd[WS_TOKEN_HEX_LEN / 2];
  size_t got = 0;
  int fd = open("/dev/urandom", O_RDONLY);

  if (fd < 0)
    return false;

  while (got < sizeof(rnd)) {
    ssize_t r = read(fd, rnd + got, sizeof(rnd) - got);
    if (r <= 0)
      break;
    got += (size_t)r;
  }
  close(fd);

  if (got != sizeof(rnd))
    return false;

  hex_encode(rnd, sizeof(rnd), out);
  memset(rnd, 0, sizeof(rnd));
  return true;
}

static bool publish_token_file(const char *path, const char *token) {
  /* 0640 and root-owned: readable by whatever group the web/CGI layer runs
   * as, never world-readable. O_TRUNC because a stale longer token from a
   * previous boot must not be left dangling past the new one. */
  int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0640);
  size_t len;

  if (fd < 0) {
    syslog(LOG_WARNING, "ws: cannot write token file %s", path);
    return false;
  }

  len = strlen(token);
  if (write(fd, token, len) != (ssize_t)len || write(fd, "\n", 1) != 1) {
    syslog(LOG_WARNING, "ws: short write on token file %s", path);
    close(fd);
    return false;
  }
  close(fd);
  return true;
}

bool ws_token_init(const char *persistent, const char *token_file) {
  char boot[WS_TOKEN_HEX_LEN + 1];

  memset(&g_tok, 0, sizeof(g_tok));

  if (persistent && *persistent) {
    sha256(persistent, strlen(persistent), g_tok.persistent_hash);
    g_tok.have_persistent = true;
    syslog(LOG_INFO, "ws: persistent token from motors.ws_token accepted");
  }

  if (gen_token_hex(boot)) {
    sha256(boot, strlen(boot), g_tok.boot_hash);
    g_tok.have_boot = true;

    if (token_file && *token_file) {
      if (publish_token_file(token_file, boot))
        syslog(LOG_INFO, "ws: per-boot token published to %s", token_file);
      else
        syslog(LOG_WARNING,
               "ws: per-boot token generated but could not be published; "
               "only motors.ws_token (if set) or loopback can authenticate");
    } else {
      syslog(LOG_INFO,
             "ws: token file disabled; per-boot token is unreachable, "
             "authenticate with motors.ws_token or from loopback");
    }

    /* The plaintext has served its only purpose (being written to the file).
     * From here on the daemon holds a digest and nothing else. */
    memset(boot, 0, sizeof(boot));
  } else {
    syslog(LOG_ERR,
           "ws: /dev/urandom unavailable, refusing to mint a weak per-boot "
           "token; the listener will only accept motors.ws_token or loopback");
  }

  return g_tok.have_boot || g_tok.have_persistent;
}

/* Branch-free digest comparison. Returns true on equality without an early
 * exit on the first differing byte, so the time taken carries no information
 * about how much of the digest matched. */
static bool digest_eq(const unsigned char *a, const unsigned char *b) {
  unsigned char diff = 0;
  for (size_t i = 0; i < SHA256_DIGEST_LEN; i++)
    diff |= (unsigned char)(a[i] ^ b[i]);
  return diff == 0;
}

bool ws_token_check(const char *presented) {
  unsigned char h[SHA256_DIGEST_LEN];
  bool ok = false;

  if (!presented || !*presented)
    return false;

  sha256(presented, strlen(presented), h);

  /* Both candidates are always evaluated (|=, not ||): short-circuiting
   * would make "matched the boot token" measurably faster than "matched the
   * persistent one", which is a small but free-to-avoid oracle. */
  if (g_tok.have_boot)
    ok |= digest_eq(h, g_tok.boot_hash);
  if (g_tok.have_persistent)
    ok |= digest_eq(h, g_tok.persistent_hash);

  memset(h, 0, sizeof(h));
  return ok;
}

bool ws_addr_is_loopback(unsigned int addr_host_order) {
  /* 127.0.0.0/8, matching timps's httpd.c check byte for byte. */
  return (addr_host_order & 0xFF000000u) == 0x7F000000u;
}

/* mbedTLS server wrapper for the WebSocket listener. See ws_tls.h. */

#ifdef MOTORS_WS_TLS

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/pk.h>
#include <mbedtls/ssl.h>
#include <mbedtls/version.h>
#include <mbedtls/x509_crt.h>

#include "ws.h"
#include "ws_tls.h"

/* One ws_tls_ctx holds ONE mbedtls_ctr_drbg_context, seeded once. Every
 * accepted connection then draws from that same DRBG from its own thread
 * (handshake, key exchange, and mbedtls_pk_parse_keyfile on mbedTLS 3.x).
 * mbedTLS only serialises its internal state when it is built with
 * MBEDTLS_THREADING_C; without it, concurrent handshakes race on the very
 * state that is supposed to produce unpredictable output, and do so silently.
 * There is no runtime check for this, so fail the BUILD rather than ship a TLS
 * server that is unsafe under exactly the load it exists for.
 *
 * <mbedtls/version.h> above already pulls in the config (mbedtls/config.h on
 * 2.x, mbedtls/build_info.h on 3.x), so the macro is visible either way -
 * including build_info.h directly would break 2.x, which the version guards
 * below still support. Same guard, same reasoning as timps's src/tls.c. */
#if !defined(MBEDTLS_THREADING_C)
#error "MOTORS_WS_TLS needs an mbedTLS built with MBEDTLS_THREADING_C: one CTR_DRBG is shared across all connection threads and mbedTLS will not lock it otherwise. Rebuild mbedTLS with MBEDTLS_THREADING_C (plus MBEDTLS_THREADING_PTHREAD), or turn off BR2_PACKAGE_THINGINO_MOTORS_WS_TLS."
#endif

struct ws_tls_ctx {
  mbedtls_ssl_config conf;
  mbedtls_x509_crt cert;
  mbedtls_pk_context key;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context drbg;
};

struct ws_tls_conn {
  mbedtls_ssl_context ssl;
  mbedtls_net_context net;
};

/* Session tickets are deliberately NOT wired up, unlike timps's tls.c.
 *
 * timps resumes constantly - the WebUI preview reopens /stream.mp4 and /events
 * on every page load and every reconnect, so skipping a full handshake there is
 * a real saving. This listener is the opposite shape: a PTZ panel opens ONE
 * connection and holds it for the life of the page. Resumption would save at
 * most one handshake per page load, in exchange for an
 * mbedtls_ssl_ticket_context (a live AES key plus its rotation timer) sitting
 * in a 64 MB device's RAM for the daemon's entire uptime, and a
 * not-forward-secret resumption path to reason about. Not worth it here. */

ws_tls_ctx *ws_tls_ctx_new(const char *cert_file, const char *key_file) {
  ws_tls_ctx *c = calloc(1, sizeof(*c));
  const char *pers = "motors-ws-tls";

  if (!c)
    return NULL;

  mbedtls_ssl_config_init(&c->conf);
  mbedtls_x509_crt_init(&c->cert);
  mbedtls_pk_init(&c->key);
  mbedtls_entropy_init(&c->entropy);
  mbedtls_ctr_drbg_init(&c->drbg);

  if (mbedtls_ctr_drbg_seed(&c->drbg, mbedtls_entropy_func, &c->entropy,
                            (const unsigned char *)pers, strlen(pers)) != 0) {
    syslog(LOG_ERR, "ws: TLS entropy seed failed");
    goto fail;
  }
  if (mbedtls_x509_crt_parse_file(&c->cert, cert_file) != 0) {
    syslog(LOG_ERR, "ws: cannot parse TLS certificate %s", cert_file);
    goto fail;
  }
#if MBEDTLS_VERSION_MAJOR >= 3
  if (mbedtls_pk_parse_keyfile(&c->key, key_file, NULL, mbedtls_ctr_drbg_random,
                               &c->drbg) != 0)
#else
  if (mbedtls_pk_parse_keyfile(&c->key, key_file, NULL) != 0)
#endif
  {
    syslog(LOG_ERR, "ws: cannot parse TLS key %s", key_file);
    goto fail;
  }
  if (mbedtls_ssl_config_defaults(&c->conf, MBEDTLS_SSL_IS_SERVER,
                                  MBEDTLS_SSL_TRANSPORT_STREAM,
                                  MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
    syslog(LOG_ERR, "ws: TLS config defaults failed");
    goto fail;
  }
#if MBEDTLS_VERSION_MAJOR < 3
  /* 2.x's PRESET_DEFAULT still negotiates TLS 1.0/1.1 - require 1.2. 3.x
   * already defaults to >= 1.2 and dropped this API in 3.2+. */
  mbedtls_ssl_conf_min_version(&c->conf, MBEDTLS_SSL_MAJOR_VERSION_3,
                               MBEDTLS_SSL_MINOR_VERSION_3);
#endif
  mbedtls_ssl_conf_rng(&c->conf, mbedtls_ctr_drbg_random, &c->drbg);
  if (mbedtls_ssl_conf_own_cert(&c->conf, &c->cert, &c->key) != 0) {
    syslog(LOG_ERR, "ws: TLS cert/key pair rejected (%s / %s)", cert_file,
           key_file);
    goto fail;
  }

  return c;
fail:
  ws_tls_ctx_free(c);
  return NULL;
}

void ws_tls_ctx_free(ws_tls_ctx *c) {
  if (!c)
    return;
  mbedtls_ssl_config_free(&c->conf);
  mbedtls_x509_crt_free(&c->cert);
  mbedtls_pk_free(&c->key);
  mbedtls_ctr_drbg_free(&c->drbg);
  mbedtls_entropy_free(&c->entropy);
  free(c);
}

/* Handshake failures that are NOT plain peer noise are the only runtime
 * evidence of a broken TLS setup (a cert clients reject, a config mismatch),
 * so the shipped log level must see them - but rate-limited, because a scanner
 * hammering a broken listener must not flood a 64 KB syslog ring. Lifted from
 * timps's hs_fail_warn() for the same reason it exists there. */
static void hs_fail_warn(int r) {
  static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;
  static time_t t_last;
  static unsigned muted;

  pthread_mutex_lock(&mtx);
  {
    time_t now = time(NULL);
    if (!t_last || now - t_last >= 60) {
      syslog(LOG_WARNING,
             "ws: TLS handshake failed (-0x%x, %u more suppressed) - rejected/"
             "expired certificate or a TLS config problem?",
             -r, muted);
      t_last = now;
      muted = 0;
    } else {
      muted++;
    }
  }
  pthread_mutex_unlock(&mtx);
}

static bool set_nonblock(int fd) {
  int fl = fcntl(fd, F_GETFL, 0);
  if (fl < 0)
    return false;
  return fcntl(fd, F_SETFL, fl | O_NONBLOCK) == 0;
}

ws_tls_conn *ws_tls_accept(ws_tls_ctx *ctx, int fd, int timeout_ms) {
  ws_tls_conn *c;
  long long deadline;
  int r;

  if (!ctx)
    return NULL;

  /* Non-blocking BEFORE mbedtls_ssl_setup(), so the very first record read is
   * already governed by the deadline below. mbedtls_net_recv() only reports
   * WANT_READ when the fd actually carries O_NONBLOCK (it checks with
   * F_GETFL), which is exactly why this cannot be deferred until after the
   * handshake. */
  if (!set_nonblock(fd))
    return NULL;

  c = calloc(1, sizeof(*c));
  if (!c)
    return NULL;

  mbedtls_ssl_init(&c->ssl);
  mbedtls_net_init(&c->net);
  c->net.fd = fd;

  if (mbedtls_ssl_setup(&c->ssl, &ctx->conf) != 0)
    goto fail;
  mbedtls_ssl_set_bio(&c->ssl, &c->net, mbedtls_net_send, mbedtls_net_recv,
                      NULL);

  /* Bound the whole handshake, not each read. A client that opens a socket,
   * sends one ClientHello byte and stops must not park this connection thread
   * forever - the same slow-loris shape ws.c's read_exact() already defends
   * the plaintext handshake against, and the reason this loop polls by hand
   * rather than leaning on SO_RCVTIMEO. */
  deadline = ws_now_ms() + timeout_ms;
  while ((r = mbedtls_ssl_handshake(&c->ssl)) != 0) {
    short events;
    int left;

    if (r == MBEDTLS_ERR_SSL_WANT_READ)
      events = POLLIN;
    else if (r == MBEDTLS_ERR_SSL_WANT_WRITE)
      events = POLLOUT;
    else {
      /* Peer noise - dead, mute or garbage-speaking connections: scanners,
       * timeouts, resets, and a plain-HTTP client that reached the TLS path by
       * mistake - stays on DEBUG. Everything else, which is where the
       * cert/config error classes live, goes to hs_fail_warn(). The #ifdefs
       * keep this building across 2.x/3.x, where some error macros were
       * pruned. */
      if (r == MBEDTLS_ERR_SSL_CONN_EOF ||
          r == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY ||
          r == MBEDTLS_ERR_NET_CONN_RESET ||
#ifdef MBEDTLS_ERR_SSL_INVALID_RECORD
          r == MBEDTLS_ERR_SSL_INVALID_RECORD ||
#endif
#ifdef MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE
          r == MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE ||
#endif
          r == MBEDTLS_ERR_NET_RECV_FAILED)
        syslog(LOG_DEBUG, "ws: TLS handshake failed (-0x%x)", -r);
      else
        hs_fail_warn(r);
      goto fail;
    }

    left = (int)(deadline - ws_now_ms());
    if (left <= 0) {
      syslog(LOG_DEBUG, "ws: TLS handshake timed out");
      goto fail;
    }
    {
      struct pollfd p = {.fd = fd, .events = events, .revents = 0};
      int pr;
      do {
        pr = poll(&p, 1, left);
      } while (pr < 0 && errno == EINTR);
      if (pr <= 0)
        goto fail; /* timeout or poll error - either way, give up */
      if (p.revents & (POLLERR | POLLNVAL))
        goto fail;
    }
  }

  return c;
fail:
  mbedtls_ssl_free(&c->ssl);
  free(c);
  return NULL;
}

/* mbedTLS's WANT_READ/WANT_WRITE both mean "call me again once the socket has
 * moved"; ws.c's loops only understand EAGAIN, and they poll for both
 * directions on a write, so collapsing the two here loses nothing. */
static ssize_t want_more(void) {
  errno = EAGAIN;
  return -1;
}

ssize_t ws_tls_read(ws_tls_conn *c, void *buf, size_t n) {
  int r = mbedtls_ssl_read(&c->ssl, (unsigned char *)buf, n);

  if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE)
    return want_more();
  /* close_notify is an orderly shutdown, which read() spells as 0 - not as an
   * error. ws.c turns that into WS_CLOSED, the same as a plain-socket EOF. */
  if (r == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
    return 0;
  if (r < 0) {
    errno = EIO;
    return -1;
  }
  return (ssize_t)r;
}

ssize_t ws_tls_write(ws_tls_conn *c, const void *buf, size_t n) {
  int r = mbedtls_ssl_write(&c->ssl, (const unsigned char *)buf, n);

  if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE)
    return want_more();
  if (r < 0) {
    errno = EIO;
    return -1;
  }
  /* A short write is legal and normal here (mbedTLS caps a write at one
   * record); ws.c's write_all() loops on the remainder. */
  return (ssize_t)r;
}

int ws_tls_pending(const ws_tls_conn *c) {
  /* Casting away const: mbedtls_ssl_get_bytes_avail() takes a non-const
   * pointer even though it only reads. Keeping ws_tls_pending() const is worth
   * the cast - it lets ws.c's io_pending() take a const ws_io *, which is what
   * documents that a liveness peek cannot disturb the session. */
  return (int)mbedtls_ssl_get_bytes_avail((mbedtls_ssl_context *)&c->ssl);
}

void ws_tls_close(ws_tls_conn *c) {
  if (!c)
    return;
  /* Best effort: the peer is often already gone, and on a non-blocking socket
   * this can legitimately return WANT_WRITE. Neither is worth another poll
   * loop at teardown - the fd is closed immediately afterwards regardless. */
  mbedtls_ssl_close_notify(&c->ssl);
  mbedtls_ssl_free(&c->ssl);
  free(c);
}

#endif /* MOTORS_WS_TLS */

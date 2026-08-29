#ifndef MOTORS_WS_TLS_H
#define MOTORS_WS_TLS_H

#include <stddef.h>
#include <sys/types.h>

/* mbedTLS server wrapper for the WebSocket listener - the wss:// half of
 * ws.c's ws_io seam. Only compiled when MOTORS_WS_TLS is defined.
 *
 * Scope on purpose: this file does TLS and nothing else. It does not accept
 * sockets, does not decide which connections should be encrypted, and does not
 * know what a WebSocket is. motor-ws.c owns those decisions; ws.c owns the
 * protocol. That keeps the new dependency confined to one translation unit, so
 * a build without BR2_PACKAGE_THINGINO_MOTORS_WS_TLS links no TLS at all
 * rather than linking it and not using it.
 *
 * Modelled on the sibling timps project's src/tls.c, which solves the same
 * problem for the same firmware family against the same mbedTLS: same
 * config_defaults + own_cert shape, same 2.x/3.x version guards, same
 * rate-limited handshake-failure logging. The differences are deliberate and
 * noted at each site in ws_tls.c - chiefly that this one drives the handshake
 * with poll() on a non-blocking socket instead of SO_RCVTIMEO on a blocking
 * one, because ws.c's whole I/O model is already poll-with-a-deadline. */

typedef struct ws_tls_ctx ws_tls_ctx;
typedef struct ws_tls_conn ws_tls_conn;

/* Load a certificate/key pair and build the shared server config. Returns NULL
 * on any failure (unreadable/malformed cert, mismatched key, no entropy), in
 * which case the caller is expected to carry on WITHOUT TLS rather than refuse
 * to start - a camera whose cert is missing must still serve plain ws://.
 *
 * One context is shared by every connection thread; see the MBEDTLS_THREADING_C
 * requirement enforced at the top of ws_tls.c. */
ws_tls_ctx *ws_tls_ctx_new(const char *cert_file, const char *key_file);
void ws_tls_ctx_free(ws_tls_ctx *ctx);

/* Run the TLS handshake on an already-accepted socket, bounded by
 * timeout_ms in total (not per read).
 *
 * On success returns a session handle and leaves `fd` in NON-BLOCKING mode,
 * which is what lets ws.c's poll-then-read loop keep its deadline instead of
 * blocking inside mbedTLS. On failure returns NULL and leaves the socket alone
 * - it is the caller's to close either way. */
ws_tls_conn *ws_tls_accept(ws_tls_ctx *ctx, int fd, int timeout_ms);

/* POSIX-shaped I/O, so ws.c's existing error handling covers both transports
 * unchanged (see the transport seam comment in ws.c):
 *   >0  bytes moved
 *    0  read only: the peer closed cleanly
 *   -1  errno set. EAGAIN means "no progress yet, poll and call again" and
 *       covers mbedTLS's WANT_READ *and* WANT_WRITE - a write can need to read
 *       and vice versa, so the caller must poll for both directions. */
ssize_t ws_tls_read(ws_tls_conn *c, void *buf, size_t n);
ssize_t ws_tls_write(ws_tls_conn *c, const void *buf, size_t n);

/* Bytes already decrypted into mbedTLS's own buffer. poll() on the raw fd
 * cannot see them, so any poll-driven read loop has to check this first or it
 * will sleep on data it is already holding. */
int ws_tls_pending(const ws_tls_conn *c);

/* Sends close_notify (best effort) and frees the session. Does NOT close the
 * fd; the caller owns that. */
void ws_tls_close(ws_tls_conn *c);

#endif /* MOTORS_WS_TLS_H */

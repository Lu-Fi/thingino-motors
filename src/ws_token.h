#ifndef MOTORS_WS_TOKEN_H
#define MOTORS_WS_TOKEN_H

#include <stdbool.h>

/* Access control for the /ws listener.
 *
 * Modelled directly on the timps project's /control auth (src/auth.c,
 * src/mp4/httpd.c there), because the deployment shape is the same - a root
 * daemon on a camera whose only realistic trust boundary is the LAN - and
 * inventing a second scheme for the same problem in the same firmware would
 * be worse than copying a working one:
 *
 *   - a per-boot random token, generated from /dev/urandom at startup and
 *     published to a mode-0640 file so on-device readers (the CGI layer,
 *     shell tooling) can hand it to whoever needs it;
 *   - an OPTIONAL persistent secret from the config file, for remote
 *     automation that cannot re-read a per-boot file;
 *   - accepted as an "X-Motors-Token:" request header OR a "?token=" query
 *     parameter. The query form is not redundant: the browser's WebSocket
 *     constructor cannot set request headers on the opening handshake (same
 *     limitation that forces timps to accept ?token= for EventSource and
 *     <img src>), so for the primary use case the query form is the ONLY
 *     form available.
 *
 * Where this deliberately differs from timps: the plaintext token is not
 * kept. See ws_token_check() for why.
 *
 * NOT a password database. There is one principal ("whoever may drive the
 * motors"), no usernames, no per-user state. */

/* 128 bits, hex-encoded: 32 chars + NUL. Same size as timps's g_ctl_token so
 * the two are interchangeable to a human reading a token file. */
#define WS_TOKEN_HEX_LEN 32

/* Initialise the token store.
 *
 * persistent   optional secret from motors.ws_token in /etc/thingino.json;
 *              NULL or "" disables it. Hashed and then wiped from this
 *              function's view - the caller must wipe its own copy.
 * token_file   where to publish the per-boot token (mode 0640); NULL or ""
 *              disables publication, in which case the per-boot token is
 *              generated but nothing on the device can learn it, which is
 *              only useful if a persistent secret is configured.
 *
 * Returns true if at least one credential is usable. */
bool ws_token_init(const char *persistent, const char *token_file);

/* Constant-time check of a presented token against every configured
 * credential. Returns true on match. Safe to call from several connection
 * threads at once: the store is written once at startup and read-only after.
 */
bool ws_token_check(const char *presented);

/* True when a 32-bit IPv4 address in HOST byte order is in 127.0.0.0/8. */
bool ws_addr_is_loopback(unsigned int addr_host_order);

#endif /* MOTORS_WS_TOKEN_H */

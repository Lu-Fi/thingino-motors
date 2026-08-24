#ifndef MOTORS_WS_H
#define MOTORS_WS_H

#include <stdbool.h>
#include <stddef.h>

/* Generic RFC 6455 WebSocket server mechanics: HTTP-Upgrade handshake,
 * frame read/write, masking, control frames.
 *
 * Deliberately knows NOTHING about motors, tokens or JSON. Everything that
 * is policy (which Origins are acceptable, which token unlocks the socket,
 * what the messages mean) lives in motor-ws.c; everything that is protocol
 * lives here. The split exists so a second daemon in this project family can
 * take ws.c/ws.h verbatim - there is no library to share, so the seam has to
 * carry that weight instead.
 *
 * No TLS. See ws_listen_start() in motor-ws.c for where a wss:// listener
 * would have to sit if anyone adds one. */

/* Frame payload cap.
 *
 * Every command this protocol accepts is a short fixed-shape JSON object
 * (see motor-ws.c); 2 KiB is already an order of magnitude of headroom. The
 * cap is what stops a client from making the daemon allocate - the receive
 * buffer is a fixed member of ws_conn, never a malloc driven by the peer's
 * declared length, so an absurd 64-bit length header costs a close frame
 * rather than an OOM on a 64 MB camera. */
#define WS_MAX_PAYLOAD 2048

/* HTTP request head cap for the handshake. Long enough for a real browser's
 * upgrade request (Origin + Cookie + User-Agent + Sec-*), short enough that a
 * client that never sends the blank line cannot grow the daemon's memory. */
#define WS_MAX_HANDSHAKE 3072

/* opcodes (RFC 6455 section 5.2) */
#define WS_OP_CONT 0x0
#define WS_OP_TEXT 0x1
#define WS_OP_BIN 0x2
#define WS_OP_CLOSE 0x8
#define WS_OP_PING 0x9
#define WS_OP_PONG 0xA

/* close codes (RFC 6455 section 7.4.1) used by this implementation */
#define WS_CLOSE_NORMAL 1000
#define WS_CLOSE_GOING_AWAY 1001
#define WS_CLOSE_PROTOCOL 1002
#define WS_CLOSE_UNSUPPORTED 1003
#define WS_CLOSE_POLICY 1008
#define WS_CLOSE_TOO_BIG 1009
#define WS_CLOSE_INTERNAL 1011

/* return codes; negative values are all terminal for the connection */
#define WS_OK 0
#define WS_AGAIN 1     /* timeout expired with no complete frame */
#define WS_CLOSED (-1) /* peer sent CLOSE, or EOF */
#define WS_EPROTO (-2) /* framing violation -> close 1002 */
#define WS_ETOOBIG (-3)/* payload over WS_MAX_PAYLOAD -> close 1009 */
#define WS_EIO (-4)    /* socket error/timeout on a partial frame */

/* Parsed handshake request. All strings are NUL-terminated and truncated to
 * the buffer size rather than overflowing; a truncated value simply fails to
 * match an allow-list entry, which is the safe direction. */
typedef struct {
  char method[8];
  char path[64];   /* request target with the query string stripped */
  char query[256]; /* everything after '?', or "" */
  char host[128];  /* Host: header value, port included if the client sent one */
  char origin[192];/* Origin: header value, or "" when the client sent none */
  char key[64];    /* Sec-WebSocket-Key: header value */
  int version;     /* Sec-WebSocket-Version:, -1 if absent/unparsable */
  bool has_upgrade_websocket;
  bool has_connection_upgrade;
  bool has_origin; /* distinguishes "Origin: " (empty) from no Origin at all */
  /* The raw request head, retained so callers can read headers this struct
   * does not model (ws_header() below). Keeping the bytes rather than adding
   * named fields for every application-specific header is what lets this
   * layer stay free of motors-specific knowledge. */
  char head[WS_MAX_HANDSHAKE + 1];
  size_t head_len;
} ws_handshake;

/* Read an arbitrary header value out of a parsed handshake. name is given
 * WITHOUT the colon; matching is case-insensitive and anchored at a line
 * start, so a value can never impersonate a header name. Returns true when
 * found; out is always NUL-terminated. */
bool ws_header(const ws_handshake *hs, const char *name, char *out, size_t cap);

typedef struct {
  int fd;
  /* Reassembly buffer for fragmented messages (RFC 6455 section 5.4). Fixed
   * size, so a fragment sequence that would exceed WS_MAX_PAYLOAD in total is
   * rejected with WS_ETOOBIG instead of growing without bound - the classic
   * way a naive WebSocket server is turned into a memory bomb. */
  unsigned char frag[WS_MAX_PAYLOAD];
  size_t frag_len;
  int frag_op; /* opcode of the message being reassembled, 0 when idle */
} ws_conn;

void ws_conn_init(ws_conn *c, int fd);

/* --- handshake --- */

/* Read and parse the HTTP request head (up to the blank line). Returns WS_OK,
 * WS_ETOOBIG (head over WS_MAX_HANDSHAKE), WS_EPROTO (malformed request line)
 * or WS_EIO/WS_CLOSED. Does not validate Origin or any credential: that is
 * policy, and policy lives in the caller. */
int ws_handshake_read(int fd, ws_handshake *hs, int timeout_ms);

/* True if hs is a structurally valid RFC 6455 version-13 upgrade request
 * (GET, Upgrade: websocket, Connection: ...upgrade..., a Sec-WebSocket-Key,
 * version 13). Says nothing about whether it should be ALLOWED. */
bool ws_handshake_is_upgrade(const ws_handshake *hs);

/* Compute the Sec-WebSocket-Accept value for a Sec-WebSocket-Key:
 *   base64(SHA1(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
 * out must hold at least 29 bytes (28 base64 chars + NUL). Exposed mainly so
 * the self-test can check the RFC 6455 section 1.3 vector. */
void ws_accept_key(const char *key, char out[29]);

/* Send the 101 response. subproto may be NULL. */
int ws_handshake_accept(int fd, const ws_handshake *hs, const char *subproto);

/* Send a plain HTTP error response and nothing else - used for every refusal
 * before the upgrade completes (bad origin, missing token, too many clients).
 * The body is a fixed string; nothing from the request is ever reflected, so
 * this cannot become a reflected-XSS or header-injection surface. */
int ws_handshake_reject(int fd, int status, const char *status_text,
                        const char *body);

/* --- frames --- */

/* Read one complete (possibly reassembled) data message.
 *
 * Control frames are handled internally: PING is answered with PONG, PONG is
 * swallowed, CLOSE returns WS_CLOSED. The function therefore only ever hands
 * back TEXT or BIN, and the caller never has to think about the control
 * plane. timeout_ms bounds the total wait; WS_AGAIN means "nothing arrived",
 * which is the caller's cue to do its periodic work (status push, keepalive).
 */
int ws_read_message(ws_conn *c, int *opcode, unsigned char *out, size_t cap,
                    size_t *out_len, int timeout_ms);

/* Send an unmasked server frame (RFC 6455 section 5.1: the server MUST NOT
 * mask). Returns WS_OK or WS_EIO. */
int ws_send_frame(int fd, int opcode, const void *payload, size_t len);
int ws_send_text(int fd, const char *text);
int ws_send_ping(int fd);
int ws_send_close(int fd, int code, const char *reason);

/* --- base64 --- */

/* Standard base64 with padding. Returns the number of characters written
 * (excluding the NUL). out must hold 4*((len+2)/3)+1 bytes. Hand-rolled
 * because the handshake needs exactly one 20-byte encode and pulling in a
 * dependency for that would be absurd. */
size_t ws_base64_encode(const unsigned char *in, size_t len, char *out);

/* Extract a query-string parameter value ("name=value&..."). Returns true and
 * fills out (NUL-terminated, truncated to cap) when found. URL-decodes %XX
 * and '+'; a malformed escape is copied through literally rather than
 * consuming the terminator. */
bool ws_query_param(const char *query, const char *name, char *out, size_t cap);

#endif /* MOTORS_WS_H */

/* WebSocket frontend for motors-daemon: listener, access control, and the
 * JSON command protocol. Protocol mechanics live in ws.c; the motor
 * operations themselves live in motor-daemon.c behind motor-ctl.h. */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>

#include <json_config.h>

#include "motor-ctl.h"
#include "motor-ws.h"
#include "ws.h"
#include "ws_token.h"

#ifdef MOTORS_WS_TLS
#include "ws_tls.h"
#endif

/* The only request target that upgrades. Anything else gets a 404, so the
 * port does not double as an accidental generic endpoint. */
#define WS_PATH "/ws"

/* Time a client gets to complete its HTTP upgrade before the worker thread
 * is reclaimed. A connection that opens the socket and then says nothing is
 * the cheapest possible DoS against a thread-per-connection server; this is
 * the bound that makes it pointless. */
#define WS_HANDSHAKE_TIMEOUT_MS 5000

/* Keepalive PING cadence. Also serves as the wakeup that notices a peer whose
 * socket has died without a FIN - the send fails and the thread exits. */
#define WS_PING_INTERVAL_MS 20000

/* Liveness deadline: close a connection that has not sent ANY frame for this
 * long. ws_read_message() stamps ws_conn.last_rx_ms on every complete frame,
 * so a browser answering our PINGs automatically (all of them do) keeps
 * itself alive for free, and a client that cannot emit a PONG can keep itself
 * alive just by sending {"cmd":"ping"} occasionally.
 *
 * Why three ping intervals (60 s) rather than one or two:
 *
 *  - One interval is a race, not a timeout. The check only runs when the read
 *    loop wakes, which is every push_ms (50..5000 ms) or every 1000 ms when
 *    the client has not subscribed, so the effective granularity is up to 5 s
 *    on top of a 20 s budget. Three intervals leaves room for that jitter
 *    plus two entirely lost PING/PONG round trips.
 *
 *  - These are WiFi cameras. A re-association or an AP roam routinely eats
 *    10-30 s of a TCP connection that then recovers perfectly well. Tearing
 *    down a PTZ control socket during a hiccup it would have survived is a
 *    worse failure than holding a dead one for another 20 s: a stale
 *    connection costs one of ws_max_clients (4) slots and one 64 KB thread
 *    stack, and nothing else - it issues no commands and moves no motors.
 *    So the bias is deliberately toward forgiving.
 *
 *  - Something has to reclaim the slot, though, and the OS will not do it in
 *    any useful time. SO_KEEPALIVE is set on these sockets, but with stock
 *    Linux sysctls that is tcp_keepalive_time (7200 s) + 9 x 75 s before the
 *    kernel gives up - over two hours, during which a laptop that closed its
 *    lid mid-session holds a quarter of the connection budget. Closing the
 *    gap between "two hours" and "instantly" is the entire job of this
 *    constant, and 60 s sits comfortably inside it. */
#define WS_LIVENESS_TIMEOUT_MS (3 * WS_PING_INTERVAL_MS)

/* Even a client that subscribed to pushes gets a status frame at least this
 * often while idle, so a UI that missed one update self-heals. */
#define WS_HEARTBEAT_MS 5000

/* Bounds on the wire values. Both are absurdly generous relative to real
 * hardware (pan travel is ~4000 steps, tilt ~2000) and exist purely so that
 * nothing pathological reaches the arithmetic in motor_ctl_*: a delta of
 * INT_MIN would overflow the `motor_message.x + rel_x` in
 * motor_ctl_relative() before any clamp could see it. The handlers clamp
 * again to the real travel limits; this is the outer guard, not the only
 * one. */
#define WS_MAX_ABS_POS 100000
#define WS_MAX_REL_DELTA 100000

/* Rate limiter strike budget: once a connection has been throttled this many
 * times it is closed rather than argued with. A UI holding a button produces
 * ~11 commands/s and will never see a single strike. */
#define WS_MAX_STRIKES 50

/* Time a TLS peer gets to complete the cryptographic handshake, before the
 * HTTP one even starts. Separate from WS_HANDSHAKE_TIMEOUT_MS and larger,
 * because this budget covers an RSA/ECDHE key exchange on a ~1 GHz MIPS core
 * with no crypto accelerator plus one or two client round trips - measured at
 * a few hundred ms on real hardware, but a phone on weak WiFi is not that. */
#define WS_TLS_HANDSHAKE_TIMEOUT_MS 15000

static motor_ws_cfg g_cfg;

#ifdef MOTORS_WS_TLS
/* NULL when TLS is off, unavailable, or no certificate could be loaded. Set
 * once in motor_ws_start() before the listener thread exists and never written
 * again, so the connection threads read it without a lock. */
static ws_tls_ctx *g_tls;
#endif

/* Connections that have not authenticated yet: TLS handshake, HTTP upgrade,
 * Origin and token check. They get their own small budget, separate from
 * ws_max_clients, because they used to share it: four sockets that open and
 * then dribble - each held up to WS_TLS_HANDSHAKE_TIMEOUT_MS, re-opened as
 * soon as it is dropped - locked every legitimate client out while holding
 * no credential at all.
 *
 * When the table is full the OLDEST entry is evicted (shutdown() on its
 * socket, which wakes its poll and ends it within one read) rather than the
 * newcomer refused, so a flood can delay a real client but cannot keep it
 * out: a browser finishes its handshake in well under a second, an attacker
 * has to keep beating that to stay ahead. The minimum age stops a burst of
 * genuine reconnects - four PTZ tabs after a daemon restart - from evicting
 * each other before any of them had a chance. */
#define WS_MAX_PENDING 4
#define WS_PENDING_MIN_AGE_MS 500

/* Live connection counts, guarded by g_count_lock. A plain int + mutex rather
 * than an atomic builtin: this has to build on whatever the buildroot
 * toolchain provides for MIPS32, and the accept path is not hot enough for
 * the difference to matter.
 *
 * g_nclients counts AUTHENTICATED connections only - the ones ws_max_clients
 * is about. g_pending[] holds the fd of each connection still in its
 * handshake (-1 = free slot). An entry is removed by its own thread, under the
 * lock, BEFORE that thread closes the fd: the listener's shutdown() of an
 * evicted fd, also under the lock, can therefore never reach a descriptor
 * number that has since been reused by another connection. */
static pthread_mutex_t g_count_lock = PTHREAD_MUTEX_INITIALIZER;
static int g_nclients = 0;
static struct {
  int fd;
  long long since;
} g_pending[WS_MAX_PENDING];

/* Homing is the one command that runs for tens of seconds while holding the
 * command mutex. It is dispatched to its own thread so the WS connection
 * stays responsive (a client must always be able to send "stop"), and this
 * flag stops a client from queueing a hundred of them behind the mutex. */
static pthread_mutex_t g_home_lock = PTHREAD_MUTEX_INITIALIZER;
static bool g_home_running = false;

typedef struct {
  /* Owns both members: conn_thread() closes the fd and frees any TLS session
   * on every exit path. ws.c only borrows this. */
  ws_io io;
  ws_conn ws;
  bool local; /* peer is in 127.0.0.0/8 */
  char peer[INET_ADDRSTRLEN];

  int push_ms;            /* 0 = client has not subscribed */
  long long last_poll_ms; /* when the driver was last sampled */
  long long last_sent_ms; /* when a status frame last went out */
  long long last_ping_ms;

  /* token bucket, in thousandths of a command: integer arithmetic keeps the
   * per-command check off the FPU emulation path and out of the binary */
  long long tokens_milli;
  long long bucket_ms;
  int strikes;

  bool authed; /* counted in g_nclients rather than g_pending[] */

  /* last pushed sample, so an idle connection stays silent */
  int last_x, last_y, last_moving;
} ws_client;

/* ------------------------------------------------------------------ *
 * helpers
 * ------------------------------------------------------------------ */

/* One clock for the whole frontend, shared with ws.c's liveness stamp.
 *
 * It is monotonic now (see ws_now_ms()). Every use below - the ping cadence,
 * the push cadence, the heartbeat, the rate-limiter bucket, the liveness
 * deadline - measures an INTERVAL, never a date, so monotonic is strictly the
 * correct source for all of them. Under the previous gettimeofday() the first
 * NTP sync after boot (these cameras have no RTC, so that step is routinely
 * hours or years) would jump every one of those timers at once; for the
 * liveness deadline that would not merely skew a cadence, it would drop every
 * open connection. */
static long long now_ms(void) { return ws_now_ms(); }

static int clampi(int v, int lo, int hi) {
  return (v < lo) ? lo : ((v > hi) ? hi : v);
}

/* Stack for a connection thread. 64 KB covers the plain path: the deepest
 * frame in this file is conn_thread() itself - the handshake struct (~3.5 KB)
 * plus one message buffer - and libjct's recursion is capped by
 * json_nesting_too_deep(). A wss:// connection additionally runs the mbedTLS
 * handshake (bignum and ECP work, record buffers on the stack in places) on
 * top of that frame. Measured on a T23 (2026-09-24, mbedTLS 3.6.6, TLS 1.3,
 * ECDSA P-256 certificate): 16 KB of stack touched after the handshake. An
 * RSA certificate's private-key operation was not measured and is heavier,
 * so a TLS-capable listener still gives every connection thread 128 KB. It is
 * address space, not RAM: only the pages a thread actually touches become
 * resident, so the headroom costs nothing unless it is used. The sniff that
 * decides plain vs TLS runs on the thread itself, hence one size for all. */
#define WS_STACK_PLAIN (64 * 1024)
#define WS_STACK_TLS (128 * 1024)

/* Lowest-numbered-first scan is fine for a table of four. Returns the slot
 * index, or -1 when the table is full and nothing in it is old enough to
 * evict. Called with g_count_lock held. */
static int pending_claim_locked(int fd, long long now) {
  int oldest = -1;

  for (int i = 0; i < WS_MAX_PENDING; i++) {
    if (g_pending[i].fd < 0) {
      g_pending[i].fd = fd;
      g_pending[i].since = now;
      return i;
    }
    if (oldest < 0 || g_pending[i].since < g_pending[oldest].since)
      oldest = i;
  }

  if (now - g_pending[oldest].since < WS_PENDING_MIN_AGE_MS)
    return -1;

  /* The evicted thread still owns its fd and will find it missing from the
   * table when it comes to release it - which is how it knows it was evicted
   * rather than finished. */
  shutdown(g_pending[oldest].fd, SHUT_RDWR);
  g_pending[oldest].fd = fd;
  g_pending[oldest].since = now;
  return oldest;
}

/* Remove fd from the pending table. Returns false if it was no longer there,
 * i.e. the listener evicted this connection. Called with g_count_lock held. */
static bool pending_release_locked(int fd) {
  for (int i = 0; i < WS_MAX_PENDING; i++) {
    if (g_pending[i].fd == fd) {
      g_pending[i].fd = -1;
      return true;
    }
  }
  return false;
}

#ifdef MOTORS_WS_TLS
/* Wait for the socket to have at least one byte. Only used by the first-byte
 * protocol sniff in conn_thread(); ws.c owns every other wait on this fd.
 * Returns 0 when readable, -1 on timeout or error. */
static int poll_fd_readable(int fd, int timeout_ms) {
  struct pollfd p = {.fd = fd, .events = POLLIN, .revents = 0};
  int r;

  do {
    r = poll(&p, 1, timeout_ms);
  } while (r < 0 && errno == EINTR);

  if (r <= 0)
    return -1;
  return (p.revents & (POLLERR | POLLNVAL)) ? -1 : 0;
}
#endif

/* ------------------------------------------------------------------ *
 * outgoing JSON
 *
 * Hand-rolled snprintf rather than libjct's json_to_string(): every frame
 * this daemon emits is one flat object of at most eleven scalar fields, and
 * building a JsonValue tree plus a malloc'd string for each one would cost a
 * dozen allocations per push, several times a second, per client, on a
 * camera with 64 MB of RAM. The sibling timps project builds its /control
 * and /events JSON exactly this way for the same reason.
 *
 * NOTHING here interpolates a client-supplied string. `type`, `cmd` and
 * `code` are always pointers to string literals chosen by a switch in this
 * file after the client's input was matched against a fixed set - never the
 * client's own bytes. That is what makes it safe to have no JSON string
 * escaper on the write side, and it is a property to preserve if fields are
 * added later.
 * ------------------------------------------------------------------ */

static int fmt_status(char *buf, size_t cap, const char *type,
                      const struct motor_message *m) {
  return snprintf(buf, cap,
                  "{\"type\":\"%s\",\"x\":%d,\"y\":%d,"
                  "\"x_max\":%u,\"y_max\":%u,\"speed\":%d,"
                  "\"moving\":%s,\"inversion\":%u}",
                  type, m->x, m->y, m->x_max_steps, m->y_max_steps, m->speed,
                  (m->status == MOTOR_IS_RUNNING) ? "true" : "false",
                  m->inversion_state);
}

static int send_status(ws_client *c, const char *type,
                       const struct motor_message *m) {
  char buf[256];
  int n = fmt_status(buf, sizeof(buf), type, m);
  if (n < 0 || (size_t)n >= sizeof(buf))
    return WS_EIO;
  return ws_send_text(&c->io, buf);
}

static int send_error(ws_client *c, long long id, const char *code,
                      const char *msg) {
  char buf[256];
  int n;

  if (id >= 0)
    n = snprintf(buf, sizeof(buf),
                 "{\"type\":\"error\",\"id\":%lld,\"code\":\"%s\","
                 "\"msg\":\"%s\"}",
                 id, code, msg);
  else
    n = snprintf(buf, sizeof(buf),
                 "{\"type\":\"error\",\"code\":\"%s\",\"msg\":\"%s\"}", code,
                 msg);

  if (n < 0 || (size_t)n >= sizeof(buf))
    return WS_EIO;
  return ws_send_text(&c->io, buf);
}

static int send_ack(ws_client *c, long long id, const char *cmd, bool have_xy,
                    int x, int y) {
  char buf[192];
  int n;

  if (have_xy)
    n = snprintf(buf, sizeof(buf),
                 "{\"type\":\"ack\",\"id\":%lld,\"cmd\":\"%s\",\"x\":%d,"
                 "\"y\":%d}",
                 id, cmd, x, y);
  else
    n = snprintf(buf, sizeof(buf),
                 "{\"type\":\"ack\",\"id\":%lld,\"cmd\":\"%s\"}", id, cmd);

  if (n < 0 || (size_t)n >= sizeof(buf))
    return WS_EIO;
  return ws_send_text(&c->io, buf);
}

/* ------------------------------------------------------------------ *
 * status sampling
 * ------------------------------------------------------------------ */

/* Every subscribed connection used to sample the driver on its own cadence -
 * four clients at 150 ms meant four MOTOR_GET_STATUS ioctls and four
 * command-lock attempts where one would do, and each attempt that lands
 * during a command is a skipped push. One shared sample, reused while it is
 * younger than this, collapses them. Below the 50 ms push floor, so no client
 * ever receives a sample older than its own interval. */
#define WS_STATUS_CACHE_MS 40

static pthread_mutex_t g_status_lock = PTHREAD_MUTEX_INITIALIZER;
static struct motor_message g_status;
static long long g_status_ms;
static bool g_status_valid;

/* A command has just changed things: the next sample must come from the
 * driver, not from before the command - that is the whole point of the
 * forced poll in conn_thread(). */
static void status_invalidate(void) {
  pthread_mutex_lock(&g_status_lock);
  g_status_valid = false;
  pthread_mutex_unlock(&g_status_lock);
}

/* Non-blocking sample for the periodic push (see motor_ctl_status_try()).
 * Returns false when the driver could not be asked right now. */
static bool status_sample(struct motor_message *m) {
  long long now = now_ms();

  pthread_mutex_lock(&g_status_lock);
  if (g_status_valid && now - g_status_ms < WS_STATUS_CACHE_MS) {
    *m = g_status;
    pthread_mutex_unlock(&g_status_lock);
    return true;
  }
  pthread_mutex_unlock(&g_status_lock);

  if (!motor_ctl_status_try(m))
    return false;

  pthread_mutex_lock(&g_status_lock);
  g_status = *m;
  g_status_ms = now;
  g_status_valid = true;
  pthread_mutex_unlock(&g_status_lock);
  return true;
}

/* Status for a frame the client is owed right now - the "hello" greeting and
 * an explicit "status" command. Those used to take the command lock
 * unconditionally, which parks the connection thread for the whole of a
 * homing sweep (~35 s): no PING answered, no stop read. During a long
 * operation the driver is read without the lock instead, exactly as the move
 * worker reads it all the time; the frame may then show a position mid-sweep,
 * which is the truth. */
static void status_now(struct motor_message *m) {
  if (motor_ctl_status_try(m))
    return;
  if (motor_ctl_long_op())
    motor_ctl_status_peek(m);
  else
    motor_ctl_status(m); /* a short command holds the lock; wait it out */
}

/* ------------------------------------------------------------------ *
 * access control
 * ------------------------------------------------------------------ */

/* Reduce "http://cam.lan:8080/" or "cam.lan:8080" to "cam.lan". Comparing
 * bare hosts and ignoring the port is deliberate: the page is served by
 * busybox-httpd on :80 while this listener is on :8089 by construction, so
 * requiring port equality would reject every legitimate same-device
 * connection. The scheme is likewise ignored - an http:// page and an
 * https:// page on the same camera are the same trust domain here, and this
 * listener is plain ws:// either way. */
static void origin_host(const char *in, char *out, size_t cap) {
  const char *p = in;
  const char *sep;
  size_t i = 0;

  sep = strstr(p, "://");
  if (sep)
    p = sep + 3;

  while (*p && *p != ':' && *p != '/' && i + 1 < cap)
    out[i++] = (char)tolower((unsigned char)*p++);
  out[i] = '\0';
}

/* Origin validation.
 *
 * WebSocket is NOT covered by CORS. A cross-origin page can open a socket to
 * any host it likes and the browser will complete the handshake without any
 * preflight - the server is the only thing that can say no. Skipping this
 * check is the cross-site-WebSocket-hijacking hole, so it is done explicitly
 * even though this listener's credential is a bearer token rather than an
 * ambient cookie (which means a malicious origin could not authenticate
 * anyway - this is defence in depth, not the primary control).
 *
 * Policy:
 *   - No Origin header at all -> allowed. RFC 6455 section 4.1 requires
 *     browser clients to send one, so its absence identifies a non-browser
 *     client (curl, a script, ONVIF tooling). Those have no ambient
 *     credentials to be hijacked and must still present a token, so
 *     rejecting them would break every non-browser integration for no gain.
 *   - Origin present -> its host must equal the Host header's host (the page
 *     came from this camera), or appear in the motors.ws_origins allow-list
 *     (for a separate dashboard host).
 */
static bool origin_allowed(const ws_handshake *hs) {
  char ohost[128], hhost[128];
  const char *p;

  if (!hs->has_origin)
    return true;

  if (!hs->origin[0])
    return false; /* an explicitly empty/"null" Origin is a sandboxed or
                   * redirected context; never treat that as same-site */

  origin_host(hs->origin, ohost, sizeof(ohost));
  if (!ohost[0])
    return false;

  origin_host(hs->host, hhost, sizeof(hhost));
  if (hhost[0] && strcmp(ohost, hhost) == 0)
    return true;

  /* comma-separated allow-list; entries may be bare hosts or full origins */
  p = g_cfg.origins;
  while (*p) {
    char entry[128], ehost[128];
    size_t i = 0;

    while (*p == ' ' || *p == ',')
      p++;
    while (*p && *p != ',' && i + 1 < sizeof(entry))
      entry[i++] = *p++;
    /* An entry longer than the buffer stops the copy above without consuming
     * the rest of it; skip to the next separator by hand or the outer loop
     * would re-read the same prefix forever. An over-long entry can then
     * only fail to match, which is the safe direction. */
    while (*p && *p != ',')
      p++;
    while (i > 0 && entry[i - 1] == ' ')
      i--;
    entry[i] = '\0';
    if (!entry[0])
      continue;

    origin_host(entry, ehost, sizeof(ehost));
    if (ehost[0] && strcmp(ohost, ehost) == 0)
      return true;
  }

  return false;
}

/* Token extraction and check.
 *
 * The loopback bypass deserves a note, because copying timps's rationale
 * uncritically would be wrong here. In timps, /control is fetched by the
 * on-device page's own JS against 127.0.0.1, so loopback genuinely IS the
 * primary web-UI path. Here it is not: the browser is a REMOTE peer relative
 * to the camera even when the page was served by that same camera, so the
 * browser's WebSocket arrives from the LAN address and takes the token path.
 * Loopback therefore only covers same-host callers - a CGI, an init script,
 * `websocat` over an SSH tunnel, a future on-device automation - and it is
 * kept because those cannot conveniently read a 0640 token file from a
 * non-root context, not because the UI needs it.
 *
 * Header form preferred; query form accepted because the browser's
 * `new WebSocket(url)` constructor cannot set request headers on the opening
 * handshake. That is not a convenience - for the primary use case it is the
 * only mechanism the platform offers. The cost is that the token can land in
 * a proxy access log, which is the same tradeoff timps documents for
 * EventSource. */
static bool client_authorized(const ws_handshake *hs, bool local) {
  char tok[160];
  bool ok = false;

  if (local)
    return true;

  if (ws_header(hs, "X-Motors-Token", tok, sizeof(tok)) && tok[0]) {
    ok = ws_token_check(tok);
    memset(tok, 0, sizeof(tok));
    if (ok)
      return true;
  }

  if (ws_query_param(hs->query, "token", tok, sizeof(tok))) {
    ok = ws_token_check(tok);
    memset(tok, 0, sizeof(tok));
    if (ok)
      return true;
  }

  return false;
}

/* ------------------------------------------------------------------ *
 * command dispatch
 * ------------------------------------------------------------------ */

static void *home_worker(void *arg) {
  int speed = (int)(long)arg;

  motor_ctl_home(speed);

  pthread_mutex_lock(&g_home_lock);
  g_home_running = false;
  pthread_mutex_unlock(&g_home_lock);
  return NULL;
}

/* Read an integer field. Returns false when absent or not an integer, so the
 * caller can tell "omitted" (legal for an absolute move's unspecified axis)
 * from "present but garbage" (an error). */
static bool json_int(JsonValue *obj, const char *key, long long *out) {
  JsonValue *v = get_object_item(obj, key);
  if (!v)
    return false;
  if (v->type == JSON_NUMBER) {
    if (v->value.number.kind == JSON_NUMBER_INT) {
      *out = (long long)v->value.number.integer;
      return true;
    }
    /* Converting a double outside long long's range (1e300, or the infinity
     * that "1e999" parses to) is undefined behaviour, not a large number.
     * Saturate first, well beyond every range check the callers apply, so
     * such a value is rejected as out of range rather than turning into
     * whatever the conversion happens to produce. NaN compares false both
     * ways and is refused outright. */
    double r = v->value.number.real;
    const double lim = 9007199254740992.0; /* 2^53 */
    if (r != r)
      return false;
    if (r > lim)
      r = lim;
    if (r < -lim)
      r = -lim;
    *out = (long long)r;
    return true;
  }
  return false;
}

static const char *json_str(JsonValue *obj, const char *key) {
  JsonValue *v = get_object_item(obj, key);
  if (v && v->type == JSON_STRING)
    return v->value.string;
  return NULL;
}

/* Every legitimate command is a flat object (depth 1: {"cmd":"move","x":1,...}
 * with no nested objects/arrays at all). libjct's parse_json_string() recurses
 * once per nesting level with no depth limit of its own - confirmed by direct
 * test that a run of ~700 nested '[' on a connection thread's 64 KB stack
 * overflows it and crashes the whole daemon (not just this connection), well
 * within WS_MAX_PAYLOAD's 2048-byte cap. That byte cap bounds payload size,
 * not recursion depth - they are different resources. Loopback callers skip
 * the token entirely (see client_authorized()), so this has to reject before
 * parse_json_string() ever runs, not rely on auth to keep it out. Quoted
 * brackets don't count: a string value containing '[' is not nesting. */
#define JSON_MAX_NEST_DEPTH 8

static bool json_nesting_too_deep(const char *text) {
  int depth = 0;
  bool in_string = false;
  bool escaped = false;

  for (const char *p = text; *p; p++) {
    if (in_string) {
      if (escaped)
        escaped = false;
      else if (*p == '\\')
        escaped = true;
      else if (*p == '"')
        in_string = false;
      continue;
    }
    if (*p == '"')
      in_string = true;
    else if (*p == '{' || *p == '[') {
      if (++depth > JSON_MAX_NEST_DEPTH)
        return true;
    } else if (*p == '}' || *p == ']') {
      depth--;
    }
  }
  return false;
}

/* Returns WS_OK to continue the connection, anything else to tear it down. */
static int handle_command(ws_client *c, const char *text) {
  JsonValue *root;
  const char *cmd;
  long long id = -1;
  long long v = 0;
  int speed = 0;
  int rc = WS_OK;

  if (json_nesting_too_deep(text))
    return send_error(c, -1, "bad_json", "nested too deeply");

  root = parse_json_string(text);
  if (!root)
    return send_error(c, -1, "bad_json", "not valid JSON");
  if (root->type != JSON_OBJECT) {
    free_json_value(root);
    return send_error(c, -1, "bad_json", "top level must be an object");
  }

  if (json_int(root, "id", &v) && v >= 0 && v <= 2147483647LL)
    id = v;

  cmd = json_str(root, "cmd");
  if (!cmd) {
    rc = send_error(c, id, "bad_request", "missing cmd");
    goto out;
  }

  /* Speed is validated here AND clamped again inside
   * motor_ctl_resolve_speed()/sanitize_requested_speed(). An out-of-range
   * value is rejected outright rather than silently clamped, because a UI
   * sending speed=99999 has a bug worth surfacing, and a persistent socket
   * gives an attacker many more attempts per second than the old one-shot
   * CGI ever did - the right answer to more attempts is stricter checks, not
   * looser ones. */
  if (json_int(root, "speed", &v)) {
    if (v < 0 || v > 2000) {
      rc = send_error(c, id, "bad_speed", "speed out of range 0..2000");
      goto out;
    }
    speed = (int)v;
  }

  /* A homing sweep or a config reload holds the command lock for seconds -
   * homing for up to ~35. Every command below that needs the lock would park
   * this thread for that long, reading nothing (not even "stop") and
   * answering no PING, so it is refused up front instead. stop, ping, status
   * and subscribe never wait on the lock for long; vector checks for itself,
   * because releasing the stick is a stop and must always get through. The
   * check is a hint, not a lock: a long operation starting a moment after it
   * still makes the command wait, as it always did. */
  if (strcmp(cmd, "stop") != 0 && strcmp(cmd, "ping") != 0 &&
      strcmp(cmd, "status") != 0 && strcmp(cmd, "subscribe") != 0 &&
      strcmp(cmd, "vector") != 0 && motor_ctl_long_op()) {
    rc = send_error(c, id, "busy", "homing or config reload in progress");
    goto out;
  }

  if (strcmp(cmd, "move") == 0) {
    /* mode defaults to "rel": the hold-a-button jog is the overwhelmingly
     * common case and the one this whole change exists to make cheap. */
    const char *mode = json_str(root, "mode");
    bool absolute = (mode && strcmp(mode, "abs") == 0);
    long long xv = 0, yv = 0;
    bool got_x, got_y;
    int ax = 0, ay = 0;
    int eff_speed;

    if (mode && !absolute && strcmp(mode, "rel") != 0) {
      rc = send_error(c, id, "bad_request", "mode must be rel or abs");
      goto out;
    }

    got_x = json_int(root, "x", &xv);
    got_y = json_int(root, "y", &yv);
    if (!got_x && !got_y) {
      rc = send_error(c, id, "bad_request", "move needs x and/or y");
      goto out;
    }

    if (absolute) {
      if ((got_x && (xv < 0 || xv > WS_MAX_ABS_POS)) ||
          (got_y && (yv < 0 || yv > WS_MAX_ABS_POS))) {
        rc = send_error(c, id, "out_of_range", "absolute target out of range");
        goto out;
      }
      eff_speed = motor_ctl_resolve_speed(speed);
      motor_ctl_absolute((int)xv, got_x ? 1 : 0, (int)yv, got_y ? 1 : 0,
                         eff_speed, &ax, &ay);
    } else {
      /* A relative move with only one axis given jogs the other by zero,
       * which is what the CLI's "-d g -x N" has always meant. */
      if ((got_x && (xv < -WS_MAX_REL_DELTA || xv > WS_MAX_REL_DELTA)) ||
          (got_y && (yv < -WS_MAX_REL_DELTA || yv > WS_MAX_REL_DELTA))) {
        rc = send_error(c, id, "out_of_range", "relative delta out of range");
        goto out;
      }
      eff_speed = motor_ctl_resolve_speed(speed);
      motor_ctl_relative((int)xv, (int)yv, eff_speed, &ax, &ay);
    }

    rc = send_ack(c, id, "move", true, ax, ay);
  } else if (strcmp(cmd, "vector") == 0) {
    /* Analog-stick deflection, per-mille and signed, in the logical frame.
     * NOT a distance: the client says where the stick is and the daemon
     * decides both how far (always: to the limit) and how fast, so the page
     * never has to know the travel limits or the configured speed cap. The
     * optional `speed` validated above is the reference for FULL deflection,
     * not the speed of this update.
     *
     * Out of range is clamped here, unlike `speed` which is rejected. The
     * difference is deliberate: 1000 is a stick at the rim, so a client that
     * computes 1004 from a pointer a pixel outside the ring has made a
     * rounding error, not the kind of mistake worth surfacing that a
     * speed=99999 is. */
    long long xv = 0, yv = 0;
    bool got_x = json_int(root, "x", &xv);
    bool got_y = json_int(root, "y", &yv);
    int sx = 0, sy = 0;

    if (!got_x && !got_y) {
      rc = send_error(c, id, "bad_request", "vector needs x and/or y");
      goto out;
    }

    /* Clamp as long long: casting an out-of-range long long to int first
     * would be the undefined step this is here to avoid. */
    xv = (xv < -1000) ? -1000 : ((xv > 1000) ? 1000 : xv);
    yv = (yv < -1000) ? -1000 : ((yv > 1000) ? 1000 : yv);

    switch (motor_ctl_vector((int)xv, (int)yv, speed, &sx, &sy)) {
    case MOTOR_CTL_NO_LIMITS:
      rc = send_error(c, id, "no_limits",
                      "travel limits unknown, cannot drive a vector");
      goto out;
    case MOTOR_CTL_BUSY:
      rc = send_error(c, id, "busy", "homing or config reload in progress");
      goto out;
    default:
      break;
    }

    /* x/y in this ack are the per-axis SPEEDS commanded, not a delta the way
     * a move's ack reports one - a vector has no delta to report, and the
     * speed is the only thing the client cannot predict (the daemon caps it
     * against motors.speed_pan/speed_tilt). */
    rc = send_ack(c, id, "vector", true, sx, sy);
  } else if (strcmp(cmd, "stop") == 0) {
    motor_ctl_stop();
    rc = send_ack(c, id, "stop", false, 0, 0);
  } else if (strcmp(cmd, "home") == 0) {
    bool started = false;
    int eff_speed = motor_ctl_resolve_speed(speed);

    pthread_mutex_lock(&g_home_lock);
    if (!g_home_running) {
      g_home_running = true;
      started = true;
    }
    pthread_mutex_unlock(&g_home_lock);

    if (!started) {
      rc = send_error(c, id, "busy", "homing already in progress");
      goto out;
    }

    /* Detached, because motor_ctl_home() is synchronous and can run for tens
     * of seconds; parking this connection thread on it would make "stop"
     * unreachable from the very client that started the home. */
    if (motor_spawn_detached(home_worker, (void *)(long)eff_speed,
                             WS_STACK_PLAIN) != 0) {
      pthread_mutex_lock(&g_home_lock);
      g_home_running = false;
      pthread_mutex_unlock(&g_home_lock);
      rc = send_error(c, id, "internal", "cannot start homing thread");
      goto out;
    }
    rc = send_ack(c, id, "home", false, 0, 0);
  } else if (strcmp(cmd, "speed") == 0) {
    if (speed <= 0) {
      rc = send_error(c, id, "bad_request", "speed must be > 0");
      goto out;
    }
    motor_ctl_set_speed(speed);
    rc = send_ack(c, id, "speed", false, 0, 0);
  } else if (strcmp(cmd, "status") == 0) {
    struct motor_message m;
    status_now(&m);
    rc = send_status(c, "status", &m);
  } else if (strcmp(cmd, "subscribe") == 0) {
    if (json_int(root, "interval_ms", &v)) {
      /* 0 disables; anything else is clamped rather than rejected, because a
       * client asking for 1 ms is asking for a faster ioctl poll than the
       * hardware can answer, not doing anything abusive. The floor is the
       * real DoS control here: without it a client could ask this thread to
       * poll the motor driver as fast as the CPU allows. */
      c->push_ms = (v <= 0) ? 0 : clampi((int)v, 50, 5000);
    } else {
      c->push_ms = g_cfg.push_ms;
    }
    rc = send_ack(c, id, "subscribe", false, 0, 0);
    if (rc == WS_OK && c->push_ms) {
      struct motor_message m;
      status_now(&m);
      rc = send_status(c, "status", &m);
      c->last_poll_ms = c->last_sent_ms = now_ms();
      c->last_x = m.x;
      c->last_y = m.y;
      c->last_moving = (m.status == MOTOR_IS_RUNNING);
    }
  } else if (strcmp(cmd, "ping") == 0) {
    /* Application-level ping, distinct from the protocol PING frame that
     * ws.c answers on its own. Exists so a client can measure round-trip
     * latency without needing access to the raw frame layer. */
    rc = send_ack(c, id, "ping", false, 0, 0);
  } else {
    /* Note what is deliberately NOT exposed: 'I' (invert) and 'R' (reload)
     * are configuration operations, not PTZ operations. They stay on the
     * AF_UNIX socket, which is reachable only by a local process that can
     * open /dev/md - a meaningfully higher bar than "holds a token". */
    rc = send_error(c, id, "unknown_cmd", "unsupported cmd");
  }

out:
  free_json_value(root);
  return rc;
}

/* ------------------------------------------------------------------ *
 * connection thread
 * ------------------------------------------------------------------ */

/* Token bucket: refill at rate_limit tokens/second, cap at rate_limit (so a
 * quiet client banks at most one second of burst). Returns false when the
 * command should be dropped. */
static bool rate_ok(ws_client *c) {
  long long now = now_ms();
  long long cap = (long long)g_cfg.rate_limit * 1000;

  /* rate_limit commands per second = rate_limit milli-tokens per ms */
  c->tokens_milli += (now - c->bucket_ms) * (long long)g_cfg.rate_limit;
  c->bucket_ms = now;
  if (c->tokens_milli > cap)
    c->tokens_milli = cap;

  if (c->tokens_milli < 1000)
    return false;
  c->tokens_milli -= 1000;
  return true;
}

static int periodic(ws_client *c) {
  long long now = now_ms();

  if (c->push_ms && (now - c->last_poll_ms) >= c->push_ms) {
    struct motor_message m;
    int moving;

    /* The position source is a polled ioctl (MOTOR_GET_STATUS): there is no
     * producer inside this daemon that could signal a condvar the way timps's
     * events_notify() does, because the kernel motor driver offers no such
     * notification. So this is an honest poll on the server side that
     * becomes a push on the wire - the client still gets true server-driven
     * updates and never polls over HTTP, which is the whole point.
     *
     * Non-blocking on purpose (see motor_ctl_status_try): a skipped push
     * costs one stale frame, whereas blocking here would freeze this
     * connection - and its stop command - for as long as some other
     * frontend's long command holds the lock. Leaving last_poll_ms alone on
     * a skip means the next attempt comes one read-timeout later, not in a
     * spin. */
    if (!status_sample(&m))
      goto keepalive;
    moving = (m.status == MOTOR_IS_RUNNING);

    /* Stay silent while nothing changes, so an open panel on a parked
     * camera costs nothing but the occasional heartbeat. The two clocks are
     * separate on purpose: last_poll_ms paces how often the driver is asked,
     * last_sent_ms paces how often a frame goes out. Collapsing them into
     * one would either re-poll on every loop iteration or suppress the
     * heartbeat entirely. */
    if (m.x != c->last_x || m.y != c->last_y || moving != c->last_moving ||
        (now - c->last_sent_ms) >= WS_HEARTBEAT_MS) {
      if (send_status(c, "status", &m) != WS_OK)
        return WS_EIO;
      c->last_x = m.x;
      c->last_y = m.y;
      c->last_moving = moving;
      c->last_sent_ms = now;
    }
    c->last_poll_ms = now;
  }

keepalive:
  /* Liveness first, so a peer that is already past the deadline is closed on
   * this pass rather than getting one more PING it will never answer.
   *
   * The failure this catches is specifically the one TCP cannot: a peer whose
   * host vanished without a FIN - suspended laptop, yanked ethernet, a WiFi
   * client that left the cell. Writes to such a socket keep succeeding into
   * the kernel's send buffer for a long time, so ws_send_ping() below returns
   * WS_OK and the connection looks perfectly healthy from the write side. The
   * only evidence available is the absence of anything coming back. */
  if (ws_conn_idle_ms(&c->ws) >= WS_LIVENESS_TIMEOUT_MS) {
    syslog(LOG_INFO, "ws: %s silent for %ds, closing stale connection", c->peer,
           WS_LIVENESS_TIMEOUT_MS / 1000);
    ws_send_close(&c->io, WS_CLOSE_GOING_AWAY, "keepalive timeout");
    /* WS_CLOSED, not WS_EIO: the socket is fine, we are the ones ending this.
     * conn_thread() treats every non-WS_OK the same, but the distinction is
     * worth keeping honest for anything that reads this later. */
    return WS_CLOSED;
  }

  if ((now - c->last_ping_ms) >= WS_PING_INTERVAL_MS) {
    if (ws_send_ping(&c->io) != WS_OK)
      return WS_EIO;
    c->last_ping_ms = now;
  }

  return WS_OK;
}

/* Give back whichever budget this connection is counted in. Must run before
 * the fd is closed - see g_pending[]. */
static void client_release(ws_client *c) {
  pthread_mutex_lock(&g_count_lock);
  if (c->authed) {
    if (g_nclients > 0)
      g_nclients--;
  } else {
    (void)pending_release_locked(c->io.fd);
  }
  pthread_mutex_unlock(&g_count_lock);
}

/* Move a connection that has just authenticated from the pending table into
 * the ws_max_clients budget. Returns 0 on success, -1 if the listener evicted
 * it meanwhile (its socket is already shut down), -2 if every client slot is
 * taken. On -2 the connection stays pending, so client_release() still frees
 * its slot. */
static int client_promote(ws_client *c) {
  int rc = 0;

  pthread_mutex_lock(&g_count_lock);
  if (g_nclients >= g_cfg.max_clients) {
    rc = -2;
  } else if (!pending_release_locked(c->io.fd)) {
    rc = -1;
  } else {
    g_nclients++;
    c->authed = true;
  }
  pthread_mutex_unlock(&g_count_lock);
  return rc;
}

/* How long the teardown will wait for the peer to acknowledge the close before
 * giving up on an orderly one. Short: this only covers one round trip on a LAN,
 * and the thread is otherwise finished. */
#define WS_CLOSE_LINGER_MS 500

/* close() on a socket that still has unread bytes in its receive queue sends
 * an RST instead of a FIN, and an RST makes the peer's TCP discard whatever is
 * still sitting in ITS receive buffer - including the close frame written a
 * microsecond earlier. A PTZ client streaming at 11 Hz practically always has
 * a command or two queued here, which is how a deliberate, correctly coded
 * close still reached the browser as "no close frame received".
 *
 * So: stop writing, then read until the peer's own FIN (or the deadline) so the
 * queue is empty when close() runs. Everything read here is discarded - the
 * connection is over, and the only thing that matters is that the bytes are
 * consumed. */
static void close_gracefully(int fd) {
  long long deadline = now_ms() + WS_CLOSE_LINGER_MS;
  char sink[512];

  shutdown(fd, SHUT_WR);

  for (;;) {
    struct pollfd p = {.fd = fd, .events = POLLIN, .revents = 0};
    int left = (int)(deadline - now_ms());
    ssize_t n;

    if (left <= 0)
      break;
    if (poll(&p, 1, left) <= 0)
      break;

    n = read(fd, sink, sizeof(sink));
    if (n == 0) /* peer's FIN: nothing left to drain */
      break;
    if (n < 0) {
      if (errno == EINTR)
        continue;
      break;
    }
  }

  close(fd);
}

static void *conn_thread(void *arg) {
  ws_client *c = (ws_client *)arg;
  ws_handshake hs;
  unsigned char msg[WS_MAX_PAYLOAD + 1];
  int rc;

  /* PTZ is a latency game: without TCP_NODELAY a 40-byte command can sit in
   * the kernel waiting for Nagle to coalesce it, which is exactly the delay
   * this whole change exists to remove. */
  {
    int one = 1;
    setsockopt(c->io.fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    setsockopt(c->io.fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
  }

  /* Non-blocking on the plain path too, not only under TLS. Every read in
   * ws.c already polls first, so reads do not change; what changes is that a
   * write to a peer that has stopped reading comes back EAGAIN into
   * write_all()'s deadline instead of blocking inside send() until TCP gives
   * up - about fifteen minutes on a stock kernel, during which this thread
   * could not even run its liveness check. */
  {
    int fl = fcntl(c->io.fd, F_GETFL, 0);
    if (fl < 0 || fcntl(c->io.fd, F_SETFL, fl | O_NONBLOCK) < 0) {
      syslog(LOG_WARNING, "ws: cannot make %s non-blocking, dropping", c->peer);
      goto done;
    }
  }

  /* TLS, if this particular connection wants it.
   *
   * ws:// and wss:// share ONE port, chosen by sniffing the first byte the
   * client sends rather than by configuration. 0x16 is the TLS record type
   * "handshake", and a WebSocket client's first byte is always the 'G' of
   * "GET" - the two cannot be confused, so the ambiguity that usually makes
   * protocol sniffing a bad idea does not arise here.
   *
   * Sniffing rather than a second listener, or a config switch that picks one:
   *
   *  - It is what makes this change backward compatible. Cameras that serve
   *    the WebUI over plain http:// keep working exactly as before even once
   *    a certificate is present, which a TLS-only listener would break for
   *    every one of them at once (self-signed wss:// from an http:// page is
   *    not something a browser lets the user click through).
   *  - The port is baked into json-motor-token.cgi, motors.ws_port and every
   *    deployed page; a second port would need all of them to learn about it.
   *  - A second listener would double the accept path and the config surface
   *    to serve at most four clients.
   *
   * MSG_PEEK leaves the byte in the socket buffer, so whichever path is taken
   * below reads the stream from its true beginning. */
#ifdef MOTORS_WS_TLS
  if (g_tls) {
    unsigned char first = 0;
    ssize_t pk;

    /* Peek, but never block on it: an idle connection must be reclaimed by the
     * handshake timeout, not park a thread here. */
    if (poll_fd_readable(c->io.fd, WS_HANDSHAKE_TIMEOUT_MS) != 0) {
      syslog(LOG_DEBUG, "ws: %s sent nothing, dropping", c->peer);
      goto done;
    }
    do {
      pk = recv(c->io.fd, &first, 1, MSG_PEEK);
    } while (pk < 0 && errno == EINTR);
    if (pk <= 0)
      goto done;

    if (first == 0x16) {
      c->io.tls = ws_tls_accept(g_tls, c->io.fd, WS_TLS_HANDSHAKE_TIMEOUT_MS);
      if (!c->io.tls) {
        /* ws_tls_accept() has already logged whatever was worth logging, and
         * rate-limited it. Nothing useful can be said back to the peer - it is
         * expecting TLS records, so a plaintext HTTP error would be noise. */
        goto done;
      }
      syslog(LOG_DEBUG, "ws: TLS established with %s", c->peer);
    }
  }
#endif

  rc = ws_handshake_read(&c->io, &hs, WS_HANDSHAKE_TIMEOUT_MS);
  if (rc != WS_OK) {
    syslog(LOG_DEBUG, "ws: handshake read failed from %s (rc=%d)", c->peer, rc);
    goto done;
  }

  if (strcmp(hs.path, WS_PATH) != 0) {
    ws_handshake_reject(&c->io, 404, "Not Found", "not found\n");
    goto done;
  }

  if (!ws_handshake_is_upgrade(&hs)) {
    ws_handshake_reject(&c->io, 400, "Bad Request",
                        "expected a WebSocket version 13 upgrade\n");
    goto done;
  }

  /* Order matters only for what an attacker learns: origin first means a
   * cross-site page gets the same 403 whether or not it guessed a token. */
  if (!origin_allowed(&hs)) {
    syslog(LOG_WARNING, "ws: rejected Origin '%s' from %s", hs.origin, c->peer);
    ws_handshake_reject(&c->io, 403, "Forbidden", "origin not allowed\n");
    goto done;
  }

  if (!client_authorized(&hs, c->local)) {
    syslog(LOG_WARNING, "ws: unauthorized connection from %s", c->peer);
    ws_handshake_reject(&c->io, 401, "Unauthorized", "token required\n");
    goto done;
  }

  /* Only now does the connection count against ws_max_clients - and a full
   * house is told so in a real HTTP response over whichever transport it
   * came in on, instead of the bare close a wss:// client used to get from
   * the listener. */
  {
    int prc = client_promote(c);
    if (prc == -1)
      goto done; /* evicted while authenticating; the socket is shut down */
    if (prc == -2) {
      syslog(LOG_WARNING, "ws: connection limit (%d) reached, rejecting %s",
             g_cfg.max_clients, c->peer);
      ws_handshake_reject(&c->io, 503, "Service Unavailable",
                          "too many clients\n");
      goto done;
    }
  }

  if (ws_handshake_accept(&c->io, &hs, NULL) != WS_OK)
    goto done;

  syslog(LOG_INFO, "ws: client connected from %s%s", c->peer,
         c->local ? " (loopback)" : "");

  ws_conn_init(&c->ws, &c->io);
  c->tokens_milli = (long long)g_cfg.rate_limit * 1000;
  c->bucket_ms = now_ms();
  c->last_ping_ms = c->bucket_ms;
  c->last_poll_ms = c->last_sent_ms = c->bucket_ms;
  c->last_x = -1;
  c->last_y = -1;
  c->last_moving = -1;

  /* Greet with the current state so the UI can render without a round trip.
   * "hello" rather than "status" so a client can tell a fresh connection
   * from a reconnect that resumed mid-stream. */
  {
    struct motor_message m;
    status_now(&m);
    if (send_status(c, "hello", &m) != WS_OK)
      goto done;
  }

  for (;;) {
    int opcode = 0;
    size_t len = 0;
    int wait_ms = c->push_ms ? c->push_ms : 1000;

    rc = ws_read_message(&c->ws, &opcode, msg, sizeof(msg), &len, wait_ms);

    if (rc == WS_AGAIN) {
      /* WS_CLOSED from periodic() means the keepalive gave up and has already
       * sent its own close; anything else is a failed write, which gets one
       * more attempt at saying why. */
      int prc = periodic(c);
      if (prc == WS_OK)
        continue;
      if (prc != WS_CLOSED)
        ws_send_close(&c->io, WS_CLOSE_INTERNAL, "send failed");
      break;
    }
    if (rc == WS_CLOSED) {
      ws_send_close(&c->io, WS_CLOSE_NORMAL, "bye");
      break;
    }
    if (rc == WS_ETOOBIG) {
      ws_send_close(&c->io, WS_CLOSE_TOO_BIG, "frame too large");
      break;
    }
    if (rc == WS_EPROTO) {
      ws_send_close(&c->io, WS_CLOSE_PROTOCOL, "protocol error");
      break;
    }
    if (rc != WS_OK) {
      /* WS_EIO: the read failed or a frame arrived torn. Saying so costs one
       * frame on a socket that may well be dead already, and is the difference
       * between a client that can log "the server closed with 1011" and one
       * that can only report that the connection vanished. */
      ws_send_close(&c->io, WS_CLOSE_INTERNAL, "read error");
      break;
    }

    if (opcode != WS_OP_TEXT) {
      ws_send_close(&c->io, WS_CLOSE_UNSUPPORTED, "text frames only");
      break;
    }

    if (!rate_ok(c)) {
      /* CONSECUTIVE throttles, reset below on the first command that is let
       * through. A lifetime total would eventually close every long-lived
       * connection that ever saw a burst: a client held at 11 commands/s is
       * nowhere near the 25/s limit, but any stall inside the daemon makes the
       * commands it sent meanwhile arrive together, and that burst alone can
       * drain a bucket that only banks one second of tokens. */
      if (++c->strikes > WS_MAX_STRIKES) {
        syslog(LOG_WARNING, "ws: %s exceeded the command rate limit, closing",
               c->peer);
        ws_send_close(&c->io, WS_CLOSE_POLICY, "rate limit exceeded");
        break;
      }
      if (send_error(c, -1, "rate_limited", "too many commands") != WS_OK)
        break;
      continue;
    }
    c->strikes = 0;

    if (handle_command(c, (const char *)msg) != WS_OK) {
      ws_send_close(&c->io, WS_CLOSE_INTERNAL, "send failed");
      break;
    }

    /* A command almost always moves something; force the next periodic() to
     * SAMPLE now rather than waiting out a full interval. Only last_poll_ms:
     * zeroing last_sent_ms too would also force the frame out, defeating
     * periodic()'s change detection for the commands that changed nothing -
     * a ping, a move clamped to zero, a vector update against a travel limit
     * the camera is already parked on. Every command already answers with its
     * own ack or error, so there is no reply owed here. The shared sample is
     * dropped as well, or the forced poll would be answered from before the
     * command. */
    c->last_poll_ms = 0;
    status_invalidate();

    {
      int prc = periodic(c);
      if (prc != WS_OK) {
        if (prc != WS_CLOSED)
          ws_send_close(&c->io, WS_CLOSE_INTERNAL, "send failed");
        break;
      }
    }
  }

  syslog(LOG_INFO, "ws: client %s disconnected", c->peer);

done:
  /* Order matters: close_notify has to go out over a socket that is still
   * open, so the TLS session is torn down before the fd. Every exit path above
   * reaches here, including the ones that jump past ws_tls_accept(), where
   * io.tls is still NULL and this is a no-op. */
#ifdef MOTORS_WS_TLS
  if (c->io.tls) {
    ws_tls_close((ws_tls_conn *)c->io.tls);
    c->io.tls = NULL;
  }
#endif
  client_release(c); /* before the close; see g_pending[] */
  close_gracefully(c->io.fd);
  free(c);
  return NULL;
}

/* ------------------------------------------------------------------ *
 * listener
 * ------------------------------------------------------------------ */

static void *listen_thread(void *arg) {
  int lfd = (int)(long)arg;
  size_t stack = WS_STACK_PLAIN;

#ifdef MOTORS_WS_TLS
  if (g_tls)
    stack = WS_STACK_TLS;
#endif

  for (;;) {
    struct sockaddr_in peer;
    socklen_t plen = sizeof(peer);
    int fd = accept(lfd, (struct sockaddr *)&peer, &plen);
    ws_client *c;
    int slot;

    if (fd < 0) {
      if (errno == EINTR || errno == ECONNABORTED)
        continue;
      /* Everything else accept() reports on a listening socket that is
       * still valid is a resource shortage (EMFILE, ENFILE, ENOBUFS, ENOMEM)
       * or a connection that died in the backlog (EPROTO, and the network
       * errors Linux passes through). All of them clear on their own. This
       * loop used to break out on any of them, which closed the listener
       * for good - WebSocket control gone until a daemon restart, with one
       * syslog line as the only trace. Back off and keep serving; only a
       * socket that is itself broken ends the thread. */
      if (errno == EBADF || errno == EINVAL || errno == ENOTSOCK ||
          errno == EOPNOTSUPP) {
        syslog(LOG_ERR, "ws: accept failed: %s, listener stopped",
               strerror(errno));
        break;
      }
      syslog(LOG_WARNING, "ws: accept failed: %s, retrying", strerror(errno));
      usleep(200 * 1000);
      continue;
    }

    pthread_mutex_lock(&g_count_lock);
    slot = pending_claim_locked(fd, now_ms());
    pthread_mutex_unlock(&g_count_lock);

    if (slot < 0) {
      /* Every handshake slot is taken by a connection younger than
       * WS_PENDING_MIN_AGE_MS. Close at once: no response, no linger - this
       * is the listener thread, and a flood must not be able to slow the
       * accept loop down by making it wait on each refusal. */
      close(fd);
      continue;
    }

    c = calloc(1, sizeof(*c));
    if (!c) {
      pthread_mutex_lock(&g_count_lock);
      (void)pending_release_locked(fd);
      pthread_mutex_unlock(&g_count_lock);
      close(fd);
      continue;
    }

    /* calloc() already zeroed io.tls and authed; conn_thread() fills them in
     * as the connection progresses. */
    c->io.fd = fd;
    c->local = ws_addr_is_loopback(ntohl(peer.sin_addr.s_addr));
    inet_ntop(AF_INET, &peer.sin_addr, c->peer, sizeof(c->peer));
    c->push_ms = 0;

    if (motor_spawn_detached(conn_thread, c, stack) != 0) {
      syslog(LOG_ERR, "ws: cannot spawn connection thread");
      pthread_mutex_lock(&g_count_lock);
      (void)pending_release_locked(fd);
      pthread_mutex_unlock(&g_count_lock);
      close(fd);
      free(c);
      continue;
    }
  }

  close(lfd);
  return NULL;
}

void motor_ws_cfg_defaults(motor_ws_cfg *cfg) {
  memset(cfg, 0, sizeof(*cfg));
  cfg->enabled = true;
  cfg->port = MOTOR_WS_DEFAULT_PORT;
  snprintf(cfg->bind_addr, sizeof(cfg->bind_addr), "0.0.0.0");
  snprintf(cfg->token_file, sizeof(cfg->token_file), "/run/motors.token");
  cfg->max_clients = 4;
  cfg->rate_limit = 25; /* the UI's hold loop runs at ~11/s */
  cfg->push_ms = 150;
  /* Enabled, but that only means "serve wss:// IF a certificate turns up".
   * Empty paths mean "probe the usual places" - see resolve_tls_paths(). A
   * camera with no certificate is unaffected by this default in every
   * observable way. */
  cfg->tls_enabled = true;
  cfg->tls_cert[0] = '\0';
  cfg->tls_key[0] = '\0';
}

#ifdef MOTORS_WS_TLS
/* Where to look for a certificate when motors.ws_tls_cert/ws_tls_key are not
 * set, in order.
 *
 * This daemon never GENERATES a certificate - it only ever reads one that
 * something else on the image already produced. That is the whole reason this
 * resolution can live here in C at all, rather than in the init script the way
 * timps's has to: S95timps has to decide where to generate INTO, so its
 * decision cannot be made by a daemon that starts later. Ours is only ever
 * "which existing file", so "the first of these that is there" is a complete
 * answer, and there is exactly one certificate policy on the camera - S95timps
 * owns it, everyone else points at the result.
 *
 * [0] is that result. ensure_tls_certs() in S95timps either symlinks these two
 * paths at the WebUI's uhttpd pair, or (on an image with no WebUI) generates a
 * self-signed pair here - so whichever the platform decided, it is already
 * sitting at these paths, and using them is how motors inherits that decision
 * without re-implementing it.
 *
 * [1] is the WebUI's own pair, and it is not redundant. Three real cases reach
 * it, none of which involve minting anything:
 *
 *  - Boot order. S02ssl writes the uhttpd pair, then S59motor (this daemon)
 *    runs, then S95timps creates [0]. On the FIRST boot after a flash, [0]
 *    therefore does not exist yet when we look. It persists across later
 *    reboots because /etc is on the overlay, so this window is first-boot
 *    only - but "wss:// works from the second boot onward" is not a behaviour
 *    worth shipping when the fallback is the very file [0] would have pointed
 *    at anyway.
 *  - timps with TLS off. ensure_tls_certs() returns early unless timps's own
 *    http.https or rtsp.tls is set, so on a camera whose WebUI is https but
 *    whose timps is plain, [0] is never created at all - while the page doing
 *    the PTZ is still https and still needs wss://.
 *  - Images with the WebUI but no timps package.
 *
 * On any image that has the WebUI, [0] and [1] resolve to the SAME
 * certificate; [1] just does not depend on S95timps having run to say so.
 *
 * Why it must be the web UI's certificate and not one of our own: a browser
 * tracks trust for a self-signed certificate per origin - scheme+host+PORT -
 * so :443 and :8089 are two separate trust decisions on one camera. The user
 * clicks through the warning once, on a top-level navigation to the WebUI; a
 * WebSocket gets no such prompt (iOS Safari offers none at all) and would
 * simply fail. Presenting the identical certificate makes the one trust
 * decision cover both ports. That is the same reasoning, and the same
 * certificate, as the comment above ensure_tls_certs() in S95timps.
 *
 * If none of them is there, TLS stays off and the listener serves plain
 * ws:// - see tls_init(). */
static const char *const g_tls_candidates[][2] = {
    {"/etc/ssl/certs/timps.crt", "/etc/ssl/private/timps.key"},
    {"/etc/ssl/certs/uhttpd.crt", "/etc/ssl/private/uhttpd.key"},
};

static bool file_is_usable(const char *path) {
  struct stat st;
  /* stat() rather than access(): a DANGLING symlink is the expected failure
   * here (S95timps links timps.crt at uhttpd.crt, and an image without uhttpd
   * leaves that link pointing at nothing), and stat() follows the link and
   * says no, where a bare existence check on the link itself would say yes.
   * Size, too - an interrupted certgen leaves an empty file that would only
   * fail later, inside mbedTLS. */
  return stat(path, &st) == 0 && S_ISREG(st.st_mode) && st.st_size > 0;
}

/* Fills cert/key with the pair to use, or returns false if there is none. */
static bool resolve_tls_paths(const char **cert, const char **key) {
  size_t i;

  if (g_cfg.tls_cert[0] && g_cfg.tls_key[0]) {
    /* Explicitly configured: use it or fail, never silently fall back to
     * something else. An operator who named a certificate wants to know it is
     * missing, not to get a different one. */
    *cert = g_cfg.tls_cert;
    *key = g_cfg.tls_key;
    return true;
  }
  if (g_cfg.tls_cert[0] || g_cfg.tls_key[0]) {
    syslog(LOG_WARNING,
           "ws: motors.ws_tls_cert and ws_tls_key must be set together; "
           "ignoring the one that is set");
  }

  for (i = 0; i < sizeof(g_tls_candidates) / sizeof(g_tls_candidates[0]); i++) {
    if (file_is_usable(g_tls_candidates[i][0]) &&
        file_is_usable(g_tls_candidates[i][1])) {
      *cert = g_tls_candidates[i][0];
      *key = g_tls_candidates[i][1];
      return true;
    }
  }
  return false;
}

/* Publish whether wss:// is actually available, for json-motor-token.cgi.
 * Best effort in both directions: a camera whose /run is somehow unwritable
 * still serves TLS fine, the page just does not learn about it and stays on
 * the CGI path - which is the same place it would have been anyway. */
static void publish_tls_flag(bool on) {
  if (!on) {
    unlink(MOTOR_WS_TLS_FLAG_FILE);
    return;
  }
  {
    int fd = open(MOTOR_WS_TLS_FLAG_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0)
      close(fd);
  }
}

/* Load the certificate, or decide to live without one. Never fails the
 * listener: plain ws:// is the fallback for every problem here, and it is
 * exactly what this daemon served before wss:// existed. */
static void tls_init(void) {
  const char *cert = NULL, *key = NULL;

  if (!g_cfg.tls_enabled) {
    syslog(LOG_INFO, "ws: TLS disabled by motors.ws_tls");
    publish_tls_flag(false);
    return;
  }
  if (!resolve_tls_paths(&cert, &key)) {
    syslog(LOG_INFO, "ws: no TLS certificate found, serving plain ws:// only");
    publish_tls_flag(false);
    return;
  }

  g_tls = ws_tls_ctx_new(cert, key);
  if (!g_tls) {
    /* ws_tls_ctx_new() logged the specific reason at LOG_ERR. */
    syslog(LOG_WARNING, "ws: TLS setup failed, serving plain ws:// only");
    publish_tls_flag(false);
    return;
  }

  syslog(LOG_INFO, "ws: wss:// enabled using %s", cert);
  publish_tls_flag(true);
}
#endif /* MOTORS_WS_TLS */

int motor_ws_start(motor_ws_cfg *cfg) {
  struct sockaddr_in addr;
  int lfd, one = 1;

  g_cfg = *cfg;

  /* Sanity-clamp anything that came from the config file before it can
   * become a divisor, a buffer size or a thread budget. */
  g_cfg.port = clampi(g_cfg.port, 1, 65535);
  g_cfg.max_clients = clampi(g_cfg.max_clients, 1, 32);
  for (int i = 0; i < WS_MAX_PENDING; i++)
    g_pending[i].fd = -1;
  g_cfg.rate_limit = clampi(g_cfg.rate_limit, 1, 500);
  g_cfg.push_ms = clampi(g_cfg.push_ms, 50, 5000);

  if (!ws_token_init(g_cfg.token, g_cfg.token_file)) {
    syslog(LOG_ERR, "ws: no usable credential, refusing to start the listener; "
                    "set motors.ws_token or fix /dev/urandom");
    memset(g_cfg.token, 0, sizeof(g_cfg.token));
    memset(cfg->token, 0, sizeof(cfg->token));
    return -1;
  }

  /* Hashed by ws_token_init(); no reason to keep the plaintext anywhere. */
  memset(g_cfg.token, 0, sizeof(g_cfg.token));
  memset(cfg->token, 0, sizeof(cfg->token));

  lfd = socket(AF_INET, SOCK_STREAM, 0);
  if (lfd < 0) {
    syslog(LOG_ERR, "ws: socket() failed: %s", strerror(errno));
    return -1;
  }

  setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons((unsigned short)g_cfg.port);
  if (inet_pton(AF_INET, g_cfg.bind_addr, &addr.sin_addr) != 1)
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

  if (bind(lfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    syslog(LOG_ERR, "ws: bind to %s:%d failed: %s", g_cfg.bind_addr, g_cfg.port,
           strerror(errno));
    close(lfd);
    return -1;
  }

  if (listen(lfd, 8) < 0) {
    syslog(LOG_ERR, "ws: listen failed: %s", strerror(errno));
    close(lfd);
    return -1;
  }

  /* TLS.
   *
   * Before the listener thread exists, because the connection threads it
   * spawns read g_tls with no lock - this is the only writer, and it has to be
   * finished before any reader can run.
   *
   * The listener used to be plain ws:// only, on the reasoning that the LAN is
   * this firmware's accepted trust boundary. What changed is not the threat
   * model but the browser's: once the WebUI is served over https://, a plain
   * ws:// connection from that page is blocked as mixed content, and the PTZ
   * panel silently falls back to one CGI round trip per command - which is the
   * exact cost this whole frontend exists to remove. So wss:// is not a
   * hardening measure here, it is what keeps the fast path reachable. */
#ifdef MOTORS_WS_TLS
  tls_init();
#endif

  /* Bounded like every other thread here; the default would reserve
   * megabytes of address space for a loop that holds a sockaddr. */
  if (motor_spawn_detached(listen_thread, (void *)(long)lfd, WS_STACK_PLAIN) !=
      0) {
    syslog(LOG_ERR, "ws: cannot spawn listener thread");
    close(lfd);
#ifdef MOTORS_WS_TLS
    if (g_tls) {
      ws_tls_ctx_free(g_tls);
      g_tls = NULL;
    }
    publish_tls_flag(false);
#endif
    return -1;
  }

#ifdef MOTORS_WS_TLS
  if (g_tls) {
    syslog(LOG_INFO,
           "ws: listening on ws:// and wss://%s:%d%s (max %d clients, %d "
           "cmd/s)",
           g_cfg.bind_addr, g_cfg.port, WS_PATH, g_cfg.max_clients,
           g_cfg.rate_limit);
    return 0;
  }
#endif
  syslog(LOG_INFO, "ws: listening on ws://%s:%d%s (max %d clients, %d cmd/s)",
         g_cfg.bind_addr, g_cfg.port, WS_PATH, g_cfg.max_clients,
         g_cfg.rate_limit);
  return 0;
}

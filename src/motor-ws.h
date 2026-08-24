#ifndef MOTORS_MOTOR_WS_H
#define MOTORS_MOTOR_WS_H

#include <stdbool.h>

/* The motors-specific half of the WebSocket frontend: listener, access
 * control, and the JSON command protocol that maps onto the motor_ctl_*
 * handlers. The RFC 6455 mechanics it stands on are in ws.c/ws.h.
 *
 * Why this lives inside motors-daemon rather than in a gateway process: the
 * whole point of the change is to delete hops. Today a held PTZ button costs
 * three process spawns and two fresh socket connections every 90 ms
 * (busybox-httpd -> json-motor.cgi -> `motors` -> AF_UNIX -> daemon, then
 * `motors -j` again for the status echo). A separate WS bridge that RPC'd
 * back into this daemon would put one of those hops straight back. It also
 * matches how every other daemon in this firmware works - each one owns and
 * serves its own protocol; nothing routes through a shared front door. */

/* Default listen port for ws://<camera>:8089/ws. Configurable via
 * motors.ws_port; 8089 is chosen to sit clear of busybox-httpd (80/443) and
 * of the streamer's HTTP/RTSP ports. */
#define MOTOR_WS_DEFAULT_PORT 8089

/* Continuous ("hold to move") control: a CLIENT CONVENTION, not a wire mode.
 *
 * Hold a direction, the camera moves until you let go. There is deliberately
 * no {"mode":"cont"} for this, because the two primitives that already exist
 * express it exactly:
 *
 *   pointerdown -> {"cmd":"move","mode":"rel","x":<+/- x_max>}
 *   pointerup   -> {"cmd":"stop"}
 *
 * and the daemon does the right thing with both, verified against the
 * handlers rather than assumed:
 *
 *  - Clamping. motor_ctl_relative() adds the delta to the current position,
 *    clamps the TARGET to the runtime travel limit, and recomputes the delta
 *    from the clamped target. An oversized delta therefore becomes exactly
 *    "the distance remaining to that limit" - the client does not need to
 *    know the travel to ask for all of it.
 *
 *  - No magic number needed. Every "hello"/"status" frame carries x_max and
 *    y_max, so a client sends +/-x_max and gets a clean full-travel move.
 *    That is also the honest failure signal: a camera whose limits are
 *    unknown reports x_max = 0, and a client that sees 0 must fall back to
 *    fixed-size steps rather than inventing a large constant - with no limit
 *    to clamp against, motor_ctl_relative() would pass that constant to the
 *    hardware verbatim.
 *
 *  - Holding at the limit is a no-op, not an oscillation. The 24-step edge
 *    deadband in motor_ctl_relative() collapses "already at the edge, asked
 *    to go further" to a zero delta, which run_profiled_move() returns from
 *    immediately.
 *
 *  - Release cancels mid-flight. motor_ctl_stop() bypasses the command mutex
 *    (see motor-ctl.h) so it reaches MOTOR_STOP immediately even while a move
 *    is in progress; the generation bump then makes the in-flight profile
 *    abort at its next phase boundary instead of continuing to the target.
 *
 * The one thing that did NOT already work is the wait budget - see
 * chunk_timeout_ms() in motor-daemon.c. A full-travel chunk does not fit the
 * fixed nudge-sized timeout that every wait here used to share. */

typedef struct {
  bool enabled;
  int port;
  char bind_addr[48];  /* "0.0.0.0", or "127.0.0.1" to keep it host-local */
  char token[128];     /* motors.ws_token: optional persistent secret.
                        * motor_ws_start() hashes it and then WIPES this
                        * field, so the plaintext has the shortest possible
                        * lifetime in the daemon's address space. */
  char token_file[128];/* where the per-boot token is published, mode 0640 */
  char origins[256];   /* comma-separated extra allowed Origins; same-host is
                        * always allowed without listing it */
  int max_clients;     /* hard cap on simultaneous connections */
  int rate_limit;      /* commands per second, per connection */
  int push_ms;         /* default status push cadence */
} motor_ws_cfg;

void motor_ws_cfg_defaults(motor_ws_cfg *cfg);

/* Bind the listener and spawn its accept thread. Returns 0 on success, -1 if
 * the socket could not be set up (which is logged and non-fatal for the
 * daemon as a whole - the AF_UNIX frontend keeps working either way, and a
 * camera that cannot bind a TCP port should still be drivable by the CLI).
 * cfg is consumed: the caller's copy of cfg->token is wiped. */
int motor_ws_start(motor_ws_cfg *cfg);

#endif /* MOTORS_MOTOR_WS_H */

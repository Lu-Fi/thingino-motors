#ifndef MOTORS_MOTOR_CTL_H
#define MOTORS_MOTOR_CTL_H

#include <stdbool.h>

/* The daemon's motor-control operations, as functions.
 *
 * These are the bodies that used to be inlined in main()'s
 * `switch (request_message.command)` block, lifted out unchanged so that the
 * AF_UNIX frontend (/dev/md, spoken by the `motors` CLI) and the WebSocket
 * frontend (motor-ws.c) call ONE implementation instead of two that can
 * drift. The extraction is mechanical: same clamping, same edge deadbands,
 * same coordinate-frame conversions, same logging, same order of ioctls.
 *
 * Frames: every x/y that crosses this interface is LOGICAL (the frame the
 * web UI, ONVIF and ptz_presets speak, where +x/+y always mean the same
 * apparent direction on screen). The raw-vs-logical conversion happens
 * inside, exactly where it did before. See the large "Coordinate frames."
 * comment in motor-daemon.c. */

/* Kept identical to the copy in motor.c - these two structs are the AF_UNIX
 * wire format and the CLI has its own declaration of them. */
enum motor_status {
  MOTOR_IS_STOP,
  MOTOR_IS_RUNNING,
  /* Only ever sent as the status field of the 'R' (reload) ack, never
   * produced by MOTOR_GET_STATUS. Lets "motors -R" tell a failed reload
   * (config missing/invalid, defaults now in effect) apart from a normal
   * idle/running status without changing the wire format for any other
   * command. Keep this enum's values identical to the copy in motor.c. */
  MOTOR_RELOAD_FAILED,
};

struct motor_message {
  int x;
  int y;
  enum motor_status status;
  int speed;
  /* these two members are not standard from the original kernel module */
  unsigned int x_max_steps;
  unsigned int y_max_steps;
  unsigned int inversion_state; /* Report the inversion state */
};

/* --- serialisation ---------------------------------------------------
 *
 * Before the WebSocket listener existed, "one command at a time" was a free
 * property of the architecture: main() ran a single blocking accept() loop,
 * so no two requests could ever be in a handler simultaneously. A second
 * frontend on its own threads destroys that for free, and the handlers below
 * are full of read-modify-write sequences against shared state
 * (last_known_speed, motor_inversion_state, g_cfg) and multi-ioctl sequences
 * that must not interleave (motor_steps_impl()'s wait-then-set-speed-then-
 * move, the shared-data-channel XY split).
 *
 * Rather than audit and lock each of those individually - which would be a
 * rewrite, and would change behaviour for the existing AF_UNIX path - the
 * command mutex restores the old invariant verbatim: exactly one command
 * body runs at a time, whichever frontend it arrived on. Every motor_ctl_*
 * call below takes it internally.
 *
 * What this deliberately does NOT cover: the detached async move worker
 * (async_move_worker) still reads g_cfg and motor_inversion_state without
 * the lock. That is pre-existing, acknowledged behaviour (see the comment on
 * the 'R' reload handler), not something this change introduces or fixes.
 *
 * Consequence worth knowing: a long synchronous command - homing runs up to
 * ~35 s - holds the mutex for its whole duration and stalls the other
 * frontend. That is the same stall the AF_UNIX loop always had; it is now
 * merely visible from two directions. motor_ctl_trylock() exists so the WS
 * layer can answer "busy" instead of parking a connection thread on it. */
void motor_ctl_lock(void);
bool motor_ctl_trylock(void);
void motor_ctl_unlock(void);

/* Resolve the speed for one request the way the pre-switch block in main()
 * always did: a non-zero requested speed is sanitized, becomes the new
 * last_known_speed and is pushed to the driver; zero means "reuse the last
 * known speed" and touches nothing. Returns the speed to use.
 *
 * Takes the command lock internally, then releases it before the caller
 * invokes the actual move handler. The gap is deliberate and harmless: the
 * resolved speed is carried BY VALUE into the handler, and motor_steps_impl()
 * re-applies it to the driver on every move anyway, so a concurrent speed
 * change from the other frontend can at worst affect the next move, never
 * corrupt this one. */
int motor_ctl_resolve_speed(int requested_speed);

/* Relative jog ('d'/'g'). rel_x/rel_y are a logical delta. The applied delta
 * (after clamping to the travel limits and after the edge deadband) is
 * written to applied_x/applied_y when they are non-NULL - the AF_UNIX path
 * needs them because it logs the mutated request. */
void motor_ctl_relative(int rel_x, int rel_y, int speed, int *applied_x,
                        int *applied_y);

/* Continuous "analog stick" move. WebSocket only - the AF_UNIX protocol has
 * no gesture that needs it.
 *
 * vx/vy are a signed per-mille DEFLECTION of a virtual joystick in the
 * logical frame (-1000..1000), not a distance: how hard the stick is pushed
 * on each axis. ref_speed is what full deflection should reach, sanitized
 * like every other request's speed; 0 means the daemon's current default.
 *
 * Why this is not simply 'move' re-sent with a new speed every few frames.
 * motor_steps() opens with wait_until_idle(5000), so a move issued while
 * another is still running parks its worker for up to five seconds before
 * anything happens, and start_profiled_move_async()'s generation handoff
 * cancels the old profile without stopping the hardware, so each re-issue
 * leaves another detached worker sitting in a wait it cannot finish. A held
 * stick at 11 messages/s would do that for the whole gesture.
 *
 * So the deflection is split the way the hardware actually takes it. A
 * DIRECTION change is rare (there are only eight, and reversing a stepper
 * needs a stop regardless) and gets one full-travel move. A MAGNITUDE change
 * is continuous and gets a bare MOTOR_SPEED_AXIS ioctl, which the driver
 * applies to the move already in flight - verified on a T31/wuuk unit
 * (2026-08-24): a 3500-step move issued at speed 120 was running at ~122
 * steps/s, and `motors -s 900` mid-move took it to ~910 steps/s within one
 * one-second sample, with no stutter and no restart.
 *
 * Returns false when the travel limits are unknown for an axis the stick is
 * asking to move (x_max/y_max 0 and nothing configured): "go until the limit"
 * has no meaning then, and nothing was issued. speed_x/speed_y, when
 * non-NULL, receive the per-axis speeds actually commanded. */
bool motor_ctl_vector(int vx, int vy, int ref_speed, int *speed_x,
                      int *speed_y);

/* Absolute move ('d'/'h'). x/y are logical; got_x/got_y say whether the
 * caller actually specified that axis (0 = keep the current position). The
 * resolved RAW targets are written to target_x/target_y when non-NULL. */
void motor_ctl_absolute(int x, int got_x, int y, int got_y, int speed,
                        int *target_x, int *target_y);

/* 'd'/'s'. Also releases any stick direction held by motor_ctl_vector(), so
 * the gesture after a stop always starts with a fresh move rather than a
 * speed push against a move that is no longer running. */
void motor_ctl_stop(void);
void motor_ctl_goback(void); /* 'd'/'b' */
void motor_ctl_cruise(void); /* 'd'/'c' */
void motor_ctl_home(int speed); /* 'r' - SYNCHRONOUS, can take tens of seconds */

/* Status in the logical frame, ready to hand back to a caller as an absolute
 * target. Blocks on the command lock. */
void motor_ctl_status(struct motor_message *out);

/* Non-blocking status read: returns false and leaves *out untouched if a
 * command is currently in a handler.
 *
 * The WebSocket status-push loop uses this rather than motor_ctl_status().
 * A push is a periodic nicety - missing one costs a client one stale frame -
 * whereas blocking on it would park the connection thread for the duration
 * of whatever is holding the lock. During a homing sweep that is tens of
 * seconds during which the client could not send anything, including the
 * stop it probably wants. Skipping the sample is strictly better than
 * freezing the socket. */
bool motor_ctl_status_try(struct motor_message *out);

void motor_ctl_set_speed(int speed); /* 's' */
void motor_ctl_invert(char axis);    /* 'I', axis in {'x','y','b'} */

/* 'R' - reload /etc/thingino.json. Returns false if the reload failed (config
 * now at defaults). Fills out with fresh logical status. */
bool motor_ctl_reload(struct motor_message *out);

#endif /* MOTORS_MOTOR_CTL_H */

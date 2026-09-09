#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <unistd.h>

#include <json_config.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>

#include "motor-ctl.h"
/* The WebSocket frontend is optional at compile time.
 *
 * It is a build-time switch and not just a runtime one because the packaging
 * that consumes this tree compiles a chosen list of .c files directly rather
 * than running this repo's Makefile - thingino's package/thingino-motors has
 * a Kconfig option (BR2_PACKAGE_THINGINO_MOTORS_WS) that decides whether
 * sha1/sha256/ws/ws_token/motor-ws are in the link at all, and passes
 * -DMOTORS_WS when they are. Without this guard, an unselected build fails to
 * link on motor_ws_start(), which is what happens today; with it, a camera
 * that does not want the listener does not carry ~25 KB of protocol code it
 * can never reach.
 *
 * This repo's own Makefile always builds the full set and defines MOTORS_WS;
 * `make WS=0` reproduces the lean configuration. */
#ifdef MOTORS_WS
#include "motor-ws.h"
#endif

// Configuration structures
#define MOTOR_GPIO_STR_LEN 64
#define MOTOR_POS_STR_LEN 32

typedef struct {
  int max_steps; // maximum steps for axis
  int home;      // center/home position
  int speed;     // max/default speed for axis
  int accel;     // acceleration in steps/s^2 (0 disables ramping)
  int timeout;   // seconds
} AxisCfg;

typedef struct {
  bool gpio_invert;
  bool homing;
  bool is_spi;
  bool limitless;
  int gpio_power;
  int gpio_switch;
  char gpio_pan[MOTOR_GPIO_STR_LEN];
  char gpio_tilt[MOTOR_GPIO_STR_LEN];
  char pos0[MOTOR_POS_STR_LEN];
} MotorHwCfg;

typedef struct {
  int loglevel; // 0=DEBUG,1=INFO (simple mapping)
  AxisCfg pan;  // X axis
  AxisCfg tilt; // Y axis
  MotorHwCfg hw;
  bool loaded; // whether configuration was loaded
  double joystick_curve_exp; // see vector_axis_speed()
} MotorConfig;

#define VECTOR_CURVE_EXP_DEFAULT 2.0

static MotorConfig g_cfg = {
    .loglevel = 0,
    .pan = {0, 0, 0, 0, 0},
    .tilt = {0, 0, 0, 0, 0},
    .hw = {0},
    .loaded = false,
    .joystick_curve_exp = VECTOR_CURVE_EXP_DEFAULT,
};

static bool debug_mode = false;
static bool limits_seeded = false;

// Moved here from below so parse_modern_layout can apply config-time inversion.
enum motor_inversion {
  MOTOR_NO_INVERSION = 0x0,
  MOTOR_INVERT_X = 0x1,
  MOTOR_INVERT_Y = 0x2,
  MOTOR_INVERT_BOTH = 0x3
};

enum motor_inversion motor_inversion_state = MOTOR_NO_INVERSION;

static bool value_is_truthy(const char *value) {
  if (!value || !*value)
    return false;
  if (!strcmp(value, "0"))
    return false;
  if (!strcasecmp(value, "false"))
    return false;
  if (!strcasecmp(value, "off"))
    return false;
  return true;
}

static bool env_debug_enabled(void) {
  const char *env = getenv("DEBUG");
  return value_is_truthy(env);
}

static void configure_logmask(void) {
  int level = debug_mode ? LOG_DEBUG : LOG_INFO;
  setlogmask(LOG_UPTO(level));
}

static void write_sysfs_bool(const char *path, bool enabled,
                             const char *label) {
  int fd = open(path, O_WRONLY);
  if (fd < 0) {
    if (debug_mode) {
      syslog(LOG_DEBUG, "%s knob %s unavailable: %s", label ? label : "sysfs",
             path, strerror(errno));
    }
    return;
  }

  const char *payload = enabled ? "1\n" : "0\n";
  ssize_t written = write(fd, payload, strlen(payload));
  if (written == -1 && debug_mode) {
    syslog(LOG_DEBUG, "Failed to write '%s' to %s: %s", payload, path,
           strerror(errno));
  }
  close(fd);
}

static void sync_kernel_debug(bool enabled) {
  write_sysfs_bool("/sys/module/motor/parameters/debug", enabled,
                   "Kernel debug");
}

static void sync_kernel_limit_mode(bool disable_limits) {
  write_sysfs_bool("/sys/module/motor/parameters/nolimits", disable_limits,
                   "Kernel nolimits");
}

static int parse_loglevel(const char *s) {
  if (!s)
    return 0; // default DEBUG
  if (strcasecmp(s, "INFO") == 0)
    return 1;
  if (strcasecmp(s, "DEBUG") == 0)
    return 0;
  return 0;
}

static int json_get_int_jct(JsonValue *obj, const char *key, int *out) {
  if (!obj || obj->type != JSON_OBJECT || !key || !out)
    return 0;

  JsonValue *value = get_object_item(obj, key);
  if (!value)
    return 0;

  if (value->type == JSON_NUMBER) {
    *out = (int)(value->value.number.kind == JSON_NUMBER_INT
                     ? value->value.number.integer
                     : value->value.number.real);
    return 1;
  }

  if (value->type == JSON_STRING && value->value.string &&
      value->value.string[0] != '\0') {
    char *endptr = NULL;
    long parsed = strtol(value->value.string, &endptr, 10);
    if (endptr && *endptr == '\0') {
      *out = (int)parsed;
      return 1;
    }
  }

  return 0;
}

static int json_get_double_jct(JsonValue *obj, const char *key, double *out) {
  if (!obj || obj->type != JSON_OBJECT || !key || !out)
    return 0;

  JsonValue *value = get_object_item(obj, key);
  if (!value)
    return 0;

  if (value->type == JSON_NUMBER) {
    *out = (value->value.number.kind == JSON_NUMBER_INT
                ? (double)value->value.number.integer
                : value->value.number.real);
    return 1;
  }

  if (value->type == JSON_STRING && value->value.string &&
      value->value.string[0] != '\0') {
    char *endptr = NULL;
    double parsed = strtod(value->value.string, &endptr);
    if (endptr && *endptr == '\0') {
      *out = parsed;
      return 1;
    }
  }

  return 0;
}

static const char *json_get_string_jct(JsonValue *obj, const char *key) {
  if (!obj || obj->type != JSON_OBJECT || !key)
    return NULL;

  JsonValue *value = get_object_item(obj, key);
  if (value && value->type == JSON_STRING)
    return value->value.string;

  return NULL;
}

static int json_get_bool_jct(JsonValue *obj, const char *key, bool *out) {
  if (!obj || obj->type != JSON_OBJECT || !key || !out)
    return 0;

  JsonValue *value = get_object_item(obj, key);
  if (!value)
    return 0;

  if (value->type == JSON_BOOL) {
    *out = value->value.boolean;
    return 1;
  }

  if (value->type == JSON_NUMBER) {
    *out = (value->value.number.kind == JSON_NUMBER_INT
                ? value->value.number.integer != 0
                : value->value.number.real != 0.0);
    return 1;
  }

  if (value->type == JSON_STRING && value->value.string &&
      value->value.string[0] != '\0') {
    const char *s = value->value.string;
    if (strcasecmp(s, "true") == 0 || strcasecmp(s, "yes") == 0 ||
        strcasecmp(s, "on") == 0 || strcmp(s, "1") == 0) {
      *out = true;
      return 1;
    }
    if (strcasecmp(s, "false") == 0 || strcasecmp(s, "no") == 0 ||
        strcasecmp(s, "off") == 0 || strcmp(s, "0") == 0) {
      *out = false;
      return 1;
    }
  }

  return 0;
}

static bool parse_pos0_string(const char *pos0, int *pan_home, int *tilt_home) {
  if (!pos0 || !pan_home || !tilt_home)
    return false;

  char *endptr = NULL;
  long pan = strtol(pos0, &endptr, 10);
  if (endptr == pos0)
    return false;

  while (*endptr != '\0' && isspace((unsigned char)*endptr))
    ++endptr;

  if (*endptr != ',')
    return false;
  ++endptr;

  while (*endptr != '\0' && isspace((unsigned char)*endptr))
    ++endptr;

  if (*endptr == '\0')
    return false;

  char *tilt_end = NULL;
  long tilt = strtol(endptr, &tilt_end, 10);
  if (tilt_end == endptr)
    return false;

  while (*tilt_end != '\0') {
    if (!isspace((unsigned char)*tilt_end))
      return false;
    ++tilt_end;
  }

  *pan_home = (int)pan;
  *tilt_home = (int)tilt;
  return true;
}

static void sanitize_axis_cfg(AxisCfg *axis) {
  if (!axis)
    return;

  if (axis->max_steps < 0)
    axis->max_steps = 0;
  if (axis->speed < 0)
    axis->speed = 0;
  if (axis->accel < 0)
    axis->accel = 0;
  if (axis->timeout < 0)
    axis->timeout = 0;
  if (axis->home < 0)
    axis->home = 0;
  if (axis->max_steps > 0 && axis->home > axis->max_steps)
    axis->home = axis->max_steps / 2;
}

static void reset_config_defaults(void) {
  g_cfg.loglevel = 0;
  g_cfg.pan = (AxisCfg){0};
  g_cfg.tilt = (AxisCfg){0};
  g_cfg.hw = (MotorHwCfg){0};
  g_cfg.hw.limitless = false;
  g_cfg.hw.gpio_switch = -1;
  g_cfg.hw.gpio_power = -1;
  g_cfg.loaded = false;
  g_cfg.joystick_curve_exp = VECTOR_CURVE_EXP_DEFAULT;
}

static bool parse_modern_layout(JsonValue *root, JsonValue *motors) {
  if (!motors || motors->type != JSON_OBJECT)
    return false;

  bool parsed = false;

  const char *loglevel = json_get_string_jct(motors, "loglevel");
  if (!loglevel)
    loglevel = json_get_string_jct(root, "loglevel");
  if (loglevel) {
    g_cfg.loglevel = parse_loglevel(loglevel);
    parsed = true;
  }

  const char *driver_mode = json_get_string_jct(motors, "motion_driver");
  if (!driver_mode)
    driver_mode = json_get_string_jct(motors, "driver");
  if (!driver_mode)
    driver_mode = json_get_string_jct(root, "motion_driver");
  if (!driver_mode)
    driver_mode = json_get_string_jct(root, "driver");
  if (driver_mode)
    parsed = true;

  bool bool_value = false;
  if (json_get_bool_jct(motors, "gpio_invert", &bool_value)) {
    g_cfg.hw.gpio_invert = bool_value;
    parsed = true;
  }
  // Apply config-time axis inversion (invert_x / invert_y from thingino.json).
  // load_config_file() zeroes motor_inversion_state before calling here, so
  // these XORs act as an idempotent set; runtime "motors -I" IPC toggles then
  // XOR on top until the next reload/restart.
  bool invert_x = false, invert_y = false;
  if (json_get_bool_jct(motors, "invert_x", &invert_x)) {
    if (invert_x)
      motor_inversion_state ^= MOTOR_INVERT_X;
    parsed = true;
  }
  if (json_get_bool_jct(motors, "invert_y", &invert_y)) {
    if (invert_y)
      motor_inversion_state ^= MOTOR_INVERT_Y;
    parsed = true;
  }
  if (json_get_bool_jct(motors, "homing", &bool_value)) {
    g_cfg.hw.homing = bool_value;
    parsed = true;
  }
  if (json_get_bool_jct(motors, "is_spi", &bool_value)) {
    g_cfg.hw.is_spi = bool_value;
    parsed = true;
  }
  bool limitless_value = false;
  if (json_get_bool_jct(motors, "limitless", &limitless_value) ||
      json_get_bool_jct(motors, "nolimits", &limitless_value)) {
    g_cfg.hw.limitless = limitless_value;
    parsed = true;
  }

  parsed |= json_get_int_jct(motors, "gpio_power", &g_cfg.hw.gpio_power);
  parsed |= json_get_int_jct(motors, "gpio_switch", &g_cfg.hw.gpio_switch);

  const char *gpio_pan = json_get_string_jct(motors, "gpio_pan");
  if (gpio_pan) {
    strncpy(g_cfg.hw.gpio_pan, gpio_pan, sizeof(g_cfg.hw.gpio_pan) - 1);
    g_cfg.hw.gpio_pan[sizeof(g_cfg.hw.gpio_pan) - 1] = '\0';
    parsed = true;
  }

  const char *gpio_tilt = json_get_string_jct(motors, "gpio_tilt");
  if (gpio_tilt) {
    strncpy(g_cfg.hw.gpio_tilt, gpio_tilt, sizeof(g_cfg.hw.gpio_tilt) - 1);
    g_cfg.hw.gpio_tilt[sizeof(g_cfg.hw.gpio_tilt) - 1] = '\0';
    parsed = true;
  }

  // The initial point is the first preset; pos_0 remains a fallback for
  // configs that predate the presets array.
  bool have_initial = false;
  JsonValue *presets = get_object_item(motors, "presets");
  if (presets && presets->type == JSON_ARRAY && get_array_size(presets) > 0) {
    JsonValue *first = get_array_item(presets, 0);
    if (first && first->type == JSON_OBJECT) {
      int hx = 0, hy = 0;
      if (json_get_int_jct(first, "x", &hx) && json_get_int_jct(first, "y", &hy)) {
        g_cfg.pan.home = hx;
        g_cfg.tilt.home = hy;
        snprintf(g_cfg.hw.pos0, sizeof(g_cfg.hw.pos0), "%d,%d", hx, hy);
        parsed = true;
        have_initial = true;
      }
    }
  }
  if (!have_initial) {
    const char *pos0 = json_get_string_jct(motors, "pos_0");
    if (pos0) {
      strncpy(g_cfg.hw.pos0, pos0, sizeof(g_cfg.hw.pos0) - 1);
      g_cfg.hw.pos0[sizeof(g_cfg.hw.pos0) - 1] = '\0';
      if (parse_pos0_string(pos0, &g_cfg.pan.home, &g_cfg.tilt.home))
        parsed = true;
    }
  }

  parsed |= json_get_int_jct(motors, "steps_pan", &g_cfg.pan.max_steps);
  parsed |= json_get_int_jct(motors, "steps_tilt", &g_cfg.tilt.max_steps);
  parsed |= json_get_int_jct(motors, "speed_pan", &g_cfg.pan.speed);
  parsed |= json_get_int_jct(motors, "speed_tilt", &g_cfg.tilt.speed);
  parsed |= json_get_int_jct(motors, "accel_pan", &g_cfg.pan.accel);
  parsed |= json_get_int_jct(motors, "accel_tilt", &g_cfg.tilt.accel);
  parsed |= json_get_int_jct(motors, "timeout_pan", &g_cfg.pan.timeout);
  parsed |= json_get_int_jct(motors, "timeout_tilt", &g_cfg.tilt.timeout);
  parsed |= json_get_int_jct(motors, "home_pan", &g_cfg.pan.home);
  parsed |= json_get_int_jct(motors, "home_tilt", &g_cfg.tilt.home);

  double curve_exp;
  if (json_get_double_jct(motors, "joystick_sensitivity", &curve_exp)) {
    // Valid range 0.05..4.0; see vector_axis_speed(). isnan() first: every
    // comparison with NaN is false, so the range check below would silently
    // accept a NaN string ("nan" parses cleanly via strtod()) and pow() of
    // it later poisons pct/sx/sy with UB on the double->int cast.
    if (isnan(curve_exp) || curve_exp < 0.05 || curve_exp > 4.0)
      curve_exp = VECTOR_CURVE_EXP_DEFAULT;
    g_cfg.joystick_curve_exp = curve_exp;
    parsed = true;
  }

  return parsed;
}

static bool parse_legacy_layout(JsonValue *root) {
  if (!root || root->type != JSON_OBJECT)
    return false;

  bool parsed = false;

  const char *loglevel = json_get_string_jct(root, "loglevel");
  if (loglevel) {
    g_cfg.loglevel = parse_loglevel(loglevel);
    parsed = true;
  }

  const char *driver_mode = json_get_string_jct(root, "motion_driver");
  if (!driver_mode)
    driver_mode = json_get_string_jct(root, "driver");
  if (driver_mode)
    parsed = true;

  bool limitless_value = false;
  if (json_get_bool_jct(root, "limitless", &limitless_value) ||
      json_get_bool_jct(root, "nolimits", &limitless_value)) {
    g_cfg.hw.limitless = limitless_value;
    parsed = true;
  }

  JsonValue *pan = get_object_item(root, "pan");
  if (pan && pan->type == JSON_OBJECT) {
    parsed |= json_get_int_jct(pan, "max_steps", &g_cfg.pan.max_steps);
    parsed |= json_get_int_jct(pan, "home", &g_cfg.pan.home);
    parsed |= json_get_int_jct(pan, "speed", &g_cfg.pan.speed);
    parsed |= json_get_int_jct(pan, "accel", &g_cfg.pan.accel);
    parsed |= json_get_int_jct(pan, "timeout", &g_cfg.pan.timeout);
  }

  JsonValue *tilt = get_object_item(root, "tilt");
  if (tilt && tilt->type == JSON_OBJECT) {
    parsed |= json_get_int_jct(tilt, "max_steps", &g_cfg.tilt.max_steps);
    parsed |= json_get_int_jct(tilt, "home", &g_cfg.tilt.home);
    parsed |= json_get_int_jct(tilt, "speed", &g_cfg.tilt.speed);
    parsed |= json_get_int_jct(tilt, "accel", &g_cfg.tilt.accel);
    parsed |= json_get_int_jct(tilt, "timeout", &g_cfg.tilt.timeout);
  }

  return parsed;
}

// The streamer's image flips (image.vflip / image.hflip in the streamer
// config) mirror the displayed picture, so the same head motion reads as the
// opposite screen direction on a flipped camera. XOR them into the inversion
// state right after the config's own invert_x/invert_y (load_config_file()
// zeroes the state first, so both XOR sets compose idempotently on every
// (re)load):
//
//   net_x = invert_x XOR hflip
//   net_y = invert_y XOR vflip
//
// The logical frame is thereby defined by what is on screen, and a camera
// mounted upside-down with vflip/hflip set in the streamer needs no hand-
// tuned invert_* for the mount. Missing config / keys mean "no flips".
// A flip change requires a reload ('R' IPC / S59motor reload) or restart to
// take effect, exactly like invert_x/invert_y.
static void apply_flip_inversion(void) {
  JsonValue *root = parse_json_file("/etc/prudynt.json");
  if (!root)
    return;
  if (root->type != JSON_OBJECT) {
    free_json_value(root);
    return;
  }

  JsonValue *image = get_object_item(root, "image");
  if (image && image->type == JSON_OBJECT) {
    bool hflip = false, vflip = false;
    if (json_get_bool_jct(image, "hflip", &hflip) && hflip)
      motor_inversion_state ^= MOTOR_INVERT_X;
    if (json_get_bool_jct(image, "vflip", &vflip) && vflip)
      motor_inversion_state ^= MOTOR_INVERT_Y;
  }

  free_json_value(root);
}

// Returns true if /etc/thingino.json was found, was a JSON object, and got
// parsed into g_cfg (even if some individual keys were missing and defaults
// were used for those); false if the file is missing, unreadable, or not a
// JSON object at the root, in which case g_cfg is left at reset_config_defaults()
// and callers must not treat the (re)load as having taken effect.
static bool load_config_file(void) {
  JsonValue *root = parse_json_file("/etc/thingino.json");
  reset_config_defaults();
  // The config file is authoritative for axis inversion on every (re)load.
  // parse_modern_layout() XORs invert_x/invert_y into this state, so it must
  // start from a known zero: without this reset, a reload ('R' command) with
  // an unchanged file would toggle inversion straight back OFF. This also
  // discards any runtime "motors -I" toggles, exactly as a daemon restart
  // always has.
  motor_inversion_state = MOTOR_NO_INVERSION;
  if (!root) {
    syslog(LOG_DEBUG, "No config file found; using defaults");
    return false;
  }

  if (root->type != JSON_OBJECT) {
    syslog(LOG_DEBUG, "Config file root is not a JSON object; ignoring");
    free_json_value(root);
    return false;
  }

  bool parsed = false;
  JsonValue *motors = get_object_item(root, "motors");
  if (motors && motors->type == JSON_OBJECT)
    parsed = parse_modern_layout(root, motors);

  if (!parsed)
    parsed = parse_legacy_layout(root);

  // Flip the logical frame with the displayed image before the home
  // mirroring below picks the net inversion up.
  apply_flip_inversion();

  if (parsed) {
    sanitize_axis_cfg(&g_cfg.pan);
    sanitize_axis_cfg(&g_cfg.tilt);
    // pos_0 / home_pan / home_tilt are written by humans and by the web UI,
    // so they are logical like every other coordinate that crosses the socket.
    // Everything that consumes g_cfg.*.home below (limit seeding, the homing
    // center target) works in raw steps, so mirror once here and let the rest
    // of the daemon stay raw.
    if (g_cfg.pan.max_steps > 0 && (motor_inversion_state & MOTOR_INVERT_X))
      g_cfg.pan.home = g_cfg.pan.max_steps - g_cfg.pan.home;
    if (g_cfg.tilt.max_steps > 0 && (motor_inversion_state & MOTOR_INVERT_Y))
      g_cfg.tilt.home = g_cfg.tilt.max_steps - g_cfg.tilt.home;
    g_cfg.loaded = true;
  } else {
    syslog(LOG_DEBUG, "Config file missing required keys; using defaults");
  }

  free_json_value(root);
  return true;
}

// WebSocket listener settings, read from the same /etc/thingino.json "motors"
// object as everything else and with the same json_get_*_jct() helpers, but
// deliberately on its own pass rather than inside parse_modern_layout():
//
// these keys configure a socket that is bound exactly once, at startup. If
// they rode along with the rest of the config they would also be re-read by
// the 'R' reload path, where a changed ws_port or ws_token could not possibly
// take effect - leaving g_cfg claiming one thing while the listener does
// another. Keeping the pass separate and calling it only from main() makes it
// structurally impossible for "motors -R" to half-apply a listener setting.
// A ws_* change needs a daemon restart, and that is now a property of the
// code rather than a note in a README.
#ifdef MOTORS_WS
static void load_ws_config_file(motor_ws_cfg *cfg) {
  JsonValue *root;
  JsonValue *motors;
  const char *s;
  bool b = false;

  motor_ws_cfg_defaults(cfg);

  root = parse_json_file("/etc/thingino.json");
  if (!root)
    return;
  if (root->type != JSON_OBJECT) {
    free_json_value(root);
    return;
  }

  motors = get_object_item(root, "motors");
  if (motors && motors->type == JSON_OBJECT) {
    if (json_get_bool_jct(motors, "ws_enabled", &b))
      cfg->enabled = b;

    (void)json_get_int_jct(motors, "ws_port", &cfg->port);
    (void)json_get_int_jct(motors, "ws_max_clients", &cfg->max_clients);
    (void)json_get_int_jct(motors, "ws_rate_limit", &cfg->rate_limit);
    (void)json_get_int_jct(motors, "ws_push_ms", &cfg->push_ms);

    s = json_get_string_jct(motors, "ws_bind");
    if (s) {
      strncpy(cfg->bind_addr, s, sizeof(cfg->bind_addr) - 1);
      cfg->bind_addr[sizeof(cfg->bind_addr) - 1] = '\0';
    }

    s = json_get_string_jct(motors, "ws_token");
    if (s) {
      strncpy(cfg->token, s, sizeof(cfg->token) - 1);
      cfg->token[sizeof(cfg->token) - 1] = '\0';
    }

    s = json_get_string_jct(motors, "ws_token_file");
    if (s) {
      strncpy(cfg->token_file, s, sizeof(cfg->token_file) - 1);
      cfg->token_file[sizeof(cfg->token_file) - 1] = '\0';
    }

    s = json_get_string_jct(motors, "ws_origins");
    if (s) {
      strncpy(cfg->origins, s, sizeof(cfg->origins) - 1);
      cfg->origins[sizeof(cfg->origins) - 1] = '\0';
    }

    // TLS. All three keys are optional and none of them needs to be set for
    // wss:// to work - motor_ws_start() finds the web UI's certificate on its
    // own. They exist for the two cases it cannot guess: turning wss:// off on
    // a camera that has a certificate but does not want the listener using it
    // (ws_tls), and pointing at a certificate somewhere else (ws_tls_cert +
    // ws_tls_key, which must be given together).
    if (json_get_bool_jct(motors, "ws_tls", &b))
      cfg->tls_enabled = b;

    s = json_get_string_jct(motors, "ws_tls_cert");
    if (s) {
      strncpy(cfg->tls_cert, s, sizeof(cfg->tls_cert) - 1);
      cfg->tls_cert[sizeof(cfg->tls_cert) - 1] = '\0';
    }

    s = json_get_string_jct(motors, "ws_tls_key");
    if (s) {
      strncpy(cfg->tls_key, s, sizeof(cfg->tls_key) - 1);
      cfg->tls_key[sizeof(cfg->tls_key) - 1] = '\0';
    }
  }

  // free_json_value() frees the string that cfg->token was copied out of, so
  // the plaintext secret now exists only in cfg - which motor_ws_start()
  // hashes and wipes.
  free_json_value(root);
}
#endif /* MOTORS_WS */

#define SV_SOCK_PATH "/dev/md"
#define MAX_CONN 5
#define MOTOR_MOVE_STOP 0x0
#define MOTOR_MOVE_RUN 0x1

/* directional_attr */
#define MOTOR_DIRECTIONAL_UP 0x0
#define MOTOR_DIRECTIONAL_DOWN 0x1
#define MOTOR_DIRECTIONAL_LEFT 0x2
#define MOTOR_DIRECTIONAL_RIGHT 0x3

#define MOTOR1_MAX_SPEED 2000
#define MOTOR1_MIN_SPEED 1

/* ioctl cmd */
#define MOTOR_STOP 0x1
#define MOTOR_RESET 0x2
#define MOTOR_MOVE 0x3
#define MOTOR_GET_STATUS 0x4
#define MOTOR_SPEED 0x5
#define MOTOR_GOBACK 0x6
#define MOTOR_CRUISE 0x7
#define MOTOR_SPEED_AXIS 0x8

#define MOTOR_ACTIVE_FLAG "/run/motors-active"
#define PID_SIZE 32

// enum motor_status and struct motor_message moved to motor-ctl.h so that
// motor-ws.c can build status pushes from the same declarations. The rest of
// the AF_UNIX wire structs stay here: the WebSocket frontend never sees them.

struct request {
  char command; // d,r,s,p,b,S,i,j,R (move, reset,set speed,get position, is
                // busy,Status,initial,JSON,Reload config)
  char type;    // g,h,c,s (absolute,relative,cruise,stop)
  int x;
  int got_x;
  int y;
  int got_y;
  int speed; // Add speed to the request structure
};

struct motor_status_st {
  int directional_attr;
  int total_steps;
  int current_steps;
  int min_speed;
  int cur_speed;
  int max_speed;
  int move_is_min;
  int move_is_max;
};

struct motors_steps {
  int x;
  int y;
};

struct motor_reset_data {
  unsigned int x_max_steps;
  unsigned int y_max_steps;
  unsigned int x_cur_step;
  unsigned int y_cur_step;
};

struct motor_axis_speed {
  int x_speed;
  int y_speed;
};

struct async_move {
  int x_steps;
  int y_steps;
  int speed;
  unsigned int generation;
};

int motorfd = -1;
struct request request_message; // object for IPC request from client
int last_known_speed = 900;  // Default speed (overridden by config if present)
bool motor_inverted = false; // Global flag for motor inversion
static pthread_mutex_t motion_lock = PTHREAD_MUTEX_INITIALIZER;
static unsigned int motion_generation = 0;
static bool motion_cancelled = false;

// Forward declaration used by motor_steps() before definition below.
static int wait_until_idle(int timeout_ms, int poll_ms);
static void compute_axis_speeds(int requested_speed, int *x_speed,
                                int *y_speed);
static void motor_set_axis_speed(int x_speed, int y_speed);
static bool motion_is_cancelled(unsigned int generation);
static void write_motion_active_flag(void);
static void remove_motion_active_flag(void);
static void start_motion_active_tracker(void);
static int get_motion_timeout_ms(void);
static int chunk_timeout_ms(int steps, int speed, int floor_ms);
static void physical_delta_to_steps(int *dx, int *dy);

// Derive the default speed from the loaded config. Shared between startup
// and the 'R' (reload) IPC command so both apply identical semantics.
static void apply_config_speed_default(void) {
  if (!g_cfg.loaded)
    return;

  int cfg_speed = 0;
  if (g_cfg.pan.speed > 0)
    cfg_speed = g_cfg.pan.speed;
  if (g_cfg.tilt.speed > 0 && g_cfg.tilt.speed > cfg_speed)
    cfg_speed = g_cfg.tilt.speed;
  if (cfg_speed > 0)
    last_known_speed = cfg_speed;
}

static int sanitize_requested_speed(int requested, int fallback) {
  int speed = (requested > 0) ? requested : fallback;

  if (speed < MOTOR1_MIN_SPEED)
    speed = MOTOR1_MIN_SPEED;
  if (speed > MOTOR1_MAX_SPEED)
    speed = MOTOR1_MAX_SPEED;

  return speed;
}

static bool uses_shared_motor_data_channel(void) {
  // Cameras with a switch GPIO typically multiplex one pulse channel
  // between pan and tilt, so combined XY pulses must be serialized.
  if (g_cfg.hw.gpio_switch >= 0)
    return true;

  if (g_cfg.hw.gpio_pan[0] != '\0' && g_cfg.hw.gpio_tilt[0] != '\0' &&
      strcmp(g_cfg.hw.gpio_pan, g_cfg.hw.gpio_tilt) == 0)
    return true;

  return false;
}

void motor_ioctl(int cmd, void *arg) {
  // basically exists to not pass around the motor FD
  int ret = ioctl(motorfd, cmd, arg);
  if (ret == -1) {
    syslog(LOG_ERR, "ioctl cmd 0x%x failed: %s", cmd, strerror(errno));
  }
}

static void motor_steps_impl(int xsteps, int ysteps, int stepspeed,
                             bool wait_before) {
  struct motors_steps steps;

  if (wait_before)
    wait_until_idle(5000, 20); // avoid overlapping commands

  // Apply the correct inversion based on the motor_inversion_state
  steps.x = (motor_inversion_state & MOTOR_INVERT_X) ? -xsteps : xsteps;
  steps.y = (motor_inversion_state & MOTOR_INVERT_Y) ? -ysteps : ysteps;

  syslog(LOG_DEBUG, "Starting relative move");
  int eff_speed_x = stepspeed;
  int eff_speed_y = stepspeed;

  compute_axis_speeds(stepspeed, &eff_speed_x, &eff_speed_y);

  syslog(LOG_DEBUG, " -> steps, X %d (speed %d), Y %d (speed %d)\n", steps.x,
         eff_speed_x, steps.y, eff_speed_y);

  if (uses_shared_motor_data_channel() && steps.x != 0 && steps.y != 0) {
    struct motors_steps x_only = {.x = steps.x, .y = 0};
    struct motors_steps y_only = {.x = 0, .y = steps.y};
    int timeout_ms = get_motion_timeout_ms();

    syslog(LOG_DEBUG,
           "Shared motor data channel detected, splitting XY move into X then Y");

    motor_set_axis_speed(eff_speed_x, eff_speed_y);
    motor_ioctl(MOTOR_MOVE, &x_only);
    // Same distance-scaling as run_profiled_move()'s waits: a diagonal
    // hold-to-move puts a full-travel X leg here, which does not fit the
    // fixed nudge-sized budget. See chunk_timeout_ms().
    if (wait_until_idle(chunk_timeout_ms(steps.x, eff_speed_x, timeout_ms),
                        10) != 0)
      return;

    motor_set_axis_speed(eff_speed_x, eff_speed_y);
    motor_ioctl(MOTOR_MOVE, &y_only);
    syslog(LOG_DEBUG, "Finished setting split relative move");
    return;
  }

  motor_set_axis_speed(eff_speed_x, eff_speed_y);
  motor_ioctl(MOTOR_MOVE, &steps);
  syslog(LOG_DEBUG, "Finished setting relative move");
}

static void compute_axis_speeds(int requested_speed, int *x_speed,
                                int *y_speed) {
  int xs = requested_speed;
  int ys = requested_speed;

  if (g_cfg.loaded) {
    if (g_cfg.pan.speed > 0 && xs > g_cfg.pan.speed)
      xs = g_cfg.pan.speed;
    if (g_cfg.tilt.speed > 0 && ys > g_cfg.tilt.speed)
      ys = g_cfg.tilt.speed;
  }

  if (x_speed)
    *x_speed = xs;
  if (y_speed)
    *y_speed = ys;
}

// Whether MOTOR_SPEED_AXIS (ioctl 0x8) exists on this kernel. Learned on the
// first attempt and never re-probed. Callers that only want to know how to
// SHAPE a request read it through motor_axis_speed_supported(); the ioctl
// itself always tries the per-axis form first and falls back on its own, so
// this is a hint, not a gate.
static bool axis_speed_supported = true;

static void motor_set_axis_speed(int x_speed, int y_speed) {
  static bool axis_speed_unsupported_logged = false;

  struct motor_axis_speed axis = {
      .x_speed = x_speed,
      .y_speed = y_speed,
  };

  int ret = ioctl(motorfd, MOTOR_SPEED_AXIS, &axis);
  if (ret == 0)
    return;

  // Some kernels do not support per-axis speed ioctl (0x8).
  if ((errno == EINVAL || errno == ENOTTY || errno == ENOSYS)) {
    int fallback_speed = (x_speed < y_speed) ? x_speed : y_speed;
    axis_speed_supported = false;
    if (fallback_speed < MOTOR1_MIN_SPEED)
      fallback_speed = MOTOR1_MIN_SPEED;
    if (fallback_speed > MOTOR1_MAX_SPEED)
      fallback_speed = MOTOR1_MAX_SPEED;
    if (!axis_speed_unsupported_logged) {
      syslog(LOG_INFO,
             "MOTOR_SPEED_AXIS unsupported, falling back to MOTOR_SPEED");
      axis_speed_unsupported_logged = true;
    }
    motor_ioctl(MOTOR_SPEED, &fallback_speed);
    return;
  }

  syslog(LOG_ERR, "ioctl cmd 0x%x failed: %s", MOTOR_SPEED_AXIS,
         strerror(errno));
}

static void seed_driver_limits_from_config(void) {
  if (limits_seeded)
    return;
  if (!g_cfg.loaded)
    return;
  if (!g_cfg.hw.limitless)
    return;
  if (g_cfg.pan.max_steps <= 0 || g_cfg.tilt.max_steps <= 0)
    return;

  struct motor_reset_data data = {
      .x_max_steps = (unsigned int)g_cfg.pan.max_steps,
      .y_max_steps = (unsigned int)g_cfg.tilt.max_steps,
  };

  data.x_cur_step = (g_cfg.pan.home > 0 && g_cfg.pan.home < g_cfg.pan.max_steps)
                        ? (unsigned int)g_cfg.pan.home
                        : data.x_max_steps / 2;
  data.y_cur_step =
      (g_cfg.tilt.home > 0 && g_cfg.tilt.home < g_cfg.tilt.max_steps)
          ? (unsigned int)g_cfg.tilt.home
          : data.y_max_steps / 2;

  syslog(LOG_INFO,
         "Applying configured max steps to kernel (x=%u home=%u, y=%u home=%u)",
         data.x_max_steps, data.x_cur_step, data.y_max_steps, data.y_cur_step);
  motor_ioctl(MOTOR_RESET, &data);
  limits_seeded = true;
}

static int read_uint_sysfs(const char *path, unsigned int *out) {
  FILE *f = fopen(path, "r");
  if (!f)
    return -1;
  char buf[64];
  if (!fgets(buf, sizeof(buf), f)) {
    fclose(f);
    return -1;
  }
  fclose(f);
  unsigned long v = 0;
  char *endp = NULL;
  v = strtoul(buf, &endp, 0);
  if (endp == buf)
    return -1;
  if (out)
    *out = (unsigned int)v;
  return 0;
}

static void motor_get_maxsteps_sysfs(unsigned int *maxx, unsigned int *maxy) {
  unsigned int x = 0, y = 0;
  (void)read_uint_sysfs("/sys/module/motor/parameters/hmaxstep", &x);
  (void)read_uint_sysfs("/sys/module/motor/parameters/vmaxstep", &y);
  if (maxx && x > 0)
    *maxx = x;
  if (maxy && y > 0)
    *maxy = y;
}

void motor_status_get(struct motor_message *msg) {
  if (!msg)
    return;

  // Kernel ioctl may not fill extension fields added in userspace struct.
  memset(msg, 0, sizeof(*msg));
  motor_ioctl(MOTOR_GET_STATUS, msg);

  // Single source of truth: when configured, always expose configured limits.
  // This keeps status, homing, clamping, and API responses consistent.
  if (g_cfg.loaded) {
    if (g_cfg.pan.max_steps > 0) {
      msg->x_max_steps = (unsigned int)g_cfg.pan.max_steps;
      // Clamp reported position to configured range to prevent drift past
      // limits (e.g. when invert_y causes the kernel counter to overshoot).
      if (msg->x < 0)
        msg->x = 0;
      if (msg->x > (int)g_cfg.pan.max_steps)
        msg->x = (int)g_cfg.pan.max_steps;
    }
    if (g_cfg.tilt.max_steps > 0) {
      msg->y_max_steps = (unsigned int)g_cfg.tilt.max_steps;
      if (msg->y < 0)
        msg->y = 0;
      if (msg->y > (int)g_cfg.tilt.max_steps)
        msg->y = (int)g_cfg.tilt.max_steps;
    }
  }

  msg->inversion_state = (unsigned int)motor_inversion_state;
}

void motor_get_maxsteps(unsigned int *maxx, unsigned int *maxy) {
  struct motor_message msg;
  motor_status_get(&msg);
  if (maxx)
    *maxx = msg.x_max_steps;
  if (maxy)
    *maxy = msg.y_max_steps;
}

int motor_is_busy() {
  struct motor_message msg;
  motor_status_get(&msg);
  return msg.status == MOTOR_IS_RUNNING ? 1 : 0;
}

void motor_steps(int xsteps, int ysteps, int stepspeed) {
  motor_steps_impl(xsteps, ysteps, stepspeed, true);
}

static int execute_profile_phase(int total, int phase_end, int xsteps,
                                 int ysteps, int *moved_x, int *moved_y,
                                 int *progress, int speed_now,
                                 int timeout_ms, unsigned int generation) {
  if (!moved_x || !moved_y || !progress)
    return -1;

  if (phase_end <= *progress)
    return 0;

  if (phase_end > total)
    phase_end = total;

  if (motion_is_cancelled(generation))
    return -1;

  int target_x =
      (int)(((long long)xsteps * (long long)phase_end) / (long long)total);
  int target_y =
      (int)(((long long)ysteps * (long long)phase_end) / (long long)total);
  int chunk_x = target_x - *moved_x;
  int chunk_y = target_y - *moved_y;

  *moved_x = target_x;
  *moved_y = target_y;
  *progress = phase_end;

  if (chunk_x == 0 && chunk_y == 0)
    return 0;

  motor_steps_impl(chunk_x, chunk_y, speed_now, false);
  {
    int chunk = (abs(chunk_x) > abs(chunk_y)) ? abs(chunk_x) : abs(chunk_y);
    if (wait_until_idle(chunk_timeout_ms(chunk, speed_now, timeout_ms), 10) != 0)
      return -1;
  }

  return 0;
}

void motor_set_position(int xpos, int ypos, int stepspeed) {
  struct motor_message msg;
  motor_status_get(&msg);

  int deltax = xpos - msg.x;
  int deltay = ypos - msg.y;

  syslog(LOG_DEBUG, "Starting absolute move");
  int eff_speed = stepspeed;
  syslog(LOG_DEBUG,
         " -> set position current X: %d, Y: %d, steps required X: %d, Y: %d, "
         "speed %d\n",
         msg.x, msg.y, deltax, deltay, eff_speed);
  physical_delta_to_steps(&deltax, &deltay);
  motor_steps(deltax, deltay, eff_speed);
  syslog(LOG_DEBUG, "Finished setting absolute move");
}

// Poll until motors are idle or timeout (milliseconds). Returns 0 on idle, -1
// on timeout/error
static int wait_until_idle(int timeout_ms, int poll_ms) {
  const int loops = (timeout_ms <= 0 || poll_ms <= 0)
                        ? 1
                        : (timeout_ms + poll_ms - 1) / poll_ms;
  for (int i = 0; i < loops; ++i) {
    struct motor_message msg;
    motor_status_get(&msg);
    if (msg.status == MOTOR_IS_STOP)
      return 0;
    usleep((useconds_t)poll_ms * 1000);
  }
  return -1;
}

static int get_motion_timeout_ms(void) {
  int to_s = 0;
  if (g_cfg.loaded) {
    to_s = (g_cfg.pan.timeout > g_cfg.tilt.timeout) ? g_cfg.pan.timeout
                                                    : g_cfg.tilt.timeout;
  }
  if (to_s <= 0)
    to_s = 10;
  return to_s * 1000;
}

// Time budget for waiting out ONE chunk of driver motion.
//
// get_motion_timeout_ms() is a FIXED budget (motors.timeout_pan/timeout_tilt,
// 10 s when unset - and it is unset on every camera in this fleet). That was
// fine while every move through here was a UI nudge: the old WebUI fires
// steps_pan/100 = 40 steps per tick, which finishes in a twentieth of a
// second. It stops being fine for a hold-to-move gesture, which is expressed
// as a relative delta larger than the travel and clamped by
// motor_ctl_relative() into "go to the far limit" - a single chunk of up to
// steps_pan (4000) steps. enhanced_homing_daemon() budgets 15 s for exactly
// that distance, more than the 10 s default this function has to work with,
// and a camera configured with speed_pan=300 needs more like 13 s.
//
// Overrunning is not benign, which is why this is worth fixing rather than
// documenting. wait_until_idle() failing makes execute_profile_phase() (or
// the accel<=0 fast path) return -1 WITHOUT ever issuing MOTOR_STOP, so the
// hardware carries on to the end of the chunk while async_move_worker()
// concludes the move is over and clears MOTOR_ACTIVE_FLAG - the motion-active
// flag then lies to every other consumer for the rest of the physical move.
//
// So scale the budget by the distance actually commanded. The driver steps at
// roughly `speed` steps per second; x2 covers the acceleration ramp inside
// the driver, scheduling on a busy MIPS core, and the 10 ms polling
// granularity of wait_until_idle() itself. floor_ms keeps the configured
// fixed budget as a lower bound, so no move that completes today is given a
// tighter deadline than it has now.
static int chunk_timeout_ms(int steps, int speed, int floor_ms) {
  long long est;

  if (steps < 0)
    steps = -steps;
  if (speed < MOTOR1_MIN_SPEED)
    speed = MOTOR1_MIN_SPEED;

  est = ((long long)steps * 1000LL * 2LL) / (long long)speed;

  if (est < (long long)floor_ms)
    est = (long long)floor_ms;
  // Absolute ceiling. speed is already clamped to >= 1 above, so a
  // pathological speed=1 with a full-travel delta would otherwise ask
  // wait_until_idle() to spin for over two hours.
  if (est > 120000LL)
    est = 120000LL;

  return (int)est;
}

static int get_effective_accel(void) {
  int a_pan = (g_cfg.loaded && g_cfg.pan.accel > 0) ? g_cfg.pan.accel : 0;
  int a_tilt = (g_cfg.loaded && g_cfg.tilt.accel > 0) ? g_cfg.tilt.accel : 0;

  if (a_pan > 0 && a_tilt > 0)
    return (a_pan < a_tilt) ? a_pan : a_tilt;
  if (a_pan > 0)
    return a_pan;
  return a_tilt;
}

static unsigned int motion_begin_new(void) {
  unsigned int generation;

  pthread_mutex_lock(&motion_lock);
  motion_generation++;
  motion_cancelled = false;
  generation = motion_generation;
  pthread_mutex_unlock(&motion_lock);

  return generation;
}

static bool motion_is_cancelled(unsigned int generation) {
  bool cancelled;

  pthread_mutex_lock(&motion_lock);
  cancelled = motion_cancelled || generation != motion_generation;
  pthread_mutex_unlock(&motion_lock);

  return cancelled;
}

static bool motion_is_current(unsigned int generation) {
  bool is_current;

  pthread_mutex_lock(&motion_lock);
  is_current = generation == motion_generation;
  pthread_mutex_unlock(&motion_lock);

  return is_current;
}

static void motion_cancel_all(bool stop_now) {
  pthread_mutex_lock(&motion_lock);
  motion_cancelled = true;
  motion_generation++;
  pthread_mutex_unlock(&motion_lock);

  if (stop_now)
    motor_ioctl(MOTOR_STOP, NULL);
}

static int run_profiled_move(int xsteps, int ysteps, int requested_speed,
                             unsigned int generation) {
  const int total = (abs(xsteps) > abs(ysteps)) ? abs(xsteps) : abs(ysteps);
  int max_speed_x = requested_speed;
  int max_speed_y = requested_speed;
  int moved_x = 0;
  int moved_y = 0;
  int progress = 0;
  int timeout_ms = get_motion_timeout_ms();

  if (total <= 0)
    return 0;

  compute_axis_speeds(requested_speed, &max_speed_x, &max_speed_y);

  int max_speed = max_speed_x;
  if (max_speed_y < max_speed)
    max_speed = max_speed_y;
  if (max_speed < MOTOR1_MIN_SPEED)
    max_speed = MOTOR1_MIN_SPEED;

  int accel = get_effective_accel();

  // accel<=0 is the DEFAULT on this fleet (motors.json ships accel_pan and
  // accel_tilt as 0), so this - not the trapezoid below - is the path a
  // hold-to-move gesture normally takes: one chunk covering the whole travel.
  if (accel <= 0 || total < 8) {
    if (motion_is_cancelled(generation))
      return -1;
    motor_steps(xsteps, ysteps, max_speed);
    if (wait_until_idle(chunk_timeout_ms(total, max_speed, timeout_ms), 10) != 0)
      return -1;
    return motion_is_cancelled(generation) ? -1 : 0;
  }

  // Small UI nudges feel jerky if driven at full speed with abrupt stops.
  if (total < 32) {
    int capped = (max_speed * 2) / 3;
    if (capped < MOTOR1_MIN_SPEED)
      capped = MOTOR1_MIN_SPEED;
    if (max_speed > capped)
      max_speed = capped;
  }

  int start_speed = (max_speed * 2) / 3;
  if (start_speed < MOTOR1_MIN_SPEED)
    start_speed = MOTOR1_MIN_SPEED;
  if (start_speed > max_speed)
    start_speed = max_speed;

  double v0 = (double)start_speed;
  double vmax = (double)max_speed;
  double a = (double)accel;
  double accel_steps_d = (vmax * vmax - v0 * v0) / (2.0 * a);
  int accel_steps = (int)(accel_steps_d + 0.5);

  if (accel_steps < 0)
    accel_steps = 0;
  if (accel_steps * 2 > total)
    accel_steps = total / 2;

  int cruise_steps = total - (2 * accel_steps);

  int accel_end = accel_steps;
  int cruise_end = accel_steps + cruise_steps;
  int phase_speed = (start_speed + max_speed) / 2;
  if (phase_speed < MOTOR1_MIN_SPEED)
    phase_speed = MOTOR1_MIN_SPEED;
  if (phase_speed > max_speed)
    phase_speed = max_speed;

  if (execute_profile_phase(total, accel_end, xsteps, ysteps, &moved_x,
                            &moved_y, &progress, phase_speed, timeout_ms,
                            generation) != 0)
    return -1;

  if (execute_profile_phase(total, cruise_end, xsteps, ysteps, &moved_x,
                            &moved_y, &progress, max_speed, timeout_ms,
                            generation) != 0)
    return -1;

  if (execute_profile_phase(total, total, xsteps, ysteps, &moved_x, &moved_y,
                            &progress, phase_speed, timeout_ms,
                            generation) != 0)
    return -1;

  return motion_is_cancelled(generation) ? -1 : 0;
}

/* Spawn a detached worker on a bounded 64 KB stack, the same convention the
 * WS listener uses for its connection threads (see spawn_detached() in
 * motor-ws.c). Nothing joins these. 64 KB is ample: the deepest chain from
 * here is run_profiled_move -> execute_profile_phase -> motor_steps_impl,
 * every frame a handful of scalars, measured at well under 1 KB in total. It
 * matters because a held joystick button dispatches ~11 moves a second, each
 * one a thread create+destroy, and the pthread default reserves megabytes of
 * address space for each. Returns 0 on success, -1 on failure. */
static int spawn_detached_worker(void *(*fn)(void *), void *arg) {
  pthread_t tid;
  pthread_attr_t attr;
  pthread_attr_t *attrp = NULL;
  int err;

  if (pthread_attr_init(&attr) == 0) {
    pthread_attr_setstacksize(&attr, 64 * 1024);
    attrp = &attr;
  }
  err = pthread_create(&tid, attrp, fn, arg);
  if (attrp)
    pthread_attr_destroy(attrp);
  if (err != 0)
    return -1;
  pthread_detach(tid);
  return 0;
}

static void *async_move_worker(void *arg) {
  struct async_move *move = (struct async_move *)arg;

  if (!move)
    return NULL;

  write_motion_active_flag();
  (void)run_profiled_move(move->x_steps, move->y_steps, move->speed,
                          move->generation);
  if (motion_is_current(move->generation))
    remove_motion_active_flag();
  free(move);
  return NULL;
}

static int start_profiled_move_async(int xsteps, int ysteps, int speed) {
  struct async_move *move = NULL;

  // For rapid UI nudges, avoid hard-stopping on every new command.
  // Generation handoff still cancels the previous profile at segment boundary.
  motion_cancel_all(false);

  move = calloc(1, sizeof(*move));
  if (!move)
    return -1;

  move->x_steps = xsteps;
  move->y_steps = ysteps;
  move->speed = speed;
  move->generation = motion_begin_new();

  if (spawn_detached_worker(async_move_worker, move) != 0) {
    free(move);
    return -1;
  }

  return 0;
}

// motor_steps_impl() unconditionally applies motor_inversion_state to every
// delta it is handed (correct for 'g', whose x/y are a logical jog
// direction). Callers that instead compute their delta as
// raw_target - motor_status_get()'s raw, uninverted current position (the
// 'h' absolute move, and the homing center correction) already have a
// physical delta, so that later inversion would flip it a second time.
// Pre-invert here so the two inversions cancel back out to the original
// physical delta.
static void physical_delta_to_steps(int *dx, int *dy) {
  if (motor_inversion_state & MOTOR_INVERT_X)
    *dx = -*dx;
  if (motor_inversion_state & MOTOR_INVERT_Y)
    *dy = -*dy;
}

// Coordinate frames.
//
// Everything inside this daemon - homing, clamping, the kernel counter itself
// - works in RAW steps, which run in whatever direction the hardware happens
// to be wired. Everything outside it (the web UI, ONVIF, ptz_presets, the init
// script) speaks a LOGICAL frame in which +x/+y always mean the same apparent
// direction on screen, whichever way this particular unit is mounted.
//
// Relative moves were already converted, by motor_steps_impl(). Absolute
// positions were not: an absolute target and a reported position both went
// through untranslated, so a caller that says "go to x=3700" reached the same
// physical end stop no matter what invert_x said, while "jog by +100" went the
// other way. ONVIF ContinuousMove is exactly such a caller - it implements
// "pan right" as an absolute move to max_step_x - which is why inversion had
// no effect on it.
//
// For a bounded axis the logical/raw relation is a mirror, L = max - R, not a
// sign flip; the mapping is its own inverse, so one helper serves both ways.
// Applied at the IPC boundary only (request in, reply out) so that no caller
// can reach the motors in the raw frame, and no internal logic has to care.
static int axis_mirror(int value, unsigned int max_steps, bool inverted) {
  if (!inverted || max_steps == 0)
    return value;
  return (int)max_steps - value;
}

static int motor_x_to_raw(int logical, const struct motor_message *msg) {
  return axis_mirror(logical, msg->x_max_steps,
                     (motor_inversion_state & MOTOR_INVERT_X) != 0);
}

static int motor_y_to_raw(int logical, const struct motor_message *msg) {
  return axis_mirror(logical, msg->y_max_steps,
                     (motor_inversion_state & MOTOR_INVERT_Y) != 0);
}

// Status as the outside world should see it: raw counter mirrored back into
// the logical frame, so that a position read here can be handed straight back
// as an absolute target.
static void motor_status_get_logical(struct motor_message *msg) {
  motor_status_get(msg);
  msg->x = axis_mirror(msg->x, msg->x_max_steps,
                       (motor_inversion_state & MOTOR_INVERT_X) != 0);
  msg->y = axis_mirror(msg->y, msg->y_max_steps,
                       (motor_inversion_state & MOTOR_INVERT_Y) != 0);
}

static void dispatch_profiled_move(int xsteps, int ysteps, int speed,
                                   const char *log_tag) {
  if (start_profiled_move_async(xsteps, ysteps, speed) == 0) {
    if (log_tag)
      syslog(LOG_DEBUG, "%s", log_tag);
    return;
  }

  // Fallback remains profiled: run synchronously if thread creation fails.
  unsigned int generation = motion_begin_new();
  write_motion_active_flag();
  (void)run_profiled_move(xsteps, ysteps, speed, generation);
  remove_motion_active_flag();

  if (log_tag)
    syslog(LOG_DEBUG, "%s (sync fallback)", log_tag);
}

// Perform two-phase homing using relative moves and busy polling
// Phase 1: rotate halfway to one side;
// Phase 2: full way back to the opposite side
static int enhanced_homing_daemon(int stepspeed) {
  struct motor_message status;
  motor_status_get(&status);

  unsigned int cfg_x = (g_cfg.loaded && g_cfg.pan.max_steps > 0)
                           ? (unsigned int)g_cfg.pan.max_steps
                           : 0;
  unsigned int cfg_y = (g_cfg.loaded && g_cfg.tilt.max_steps > 0)
                           ? (unsigned int)g_cfg.tilt.max_steps
                           : 0;
  int runtime_x = (status.x_max_steps > 0) ? (int)status.x_max_steps : 0;
  int runtime_y = (status.y_max_steps > 0) ? (int)status.y_max_steps : 0;

  // Prefer runtime-reported limits for homing sweep accuracy.
  int x_max = runtime_x > 0 ? runtime_x : (cfg_x ? (int)cfg_x : 0);
  int y_max = runtime_y > 0 ? runtime_y : (cfg_y ? (int)cfg_y : 0);

  // If both are available, use the larger value to avoid undershooting edges
  // on kernels that report slightly wider travel than config defaults.
  if (cfg_x > 0 && x_max < (int)cfg_x)
    x_max = (int)cfg_x;
  if (cfg_y > 0 && y_max < (int)cfg_y)
    y_max = (int)cfg_y;

  if (x_max <= 0 || y_max <= 0) {
    unsigned int sfx = 0, sfy = 0;
    motor_get_maxsteps_sysfs(&sfx, &sfy);
    if (x_max <= 0 && sfx > 0)
      x_max = (int)sfx;
    if (y_max <= 0 && sfy > 0)
      y_max = (int)sfy;
  }
  if (x_max <= 0 || y_max <= 0) {
    syslog(LOG_DEBUG,
           "Invalid max steps (x=%d,y=%d); cannot run enhanced homing.", x_max,
           y_max);
    return -1;
  }

  int half_x = x_max / 2;
  int half_y = y_max / 2;
  int full_x = x_max;
  int full_y = y_max;

  int to_s = 0;
  if (g_cfg.loaded) {
    to_s = (g_cfg.pan.timeout > g_cfg.tilt.timeout) ? g_cfg.pan.timeout
                                                    : g_cfg.tilt.timeout;
  }
  int t1_ms = (to_s > 0 ? to_s * 1000 : 10000);
  int t2_ms = (to_s > 0 ? to_s * 1000 : 15000);
  int t3_ms = (to_s > 0 ? to_s * 1000 : 10000);

    syslog(LOG_DEBUG,
      "Enhanced homing limits/config: x_max=%d y_max=%d cfg_home=%d,%d "
      "start=%d,%d",
      x_max, y_max, g_cfg.pan.home, g_cfg.tilt.home, status.x, status.y);

    // Requested relative homing sequence on both axes:
    // 1) move by +max/2
    // 2) move by -max
    // 3) move by +max/2 (center)

    motor_status_get(&status);
    syslog(LOG_DEBUG, "Enhanced homing pre-phase1: pos=%d,%d", status.x,
      status.y);
    syslog(LOG_DEBUG, "Enhanced homing phase 1: dx=%d dy=%d speed=%d", half_x,
      half_y, stepspeed);
    motor_steps(half_x, half_y, stepspeed);
  if (wait_until_idle(t1_ms, 100) != 0) {
    syslog(LOG_DEBUG,
           "Timeout waiting for enhanced homing phase 1 to complete.");
    return -1;
  }
    motor_status_get(&status);
    syslog(LOG_DEBUG, "Enhanced homing post-phase1: pos=%d,%d", status.x,
      status.y);

    motor_status_get(&status);
    syslog(LOG_DEBUG, "Enhanced homing pre-phase2: pos=%d,%d", status.x,
      status.y);
    syslog(LOG_DEBUG, "Enhanced homing phase 2: dx=%d dy=%d speed=%d", -full_x,
      -full_y, stepspeed);
    motor_steps(-full_x, -full_y, stepspeed);
  if (wait_until_idle(t2_ms, 100) != 0) {
    syslog(LOG_DEBUG,
           "Timeout waiting for enhanced homing phase 2 to complete.");
    return -1;
  }
    motor_status_get(&status);
    syslog(LOG_DEBUG, "Enhanced homing post-phase2: pos=%d,%d", status.x,
      status.y);

    motor_status_get(&status);
    syslog(LOG_DEBUG, "Enhanced homing pre-phase3: pos=%d,%d", status.x,
      status.y);
    syslog(LOG_DEBUG, "Enhanced homing phase 3: dx=%d dy=%d speed=%d", half_x,
      half_y, stepspeed);
    motor_steps(half_x, half_y, stepspeed);
  if (wait_until_idle(t3_ms, 100) != 0) {
    syslog(LOG_DEBUG,
           "Timeout waiting for enhanced homing center move to complete.");
    return -1;
  }
    motor_status_get(&status);
    syslog(LOG_DEBUG, "Enhanced homing post-phase3: pos=%d,%d", status.x,
      status.y);

    int center_x = x_max / 2;
    int center_y = y_max / 2;
    if (g_cfg.loaded && g_cfg.pan.home > 0 && g_cfg.pan.home < x_max)
      center_x = g_cfg.pan.home;
    if (g_cfg.loaded && g_cfg.tilt.home > 0 && g_cfg.tilt.home < y_max)
      center_y = g_cfg.tilt.home;

    if (status.x != center_x || status.y != center_y) {
      int corr_dx = center_x - status.x;
      int corr_dy = center_y - status.y;
      syslog(LOG_DEBUG,
             "Enhanced homing center correction: current=%d,%d target=%d,%d "
             "delta=%d,%d",
             status.x, status.y, center_x, center_y, corr_dx, corr_dy);
      physical_delta_to_steps(&corr_dx, &corr_dy);
      motor_steps(corr_dx, corr_dy, stepspeed);
      if (wait_until_idle(t3_ms, 100) != 0) {
        syslog(LOG_DEBUG,
               "Timeout waiting for enhanced homing center correction.");
        return -1;
      }
      motor_status_get(&status);
      syslog(LOG_DEBUG, "Enhanced homing post-correction: pos=%d,%d", status.x,
             status.y);
    }

  syslog(LOG_DEBUG, "Enhanced homing completed successfully at center.");
  return 0;
}

// ===================================================================
// Command handlers.
//
// Every function below is the body of one case of main()'s old
// `switch (request_message.command)` block, moved verbatim - same clamps,
// same edge deadbands, same frame conversions, same syslog lines, same order
// of ioctls. The only changes are mechanical: locals that used to be main()'s
// (motor_message, motor_reset_data) became locals here, and the two cases
// that mutated request_message purely so the trailing syslog could print the
// adjusted value now hand that value back through an out-parameter.
//
// See motor-ctl.h for why they all take a single command mutex.
// ===================================================================

static pthread_mutex_t command_lock = PTHREAD_MUTEX_INITIALIZER;

void motor_ctl_lock(void) { pthread_mutex_lock(&command_lock); }

bool motor_ctl_trylock(void) {
  return pthread_mutex_trylock(&command_lock) == 0;
}

void motor_ctl_unlock(void) { pthread_mutex_unlock(&command_lock); }

int motor_ctl_resolve_speed(int requested_speed) {
  int request_speed;

  motor_ctl_lock();
  request_speed = sanitize_requested_speed(0, last_known_speed);

  if (requested_speed != 0) {
    request_speed = sanitize_requested_speed(requested_speed, last_known_speed);
    last_known_speed = request_speed;
    motor_set_axis_speed(last_known_speed, last_known_speed);
    syslog(LOG_DEBUG, "Using request speed %d (last known updated to %d)",
           request_speed, last_known_speed);
  } else {
    syslog(LOG_DEBUG, "Using last known speed %d", request_speed);
  }

  motor_ctl_unlock();
  return request_speed;
}

void motor_ctl_relative(int rel_x, int rel_y, int speed, int *applied_x,
                        int *applied_y) {
  struct motor_message motor_message;

  motor_ctl_lock();

  motor_status_get(&motor_message);
  {
    int target_x = motor_message.x + rel_x;
    int target_y = motor_message.y + rel_y;
    int runtime_x_max =
        (motor_message.x_max_steps > 0)
            ? (int)motor_message.x_max_steps
            : ((g_cfg.loaded && g_cfg.pan.max_steps > 0) ? g_cfg.pan.max_steps
                                                         : 0);
    int runtime_y_max =
        (motor_message.y_max_steps > 0)
            ? (int)motor_message.y_max_steps
            : ((g_cfg.loaded && g_cfg.tilt.max_steps > 0) ? g_cfg.tilt.max_steps
                                                          : 0);

    if (runtime_x_max > 0) {
      if (target_x < 0)
        target_x = 0;
      if (target_x > runtime_x_max)
        target_x = runtime_x_max;
    }
    if (runtime_y_max > 0) {
      if (target_y < 0)
        target_y = 0;
      if (target_y > runtime_y_max)
        target_y = runtime_y_max;
    }

    // At edges, suppress tiny corrective oscillation from repeated
    // relative pushes and stale position updates.
    const int edge_deadband = 24;
    if (runtime_x_max > 0) {
      if ((target_x >= runtime_x_max - edge_deadband &&
           motor_message.x >= runtime_x_max - edge_deadband) ||
          (target_x <= edge_deadband && motor_message.x <= edge_deadband)) {
        target_x = motor_message.x;
      }
    }
    if (runtime_y_max > 0) {
      if ((target_y >= runtime_y_max - edge_deadband &&
           motor_message.y >= runtime_y_max - edge_deadband) ||
          (target_y <= edge_deadband && motor_message.y <= edge_deadband)) {
        target_y = motor_message.y;
      }

      // If we are already running at a mechanical edge, ignore
      // additional relative Y nudges until motion settles.
      if (motor_message.status == MOTOR_IS_RUNNING &&
          (motor_message.y <= edge_deadband ||
           motor_message.y >= runtime_y_max - edge_deadband)) {
        target_y = motor_message.y;
      }
    }

    rel_x = target_x - motor_message.x;
    rel_y = target_y - motor_message.y;

    if (applied_x)
      *applied_x = rel_x;
    if (applied_y)
      *applied_y = rel_y;

    dispatch_profiled_move(rel_x, rel_y, speed, "Profiled driver move started");
  }

  motor_ctl_unlock();
}

// --- continuous vector ('vector', WebSocket only) -------------------------
//
// See motor-ctl.h for why a stick deflection is not just a repeated 'move'.

// Backstop dead zone (per-mille); the browser's own is larger.
#define VECTOR_DEADZONE 40

// Speed at the dead-zone edge, as % of full-deflection speed.
#define VECTOR_MIN_SPEED_PCT 12

// Own lock, not command_lock: must clear even mid-homing-sweep.
static pthread_mutex_t vector_lock = PTHREAD_MUTEX_INITIALIZER;
static int vector_dir_x = 0;
static int vector_dir_y = 0;

static void vector_release(void) {
  pthread_mutex_lock(&vector_lock);
  vector_dir_x = 0;
  vector_dir_y = 0;
  pthread_mutex_unlock(&vector_lock);
}

// Deflection-to-speed curve exponent (1.0 = linear; below = more
// sensitive near centre; above = less). User-configurable via
// motors.joystick_sensitivity (g_cfg.joystick_curve_exp); see
// parse_modern_layout() for range-checking, VECTOR_CURVE_EXP_DEFAULT
// below for the fallback.
static int vector_axis_speed(int deflection, int ref_speed) {
  int mag = (deflection < 0) ? -deflection : deflection;
  double ratio, pct;

  if (mag <= VECTOR_DEADZONE)
    return 0;
  if (mag > 1000)
    mag = 1000;

  ratio = (double)(mag - VECTOR_DEADZONE) / (double)(1000 - VECTOR_DEADZONE);
  // Endpoints fixed: ratio 0 stays 0, ratio 1 stays 1.
  ratio = pow(ratio, g_cfg.joystick_curve_exp);
  pct = VECTOR_MIN_SPEED_PCT + (100 - VECTOR_MIN_SPEED_PCT) * ratio;

  return (int)(((double)ref_speed * pct) / 100.0);
}

bool motor_ctl_vector(int vx, int vy, int ref_speed, int *speed_x_out,
                      int *speed_y_out) {
  struct motor_message m;
  int dir_x = (vx > VECTOR_DEADZONE) - (vx < -VECTOR_DEADZONE);
  int dir_y = (vy > VECTOR_DEADZONE) - (vy < -VECTOR_DEADZONE);
  int travel_x, travel_y, base, sx, sy, ex, ey;
  bool direction_changed;

  if (speed_x_out)
    *speed_x_out = 0;
  if (speed_y_out)
    *speed_y_out = 0;

  if (!dir_x && !dir_y) {
    motor_ctl_stop();
    return true;
  }

  motor_ctl_lock();
  motor_status_get(&m);
  // sanitize_requested_speed() rather than motor_ctl_resolve_speed(): the
  // latter would write the scaled speed back to last_known_speed, so every
  // partial-deflection update would lower the reference the NEXT update
  // scales against and a held stick would ratchet itself to a standstill.
  // Nothing about a stick position should change the daemon's default speed.
  base = sanitize_requested_speed(ref_speed, last_known_speed);
  travel_x = (m.x_max_steps > 0) ? (int)m.x_max_steps
             : (g_cfg.loaded && g_cfg.pan.max_steps > 0) ? g_cfg.pan.max_steps
                                                         : 0;
  travel_y = (m.y_max_steps > 0)  ? (int)m.y_max_steps
             : (g_cfg.loaded && g_cfg.tilt.max_steps > 0)
                 ? g_cfg.tilt.max_steps
                 : 0;
  motor_ctl_unlock();

  if ((dir_x && travel_x <= 0) || (dir_y && travel_y <= 0))
    return false;

  sx = dir_x ? vector_axis_speed(vx, base) : 0;
  sy = dir_y ? vector_axis_speed(vy, base) : 0;
  // An axis the stick is not asking to move inherits the other axis's speed
  // instead of keeping 0. Not cosmetic: motor_set_axis_speed() falls back to
  // the single-speed MOTOR_SPEED ioctl with min(x,y) on kernels without
  // MOTOR_SPEED_AXIS, so a 0 here would clamp to MOTOR1_MIN_SPEED and crawl
  // the axis that IS moving at one step per second.
  if (!dir_x)
    sx = sy;
  if (!dir_y)
    sy = sx;
  // Without MOTOR_SPEED_AXIS - the case on the T31 kernels in this fleet,
  // which log "MOTOR_SPEED_AXIS unsupported" once at startup -
  // motor_set_axis_speed() collapses the pair to min(x, y). For a diagonal
  // stick that is the wrong reduction: pushed hard right and a hair up, the
  // pan would inherit the tilt's near-idle speed and crawl, which reads as a
  // hung camera. Measured before this line existed: x=1000/y=250 ran BOTH
  // axes at ~280 steps/s instead of pan at 900. The dominant axis is what the
  // stick's magnitude means, so give both that speed and let the minor axis
  // overshoot its share - a diagonal that is slightly too straight is a far
  // smaller error than one that barely moves.
  if (!axis_speed_supported && sx != sy)
    sx = sy = (sx > sy) ? sx : sy;
  if (sx < MOTOR1_MIN_SPEED)
    sx = MOTOR1_MIN_SPEED;
  if (sy < MOTOR1_MIN_SPEED)
    sy = MOTOR1_MIN_SPEED;

  pthread_mutex_lock(&vector_lock);
  direction_changed = (dir_x != vector_dir_x || dir_y != vector_dir_y);
  pthread_mutex_unlock(&vector_lock);

  if (direction_changed) {
    // motor_ctl_stop() first, and not only because reversing a stepper needs
    // it: motor_steps() opens with wait_until_idle(5000), so issuing into a
    // move that is still running would park the new worker for five seconds
    // before the new direction reached the hardware.
    motor_ctl_stop();
    motor_ctl_relative(dir_x * travel_x, dir_y * travel_y,
                       (sx > sy) ? sx : sy, NULL, NULL);
    // No per-axis push on this call. dispatch_profiled_move() is
    // asynchronous and its worker calls motor_set_axis_speed() itself, so a
    // push from here would race it and lose. The next update applies the
    // split, by which time the axis has moved a few dozen steps at the
    // faster axis's speed.
  } else {
    // compute_axis_speeds() caps one requested speed against BOTH configured
    // per-axis maxima and writes only the outputs it is given, so calling it
    // twice caps each axis against its own without duplicating that rule.
    ex = sx;
    ey = sy;
    compute_axis_speeds(sx, &ex, NULL);
    compute_axis_speeds(sy, NULL, &ey);

    motor_ctl_lock();
    motor_set_axis_speed(ex, ey);
    motor_ctl_unlock();
  }

  pthread_mutex_lock(&vector_lock);
  vector_dir_x = dir_x;
  vector_dir_y = dir_y;
  pthread_mutex_unlock(&vector_lock);

  if (speed_x_out)
    *speed_x_out = dir_x ? sx : 0;
  if (speed_y_out)
    *speed_y_out = dir_y ? sy : 0;
  return true;
}

void motor_ctl_absolute(int x, int got_x, int y, int got_y, int speed,
                        int *target_x_out, int *target_y_out) {
  struct motor_message motor_message;

  motor_ctl_lock();

  motor_status_get(&motor_message);
  // The target arrives in the logical frame; everything below this
  // point is raw. An axis the caller did not specify keeps the raw
  // current position, so it must not be mirrored.
  if (got_x == 0)
    x = motor_message.x; // as we are rewriting initial between requests
                         // this should not be necessary but leaving as
                         // is as to not break anything
  else
    x = motor_x_to_raw(x, &motor_message);
  if (got_y == 0)
    y = motor_message.y;
  else
    y = motor_y_to_raw(y, &motor_message);
  {
    int target_x = x;
    int target_y = y;

    int cfg_x_max =
        (g_cfg.loaded && g_cfg.pan.max_steps > 0) ? g_cfg.pan.max_steps : 0;
    int cfg_y_max =
        (g_cfg.loaded && g_cfg.tilt.max_steps > 0) ? g_cfg.tilt.max_steps : 0;
    int runtime_x_max = (motor_message.x_max_steps > 0)
                            ? (int)motor_message.x_max_steps
                            : cfg_x_max;
    int runtime_y_max = (motor_message.y_max_steps > 0)
                            ? (int)motor_message.y_max_steps
                            : cfg_y_max;

    // If UI requests configured edge but runtime edge is slightly
    // larger, snap to runtime edge to avoid visible rebound.
    if (runtime_x_max > 0 && cfg_x_max > 0 && target_x >= (cfg_x_max - 1) &&
        runtime_x_max > cfg_x_max)
      target_x = runtime_x_max;
    if (runtime_y_max > 0 && cfg_y_max > 0 && target_y >= (cfg_y_max - 1) &&
        runtime_y_max > cfg_y_max)
      target_y = runtime_y_max;

    if (runtime_x_max > 0) {
      if (target_x < 0)
        target_x = 0;
      if (target_x > runtime_x_max)
        target_x = runtime_x_max;
    }
    if (runtime_y_max > 0) {
      if (target_y < 0)
        target_y = 0;
      if (target_y > runtime_y_max)
        target_y = runtime_y_max;
    }

    // At mechanical edges, ignore tiny corrective nudges that cause
    // bounce when command and current are already at the same edge.
    const int edge_deadband = 24;
    if (runtime_x_max > 0) {
      if ((target_x >= runtime_x_max - edge_deadband &&
           motor_message.x >= runtime_x_max - edge_deadband) ||
          (target_x <= edge_deadband && motor_message.x <= edge_deadband)) {
        target_x = motor_message.x;
      }
    }
    if (runtime_y_max > 0) {
      if ((target_y >= runtime_y_max - edge_deadband &&
           motor_message.y >= runtime_y_max - edge_deadband) ||
          (target_y <= edge_deadband && motor_message.y <= edge_deadband)) {
        target_y = motor_message.y;
      }
    }

    int rel_x = target_x - motor_message.x;
    int rel_y = target_y - motor_message.y;

    if (target_x_out)
      *target_x_out = target_x;
    if (target_y_out)
      *target_y_out = target_y;

    physical_delta_to_steps(&rel_x, &rel_y);
    dispatch_profiled_move(rel_x, rel_y, speed,
                           "Profiled driver absolute move started");
  }

  motor_ctl_unlock();
}

void motor_ctl_goback(void) {
  motor_ctl_lock();
  motion_cancel_all(true);
  motor_ioctl(MOTOR_GOBACK, NULL);
  start_motion_active_tracker();
  motor_ctl_unlock();
}

void motor_ctl_cruise(void) {
  motor_ctl_lock();
  motion_cancel_all(true);
  motor_ioctl(MOTOR_CRUISE, NULL);
  start_motion_active_tracker();
  motor_ctl_unlock();
}

// Stop is the ONE handler that deliberately does not take the command lock.
//
// A PTZ stop has to reach the hardware immediately or it is not a stop. Held
// behind the mutex it would be unreachable for the whole duration of a homing
// sweep (up to ~35s) - precisely the situation in which a user reaches for
// it. Both things it touches are already safe to call concurrently:
// motion_cancel_all() has its own motion_lock and then issues MOTOR_STOP, and
// remove_motion_active_flag() is a bare unlink().
//
// This changes nothing on the AF_UNIX path, which is still serial and can
// never overlap anything. Caveat on the WS path, where it now CAN overlap:
// enhanced_homing_daemon() predates any notion of cancellation - it drives
// motor_steps() directly rather than through the generation-checked
// run_profiled_move() - so a stop issued mid-home halts the motors but leaves
// the remaining homing phases to run against a sweep that no longer matches
// reality. Teaching homing to cancel means changing hard-won motion code and
// is deliberately out of scope here.
void motor_ctl_stop(void) {
  motion_cancel_all(true);
  remove_motion_active_flag();
  // Releasing the stick has to go through here too, or the next gesture in
  // the same direction would look like an unchanged vector and get a speed
  // push against a move that no longer exists - a joystick that moves the
  // camera once and then never again. vector_lock is separate from
  // command_lock precisely so this stays as unblockable as the rest of stop.
  vector_release();
}

void motor_ctl_home(int speed) {
  struct motor_reset_data motor_reset_data;

  motor_ctl_lock();
  motion_cancel_all(true);
  syslog(LOG_DEBUG, "== Enhanced homing (reset), please wait");
  write_motion_active_flag();
  if (enhanced_homing_daemon(speed) != 0) {
    syslog(LOG_DEBUG,
           "Enhanced homing failed, falling back to legacy MOTOR_RESET.");
    memset(&motor_reset_data, 0, sizeof(motor_reset_data));
    motor_ioctl(MOTOR_RESET, &motor_reset_data);
  }
  remove_motion_active_flag();
  motor_ctl_unlock();
}

void motor_ctl_status(struct motor_message *out) {
  motor_ctl_lock();
  motor_status_get_logical(out);
  motor_ctl_unlock();
}

bool motor_ctl_status_try(struct motor_message *out) {
  if (!motor_ctl_trylock())
    return false;
  motor_status_get_logical(out);
  motor_ctl_unlock();
  return true;
}

void motor_ctl_set_speed(int speed) {
  motor_ctl_lock();
  last_known_speed = sanitize_requested_speed(speed, last_known_speed);
  motor_set_axis_speed(last_known_speed, last_known_speed);
  syslog(LOG_DEBUG, "Set speed command, last known speed now %d",
         last_known_speed);
  motor_ctl_unlock();
}

void motor_ctl_invert(char axis) {
  motor_ctl_lock();
  switch (axis) {
  case 'x': // Invert X only
    motor_inversion_state ^= MOTOR_INVERT_X;
    syslog(LOG_DEBUG, "Motor inversion X set to %s",
           (motor_inversion_state & MOTOR_INVERT_X) ? "ON" : "OFF");
    break;
  case 'y': // Invert Y only
    motor_inversion_state ^= MOTOR_INVERT_Y;
    syslog(LOG_DEBUG, "Motor inversion Y set to %s",
           (motor_inversion_state & MOTOR_INVERT_Y) ? "ON" : "OFF");
    break;
  case 'b': // Invert both X and Y
    motor_inversion_state ^= MOTOR_INVERT_BOTH;
    syslog(LOG_DEBUG, "Motor inversion set to %s",
           (motor_inversion_state == MOTOR_INVERT_BOTH) ? "BOTH ON"
                                                        : "BOTH OFF");
    break;
  default:
    syslog(LOG_DEBUG, "Invalid inversion command type.");
    break;
  }
  motor_ctl_unlock();
}

bool motor_ctl_reload(struct motor_message *out) {
  bool reload_ok;

  motor_ctl_lock();

  // Lets invert_x/invert_y (and speeds, accel, timeouts, pos_0,
  // joystick_sensitivity) take effect without restarting this process and,
  // critically, without
  // the modprobe -r/modprobe cycle in "S59motor restart" that has
  // oopsed live kernels. The kernel module is never touched here:
  // no ioctl is issued beyond the ordinary status read for the ack,
  // and the position counter lives in the driver, so tracking is
  // preserved across the reload.
  //
  // The async move workers read g_cfg without locking (established
  // behavior throughout this file), so cancel any in-flight profiled
  // move and let it wind down before rewriting the config under it.
  // Note that the command mutex held here does NOT protect against those
  // workers - it only keeps a second FRONTEND out. The cancel-and-wait
  // below remains the actual mechanism, exactly as before.
  motion_cancel_all(true);
  remove_motion_active_flag();
  if (wait_until_idle(2000, 20) != 0)
    syslog(LOG_WARNING, "motors -R: motors still moving after 2s wait; "
                        "reloading config anyway");
  usleep(50 * 1000); // let cancelled workers pass their final checks

  reload_ok = load_config_file();
  apply_config_speed_default();

  if (!reload_ok) {
    // load_config_file() already reset g_cfg to defaults (see its
    // own early-return logging above for the specific reason), so
    // g_cfg.loaded is now false: max-step overrides and position
    // clamping in motor_status_get() are gone until the next
    // successful load. Do not ack success.
    syslog(LOG_WARNING,
           "motors -R: reload FAILED (/etc/thingino.json missing, "
           "unreadable, or not a JSON object); config reset to "
           "defaults, previous settings are NOT in effect");
  } else {
    syslog(LOG_INFO,
           "Config reloaded from /etc/thingino.json (inversion=0x%x, "
           "default speed=%d)",
           (unsigned int)motor_inversion_state, last_known_speed);

    // steps_pan/steps_tilt are real kernel module parameters
    // (hmaxstep/vmaxstep); seed_driver_limits_from_config() only
    // ever (re)programs them once at startup (limits_seeded), and
    // deliberately not here, because doing so needs MOTOR_RESET,
    // which would destroy the position tracking this reload path
    // exists to preserve. If the freshly loaded config now disagrees
    // with what the kernel actually has loaded, userspace's
    // clamping/mirroring math (motor_status_get(),
    // motor_status_get_logical(), motor_x_to_raw()) silently
    // desyncs from kernel-enforced limits. Warn loudly; do not
    // try to auto-fix it here.
    unsigned int kernel_max_x = 0, kernel_max_y = 0;
    motor_get_maxsteps_sysfs(&kernel_max_x, &kernel_max_y);
    bool pan_mismatch = kernel_max_x > 0 && g_cfg.pan.max_steps > 0 &&
                        kernel_max_x != (unsigned int)g_cfg.pan.max_steps;
    bool tilt_mismatch = kernel_max_y > 0 && g_cfg.tilt.max_steps > 0 &&
                         kernel_max_y != (unsigned int)g_cfg.tilt.max_steps;
    if (pan_mismatch || tilt_mismatch) {
      syslog(LOG_WARNING,
             "motors -R: reloaded steps_pan/steps_tilt (%d/%d) "
             "differ from the kernel's already-loaded limits "
             "(hmaxstep=%u, vmaxstep=%u); a full restart (S59motor "
             "restart / reboot) is required for the new step "
             "limits to take effect at the kernel level",
             g_cfg.pan.max_steps, g_cfg.tilt.max_steps, kernel_max_x,
             kernel_max_y);
    }
  }

  // Ack with fresh logical status so "motors -R" callers can verify
  // the new inversion state took effect. Note: keys that are kernel
  // module parameters (gpio pins, hmaxstep/vmaxstep) are re-read
  // into g_cfg but cannot reprogram the loaded module; they still
  // need a full stop/start of S59motor.
  motor_status_get_logical(out);
  if (!reload_ok)
    out->status = MOTOR_RELOAD_FAILED;

  motor_ctl_unlock();
  return reload_ok;
}

int check_pid(char *file_name) {
  FILE *f;
  long pid;
  char pid_buffer[PID_SIZE];

  f = fopen(file_name, "r");
  if (f == NULL)
    return 0;

  if (fgets(pid_buffer, PID_SIZE, f) == NULL) {
    fclose(f);
    return 0;
  }
  fclose(f);

  if (sscanf(pid_buffer, "%ld", &pid) != 1) {
    return 0;
  }

  if (kill(pid, 0) == 0) {
    return 1;
  }

  return 0;
}

int create_pid(char *file_name) {
  FILE *f;
  char pid_buffer[PID_SIZE];

  f = fopen(file_name, "w");
  if (f == NULL)
    return -1;

  memset(pid_buffer, '\0', PID_SIZE);
  sprintf(pid_buffer, "%ld\n", (long)getpid());
  if (fwrite(pid_buffer, strlen(pid_buffer), 1, f) != 1) {
    fclose(f);
    return -2;
  }
  fclose(f);

  return 0;
}

static void write_motion_active_flag() {
  int fd = open(MOTOR_ACTIVE_FLAG, O_CREAT | O_WRONLY | O_TRUNC, 0644);
  if (fd >= 0) {
    const char payload[] = "active\n";
    (void)write(fd, payload, sizeof(payload) - 1);
    close(fd);
  }
}

static void remove_motion_active_flag() {
  unlink(MOTOR_ACTIVE_FLAG);
}

static void *motion_active_tracker(void *arg) {
  (void)arg;
  while (motor_is_busy()) {
    usleep(100 * 1000);
  }
  remove_motion_active_flag();
  return NULL;
}

static void start_motion_active_tracker() {
  write_motion_active_flag();
  (void)spawn_detached_worker(motion_active_tracker, NULL);
}

static void daemonsetup() {
  pid_t pid;

  /* Fork off the parent process */
  pid = fork();

  /* An error occurred */
  if (pid < 0)
    exit(EXIT_FAILURE);

  /* Success: Let the parent terminate */
  if (pid > 0)
    exit(EXIT_SUCCESS);

  /* On success: The child process becomes session leader */
  if (setsid() < 0)
    exit(EXIT_FAILURE);

  /* Catch, ignore and handle signals */
  // TODO: Implement a working signal handler */
  signal(SIGCHLD, SIG_IGN);
  signal(SIGHUP, SIG_IGN);
  /* SIGPIPE would otherwise kill the daemon outright the first time a write
   * lands on a socket the peer already reset - silently, since SIGPIPE writes
   * nothing to syslog and dumps no core. ws.c's plaintext writes pass
   * MSG_NOSIGNAL, but the wss:// path writes through mbedTLS's own BIO
   * (a bare write(), which can't take flags at all), and mbedTLS only
   * installs its SIGPIPE guard inside net_prepare(), which runs from
   * mbedtls_net_bind()/_connect() - neither of which ws_tls_accept() uses, as
   * it wraps a socket motor-ws.c accepted itself. Same reason and same
   * one-liner as timps's main.c. */
  signal(SIGPIPE, SIG_IGN);

  /* Fork off for the second time*/
  pid = fork();

  /* An error occurred */
  if (pid < 0)
    exit(EXIT_FAILURE);

  /* Success: Let the parent terminate */
  if (pid > 0)
    exit(EXIT_SUCCESS);

  /* Set new file permissions */
  umask(0);

  /* Change the working directory */
  chdir("/dev/");

  /* Close all open file descriptors */
  int x;
  for (x = sysconf(_SC_OPEN_MAX); x >= 0; x--) {
    close(x);
  }

  /* Open the log file */
  openlog("motors-daemon", LOG_PID, LOG_DAEMON);
}

void requestcleanup() {
  //
  request_message.command = 'd';
  request_message.type = 's';
  request_message.x = 0;
  request_message.got_x = 0;
  request_message.y = 0;
  request_message.got_y = 0;
  request_message.speed = 0; // Reset speed in request
}

int main(int argc, char *argv[]) {
  int c;
  char *pid_file;
  bool skip_reset = false; // Initialize skip_reset to false
  pid_file = "/run/motors-daemon";

  bool debug_requested = env_debug_enabled();
  const char *debug_source = debug_requested ? "environment" : NULL;
  debug_mode = debug_requested;
  configure_logmask();

  // Load configuration early. A missing/invalid config file is not fatal
  // here (defaults apply and load_config_file() already logs the specific
  // reason at LOG_DEBUG) - matches the pre-existing behavior of this call
  // site, which never checked for failure either.
  (void)load_config_file();
  apply_config_speed_default();

  while ((c = getopt(argc, argv, "dhpD")) != -1) {
    switch (c) {
    case 'd':
    case 'D':
      debug_requested = true;
      debug_source = "command line";
      break;
    case 'p':
      skip_reset = true; // Set skip_reset to true if -p is provided
      break;
    default:
      printf("Usage : \n"
             "\t -D enable debugging messages to syslog\n"
             "\t -d legacy alias for -D\n"
             "\t -h print this help message\n"
             "\t -p skip reset position on launch\n"
             "\t No option to start the daemon\n");
      return EXIT_FAILURE;
      break;
    }
  }

  if (debug_mode != debug_requested) {
    debug_mode = debug_requested;
    configure_logmask();
  }

  if (debug_mode) {
    syslog(LOG_DEBUG, "motors-daemon debug logging enabled via %s",
           debug_source ? debug_source : "environment");
  } else {
    syslog(LOG_INFO,
           "motors-daemon running with concise logging (use -D or DEBUG=1 for "
           "verbose output)");
  }

  sync_kernel_debug(debug_mode);
  daemonsetup();
  if (check_pid(pid_file) == 1) {
    syslog(LOG_INFO, "Motors daemon is already running.");
    printf("Motors daemon is already running\n");
    exit(EXIT_FAILURE);
  }
  if (create_pid(pid_file) < 0) {
    syslog(LOG_INFO, "Error creating pid file %s", pid_file);
    exit(EXIT_FAILURE);
  }
  int daemonstop = 0;
  // struct instances
  struct sockaddr_un addr; // socket struct
  struct motor_reset_data motor_reset_data;
  struct motor_message motor_message;

  // acquire control of motor device
  motorfd = open("/dev/motor", 0);
  if (motorfd == -1) {
    syslog(LOG_ERR, "Unable to open /dev/motor: %s", strerror(errno));
    exit(EXIT_FAILURE);
  }

  sync_kernel_limit_mode(g_cfg.hw.limitless);
  if (g_cfg.hw.limitless) {
    syslog(LOG_INFO, "Limitless PTZ mode enabled; relying on software stops");
    seed_driver_limits_from_config();
  }

  // Reset/homing on startup, unless skipped via -p
  if (!skip_reset) {
    syslog(LOG_DEBUG, "== Enhanced homing on startup, please wait");
    if (enhanced_homing_daemon(last_known_speed) != 0) {
      if (g_cfg.hw.limitless) {
        syslog(LOG_WARNING,
               "Enhanced homing failed but legacy MOTOR_RESET skipped (no "
               "limit switches)");
      } else {
        syslog(LOG_DEBUG, "Enhanced homing failed at startup, falling back to "
                          "legacy MOTOR_RESET.");
        memset(&motor_reset_data, 0, sizeof(motor_reset_data));
        motor_ioctl(MOTOR_RESET, &motor_reset_data);
      }
    }
  }

  int serverfd = socket(AF_UNIX, SOCK_STREAM, 0);
  syslog(LOG_DEBUG, "Server socket fd = %d", serverfd);
  // check if we could acquire fd for socket
  if (serverfd == -1) {
    syslog(LOG_ERR, "Error initializing the socket, could not get a proper fd");
    closelog();
    exit(EXIT_FAILURE);
  }

  // cleanup for socket path if path already exists
  if (remove(SV_SOCK_PATH) == -1 && errno != ENOENT) {
    syslog(LOG_ERR, "could not remove-%s, exiting", SV_SOCK_PATH);
    closelog();
    exit(EXIT_FAILURE);
  }

  memset(&addr, 0, sizeof(struct sockaddr_un));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, SV_SOCK_PATH, sizeof(addr.sun_path) - 1);
  // binding to socket
  if (bind(serverfd, (struct sockaddr *)&addr, sizeof(struct sockaddr_un)) ==
      -1) {
    syslog(LOG_ERR, "Error binding to socket, exiting");
    closelog();
    exit(EXIT_FAILURE);
  }

  // start listening on socket
  if (listen(serverfd, MAX_CONN) == -1) {
    closelog();
    exit(EXIT_FAILURE);
  }

  // Bring the WebSocket frontend up before entering the AF_UNIX accept loop.
  // It owns its own listening socket and its own thread, so the loop below is
  // completely undisturbed; a failure to bind is logged and ignored, because
  // a camera that cannot open a TCP port must still be drivable by the CLI
  // over /dev/md.
#ifdef MOTORS_WS
  {
    motor_ws_cfg ws_cfg;
    load_ws_config_file(&ws_cfg);
    if (ws_cfg.enabled) {
      if (motor_ws_start(&ws_cfg) != 0)
        syslog(LOG_WARNING, "WebSocket frontend disabled (startup failed); "
                            "the /dev/md socket is unaffected");
    } else {
      syslog(LOG_INFO, "WebSocket frontend disabled by motors.ws_enabled");
    }
    // motor_ws_start() already wiped ws_cfg.token; do it again so the local
    // copy is clean on the path where the listener never started.
    memset(&ws_cfg, 0, sizeof(ws_cfg));
  }
#endif /* MOTORS_WS */

  syslog(LOG_INFO, "motors-daemon started");

  while (daemonstop == 0) {
    // make request object go back to initial value
    syslog(LOG_DEBUG, "Start request cleanup");
    requestcleanup();
    // reset ok to close fd flag (removed unused closeready)
    syslog(LOG_DEBUG, "Waiting to accept a connection");
    // blocking code, wait for a connection
    int clientfd = accept(serverfd, NULL, NULL);
    if (clientfd == -1) {
      syslog(LOG_DEBUG,
             "clientfd is invalid after connection accept, socket doesnt work "
             "and is %i errno : %i",
             clientfd, errno);
      syslog(LOG_DEBUG, "exiting...");
      exit(EXIT_FAILURE);
    }
    syslog(LOG_DEBUG, "Accepting a connection\n");

    // load the message onto the reques_message struct
    if (read(clientfd, &request_message, sizeof(struct request)) == -1) {
      syslog(LOG_DEBUG,
             "Could not read message from motors app, ignore request");
      syslog(LOG_DEBUG, "client fd at this point is %i errno : %i", clientfd,
             errno);
    } else {
      syslog(LOG_DEBUG, "request command is %c", request_message.command);
      // The command bodies now live in the motor_ctl_* handlers above, shared
      // with the WebSocket frontend (motor-ws.c). This switch is pure
      // dispatch: unpack the AF_UNIX wire struct, call the handler, write the
      // AF_UNIX reply. Behaviour is unchanged - including the quirks, such as
      // 'i'/'j'/'p'/'b' all returning the same status struct.
      int request_speed = motor_ctl_resolve_speed(request_message.speed);

      switch (request_message.command) {
      case 'd': // move direction
        syslog(LOG_DEBUG, "request type is %c", request_message.type);
        switch (request_message.type) {
        case 'g': // relative movement
          // request_message.x/y are overwritten with the delta that was
          // actually applied, because the two syslog lines below have always
          // reported the post-clamp value rather than what the client asked
          // for.
          motor_ctl_relative(request_message.x, request_message.y,
                             request_speed, &request_message.x,
                             &request_message.y);
          syslog(LOG_DEBUG, "request x is %i", request_message.x);
          syslog(LOG_DEBUG, "request y is %i", request_message.y);
          break;
        case 'h': // absolute movement
          // Same story: these become the resolved RAW targets before logging.
          motor_ctl_absolute(request_message.x, request_message.got_x,
                             request_message.y, request_message.got_y,
                             request_speed, &request_message.x,
                             &request_message.y);
          syslog(LOG_DEBUG, "request x is %i", request_message.x);
          syslog(LOG_DEBUG, "request y is %i", request_message.y);
          break;
        case 'b': // go back
          motor_ctl_goback();
          break;
        case 'c': // cruise
          motor_ctl_cruise();
          break;
        case 's': // stop
          motor_ctl_stop();
          break;
        }
        break;
      case 'r': // reset (homing)
        motor_ctl_home(request_speed);
        break;
      case 'i': // get initial parameters
        // This doesnt seem right, we are returning current information instead
        // of initial parameters not correcting for now, as we want to have
        // functional parity
        motor_ctl_status(&motor_message);
        syslog(LOG_DEBUG, "Got current status to load into command");
        write(clientfd, &motor_message, sizeof(struct motor_message));
        break;
      case 'j': // get json
        motor_ctl_status(&motor_message);
        syslog(LOG_DEBUG, "Got current status to load into command");
        write(clientfd, &motor_message, sizeof(struct motor_message));
        break;
      case 'p': // get simple x y position
        motor_ctl_status(&motor_message);
        syslog(LOG_DEBUG, "Got current status to load into command");
        write(clientfd, &motor_message, sizeof(struct motor_message));

        break;
      case 'b': // is busy
        motor_ctl_status(&motor_message);
        syslog(LOG_DEBUG, "Got current status to load into command");
        write(clientfd, &motor_message, sizeof(struct motor_message));

        break;
      case 's': // set speed
        motor_ctl_set_speed(request_message.speed);
        break;
      case 'I': // Invert motor direction
        motor_ctl_invert(request_message.type);
        break;
      case 'R': // reload userspace config from /etc/thingino.json
        (void)motor_ctl_reload(&motor_message);
        write(clientfd, &motor_message, sizeof(struct motor_message));
        break;
      case 'S': // show status
        motor_ctl_status(&motor_message);
        motor_message.inversion_state = motor_inversion_state;
        write(clientfd, &motor_message, sizeof(struct motor_message));
        syslog(LOG_DEBUG, "Sent motor status");
        break;
      }

      // need to close fd after each request is completed
      close(clientfd);
    }

    syslog(LOG_DEBUG, "====================");

    // break;
  }

  syslog(LOG_INFO, "motors-daemon terminated.");
  remove_motion_active_flag();
  unlink(pid_file);
  closelog();

  return EXIT_SUCCESS;
}

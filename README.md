
## Load kernel module before use
ingenic-motor is a command line tool to be able to send commands to the motor.ko camera module. By default this module is not loaded and so it is necessary to enter the following commands:

```
modprobe motor hmaxstep=2540 vmaxstep=720 hst1=52 hst2=53 hst3=57 hst4=51 vst1=59 vst2=61 vst3=62 vst4=63
```

To automate this process during boot, add the line `motor hmaxstep=2540 vmaxstep=720 hst1=52 hst2=53 hst3=57 hst4=51 vst1=59 vst2=61 vst3=62 vst4=63` to `/etc/modules`.

## Module Configuration

- `hstX`: Horizontal motor phase GPIO pins.
- `vstX`: Vertical motor phase GPIO pins.
- `hmaxstep` and `vmaxstep`: Specify the maximum number of steps your hardware can handle.
Note that the maximum steps for the horizontal and vertical motors are passed as arguments when inserting the `motor` module.

### Examples for Wyze Pan Cam v3

1) connect to the camera via ssh
```
ssh root@ip.of.your.camera
```
2) load the kernel module:

check if the motor module is loaded:
```
lsmod
```
if any of them are on the list then unload them first:
```
rmmod motor
```
load the modules with parameters (you may need to experiment with the hmaxstep and vmaxstep values for your specific camera):

```
insmod /path/to/motor.ko hmaxstep=2130 vmaxstep=1600
```

3) testing

By passing the -S command line argument, the current status and x,y parameters will be returned:
```
ingenic-motor -S
```
it will look like this:
```
Max X Steps 2130.
Max Y Steps 1600.
Status Move: 0.
X Steps 1065.
Y Steps 800.
Speed 900.
```
Note: Seems like `900` is the maximum speed of the kernel module, hence why it can't be set further than that value.

### Command line options
```
Usage : ingenic-motor
         -d Direction step.
         -s Speed step (default 900).
         -x X position/step (default 0).
         -y Y position/step (default 0).
         -r two-phase homing (daemon-side), then return to center.
         -j return json string xpos,ypos,status,speed.
         -i return json string for all camera parameters
         -S show status
```

## Examples

* go to mid position of X and Y (assuming max X steps 2130 and max y steps 1600):
```
ingenic-motor -d h -x 1065 -y 800
```
* go to position of begining of X and Y
```
ingenic-motor -d h -x 0 -y 0
```
* go to x 1065 and y 0
```
ingenic-motor -d h -x 1992 -y 0
```
* get camera details as json string
```
ingenic-motor -i
```
* stop the motors
```
ingenic-motor -d s
```
* reset the motors (two-phase homing: half to one side, then full to the opposite; ends centered)
```
ingenic-motor -r
```


## JSON Configuration

The daemon and client read an optional JSON config file at startup from the first existing path:
- /etc/motors.json
- ./motors.json (working directory)

Configuration schema (per-axis parameters):

```
{
  "loglevel": "INFO",            // optional: DEBUG or INFO
  "pan": {                        // X axis
    "max_steps": 2130,            // overrides driver-reported max (optional)
    "home": 1065,                 // custom center position (optional)
    "speed": 900,                 // default/maximum speed for X
    "timeout": 10                 // seconds, used by homing waits
  },
  "tilt": {                       // Y axis
    "max_steps": 1600,
    "home": 800,
    "speed": 900,                 // default/maximum speed for Y
    "timeout": 10                 // seconds, used by homing waits
  }
}
```

Behavior:
- If the file is missing or a field is absent, built-in defaults and driver values are used.
- Homing uses configured max_steps and home (center) when provided; otherwise falls back to driver max and half-range center.
- Homing timeouts use the max of the per-axis `timeout` (in seconds). If not set, defaults are 10s/15s/10s for phases 1/2/center.
- Per-axis speed limits are enforced server-side: effective move speed is clamped to the most restrictive axis speed.
- The client also reads the config and uses the per-axis speed to initialize its default speed. Command-line `-s` overrides the config.

Example config lives well in /etc/motors.json.

## WebSocket PTZ control path

This fork adds a WebSocket listener inside `motors-daemon`. A UI holds one
connection instead of paying a full round trip per move (httpd -> CGI ->
`ingenic-motor` -> AF_UNIX -> daemon, then another one for the status echo).
Nothing about the CLI or the `/dev/md` socket changes; this is an additional
frontend, and if it fails to start the daemon keeps running without it.

Default endpoint:

```
ws://<camera>:8089/ws
```

Any other request target is answered with 404, so the port does not double as a
generic HTTP endpoint. `ws://` and `wss://` share the port: on accept the daemon
peeks the first byte the client sends - `0x16` starts a TLS record, `G` starts
the `GET` of an HTTP upgrade - and handles it accordingly. There is no config
switch for it, and a camera with no usable certificate simply serves plain
`ws://`.

The upgrade must be RFC 6455 version 13 (`GET`, `Upgrade: websocket`,
`Connection: upgrade`, `Sec-WebSocket-Key`). No subprotocol is negotiated.

### Authentication

Every non-loopback connection must present a token. Two forms are accepted, both
checked at handshake time:

- `X-Motors-Token: <token>` request header (preferred; non-browser clients).
- `?token=<token>` in the query string, because the browser's
  `new WebSocket(url)` cannot set request headers.

Peers in 127.0.0.0/8 skip the token check - a local CGI or init script cannot
conveniently read a 0640 file from a non-root context. Note that a browser is
*not* loopback here even when the page came from this camera: it connects from
the LAN address and takes the token path.

The daemon mints a fresh 128-bit token at every start and writes it to
`/run/motors.token` (mode 0640, root-owned). An optional persistent secret can
be set as `motors.ws_token`; both are accepted. If `/dev/urandom` cannot be read
the daemon refuses to mint a weak token, and the listener only starts if a
persistent one was configured.

```
# on the camera
cat /run/motors.token
```

```
# from a LAN host
TOKEN=$(ssh root@camera cat /run/motors.token)
websocat "ws://camera:8089/ws?token=$TOKEN"
```

```
# from the camera itself, no token needed
websocat ws://127.0.0.1:8089/ws
```

### Commands

Client frames are text, one JSON object per frame, flat (no nested objects or
arrays). An optional `"id"` (0..2147483647) is echoed back in the reply so a
client can match them up. An optional `"speed"` (0..2000) is rejected outright
if out of range rather than clamped.

- `{"cmd":"move","mode":"rel","x":200,"y":-50}` - relative jog; `mode` defaults
  to `"rel"`, the other value is `"abs"`. At least one of `x`/`y` is required;
  the omitted axis jogs by zero (rel) or keeps its position (abs). Wire limits
  are +/-100000 (rel) and 0..100000 (abs); the handlers clamp again to the real
  travel. The ack carries the applied delta for a relative move, the resolved
  raw target for an absolute one.
- `{"cmd":"vector","x":1000,"y":0}` - analog-stick deflection in signed
  per-mille, not a distance. The daemon drives toward the limit and picks the
  speed from the deflection, so the client never needs to know the travel or the
  configured speed cap. Out-of-range values are clamped (a stick a pixel outside
  its ring is a rounding error, not a bug worth surfacing). `|x|,|y| <= 40` is
  the dead zone and stops the motors. An optional `speed` is the reference for
  *full* deflection. The ack's `x`/`y` are the per-axis speeds commanded. Fails
  with `no_limits` on a camera whose travel limits are unknown.
- `{"cmd":"stop"}` - immediate stop; also releases any held stick direction.
- `{"cmd":"home"}` - two-phase homing, same as `ingenic-motor -r`. Runs on its
  own thread so `stop` stays reachable; a second one while it runs gets `busy`.
- `{"cmd":"speed","speed":900}` - set the daemon's default speed.
- `{"cmd":"status"}` - one status frame.
- `{"cmd":"subscribe","interval_ms":150}` - server-driven status pushes.
  `interval_ms` is clamped to 50..5000, `0` unsubscribes, and omitting it uses
  `motors.ws_push_ms`. Frames are only sent when x, y or the moving flag
  changed, plus a 5 s heartbeat so a UI that missed one self-heals.
- `{"cmd":"ping"}` - application-level ping for round-trip measurement, distinct
  from the protocol PING frame the daemon answers on its own.

Deliberately not exposed: axis inversion (`-I`) and config reload (`-R`). Those
are configuration, not PTZ, and stay on the `/dev/md` socket where the caller
has to be a local process.

"Hold to move" needs no dedicated command - `move` and `stop` already express
it, and every `hello`/`status` frame carries the travel:

```
pointerdown -> {"cmd":"move","mode":"rel","x":<+/- x_max>}
pointerup   -> {"cmd":"stop"}
```

An oversized delta becomes exactly the distance remaining to the limit. A camera
reporting `x_max` 0 has unknown limits, and a client seeing that must fall back
to fixed-size steps rather than inventing a large constant.

### Server messages

```
{"type":"hello","x":1065,"y":800,"x_max":2130,"y_max":1600,"speed":900,"moving":false,"inversion":0}
{"type":"status","x":1105,"y":800,"x_max":2130,"y_max":1600,"speed":900,"moving":true,"inversion":0}
{"type":"ack","id":7,"cmd":"move","x":40,"y":0}
{"type":"error","id":7,"code":"bad_speed","msg":"speed out of range 0..2000"}
```

`hello` is sent once on connect (so a UI can render without a round trip);
everything after it is `status`. Error codes: `bad_json`, `bad_request`,
`bad_speed`, `out_of_range`, `no_limits`, `busy`, `internal`, `unknown_cmd`,
`rate_limited`.

### Joystick sensitivity

The `vector` deflection-to-speed curve is `pow(ratio, motors.joystick_sensitivity)`,
default 2.0, valid range 0.05..4.0 (below 1.0 = more sensitive near centre,
above = less). NaN and out-of-range values fall back to the default. Speed at the
dead-zone edge is 12% of the full-deflection speed.

### Configuration

The listener reads `/etc/thingino.json`, `"motors"` object, on a separate pass
that runs only at startup - `ingenic-motor -R` deliberately cannot half-apply a
`ws_*` key, since the socket is bound exactly once. Changing any of these needs a
daemon restart.

```
{
  "motors": {
    "ws_enabled": true,          // false disables the listener entirely
    "ws_port": 8089,
    "ws_bind": "0.0.0.0",        // "127.0.0.1" to keep it host-local
    "ws_token": "",              // optional persistent secret; hashed and wiped at startup
    "ws_token_file": "/run/motors.token",
    "ws_origins": "",            // comma-separated extra allowed Origins
    "ws_max_clients": 4,
    "ws_rate_limit": 25,         // commands/s per connection
    "ws_push_ms": 150,           // default subscribe cadence
    "ws_tls": true,              // false refuses wss:// even with a certificate
    "ws_tls_cert": "",           // "" = probe the usual places
    "ws_tls_key": "",            // must be given together with ws_tls_cert
    "joystick_sensitivity": 2.0
  }
}
```

Values are sanity-clamped at startup: port 1..65535, max_clients 1..32,
rate_limit 1..500, push_ms 50..5000.

### TLS

With `ws_tls_cert`/`ws_tls_key` unset the daemon probes, in order:

```
/etc/ssl/certs/timps.crt   + /etc/ssl/private/timps.key
/etc/ssl/certs/uhttpd.crt  + /etc/ssl/private/uhttpd.key
```

It never generates a certificate, only reads one something else already
produced. Using the web UI's certificate is the point: a browser tracks trust
for a self-signed certificate per scheme+host+**port**, and a WebSocket gets no
click-through prompt (iOS Safari offers none at all), so presenting the same
certificate makes the user's one trust decision on :443 cover :8089 too.

Whether `wss://` is actually available is published as the marker file
`/run/motors.tls`, for a CGI to report to the page so it can build the right URL.
Any failure here - no certificate, unreadable key, `ws_tls` off - is logged and
the listener serves plain `ws://`; TLS is never a reason to refuse to start.

The floor is TLS 1.2 (mbedTLS 2.x still negotiates 1.0/1.1 under its default
preset, so it is set explicitly; 3.x already defaults there).

### Security properties

- Tokens are held as SHA-256 digests only; the plaintext is wiped from the
  daemon's memory once written to the token file. Comparison is branch-free over
  two fixed 32-byte digests, and both candidate digests are always evaluated, so
  neither the length nor which token matched leaks through timing.
- Origin is checked at the handshake. WebSocket is not covered by CORS, so the
  server is the only thing that can refuse a cross-site page. An Origin present
  must match the Host header's host, or appear in `ws_origins`. No Origin at all
  is allowed - that identifies a non-browser client, which has no ambient
  credentials to hijack and still needs a token. An explicitly empty or `null`
  Origin is refused.
- Unmasked client frames are rejected with close 1002, per RFC 6455 section 5.1;
  so are set RSV bits, a 64-bit length with the high bit set, and fragmented or
  oversized control frames.
- Payloads are capped at 2048 bytes across a whole reassembled message, into a
  fixed buffer - the daemon never allocates from a peer-declared length.
  Non-text frames are refused with close 1003.
- JSON nesting deeper than 8 is rejected before the parser runs. libjct recurses
  per level with no limit of its own, and ~700 nested brackets fit inside the
  2 KB payload cap and overflow a 64 KB connection stack. Loopback callers skip
  the token, so this cannot be left to auth.
- Rate limit is a token bucket at `ws_rate_limit` commands/s per connection
  (a UI holding a button runs at ~11/s); 50 throttled commands closes the
  connection with 1008.
- `ws_max_clients` connections are accepted, further ones get an immediate
  plaintext 503 - no TLS handshake is run just to refuse someone.
- Pre-auth connections are bounded: 5 s for the HTTP handshake, 15 s for the TLS
  one, and connection threads get a 64 KB stack rather than the default
  megabytes.
- Established connections are pinged every 20 s and closed after 60 s without
  any frame from the peer. All timers use `CLOCK_MONOTONIC` - these cameras have
  no RTC, and under the wall clock the first NTP sync after boot would drop every
  open connection at once.

### Fixed on this branch

- **SIGPIPE killed the daemon on `wss://` writes.** Plaintext writes pass
  `MSG_NOSIGNAL`, but the TLS path goes through mbedTLS's BIO - a bare `write()`
  with no flags - and mbedTLS only installs its SIGPIPE guard in `net_prepare()`,
  which `ws_tls_accept()` never reaches because it wraps a socket we accepted
  ourselves. One write to a reset peer terminated the process with no syslog line
  and no core. `SIGPIPE` is now ignored.
- **The handshake timeout was not a real deadline.** The 5 s budget was passed to
  every `poll()` unchanged, so a client dribbling one byte just under the timeout
  could hold a pre-auth connection - and one of the four listener slots - open
  forever. The time remaining is now re-derived from the clock before each poll.

### Building

The listener is on by default in this repo's Makefile and can be turned off:

```
make                 # daemon with the WebSocket frontend (ws:// only)
make WS_TLS=1        # also accept wss:// (needs mbedTLS)
make WS=0            # no listener, no token store, ~25 KB less text
make check           # SHA-1/SHA-256/base64/framing self-test, host build, no libjct
```

`WS_TLS` is off by default because mbedTLS is the only dependency in this tree
beyond libjct, and a plain `make` on a development host has to keep working
without it. The thingino package that consumes this tree compiles the sources
directly rather than calling this Makefile, and gates the same two sets of files
behind `BR2_PACKAGE_THINGINO_MOTORS_WS` and
`BR2_PACKAGE_THINGINO_MOTORS_WS_TLS`; both configurations must stay
warning-clean here so a broken one gets noticed.

## Build version

`ingenic-motor -V` (or `--version`) prints the build version, and `-j` carries it
as a `"version"` field. It is answered before the daemon-alive check, so it still
works on a camera whose daemon is down. The value is set on the compile command
line by the Buildroot package (`-DMOTORS_BUILD_VERSION=...`); a build straight
from this tree reports `unknown`.

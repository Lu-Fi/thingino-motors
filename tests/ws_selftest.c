/* Self-test for the parts of the WebSocket frontend that need no motor
 * hardware, no libjct and no root: the two hashes, base64, the RFC 6455
 * handshake vector, frame encoding/parsing and the query-string parser.
 *
 * Builds and runs natively on the development host (`make check`), which
 * matters because the daemon itself only links against the target sysroot -
 * without this, the new protocol code would have no execution coverage at
 * all before it reached a camera. */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

#include "sha1.h"
#include "sha256.h"
#include "ws.h"

static int failures = 0;
static int checks = 0;

static void check_str(const char *what, const char *got, const char *want) {
  checks++;
  if (strcmp(got, want) == 0) {
    printf("  ok   %s\n", what);
  } else {
    printf("  FAIL %s\n         got  '%s'\n         want '%s'\n", what, got,
           want);
    failures++;
  }
}

static void check_int(const char *what, long got, long want) {
  checks++;
  if (got == want) {
    printf("  ok   %s\n", what);
  } else {
    printf("  FAIL %s (got %ld, want %ld)\n", what, got, want);
    failures++;
  }
}

static void hexify(const unsigned char *in, size_t n, char *out) {
  static const char hx[] = "0123456789abcdef";
  for (size_t i = 0; i < n; i++) {
    out[i * 2] = hx[in[i] >> 4];
    out[i * 2 + 1] = hx[in[i] & 15];
  }
  out[n * 2] = '\0';
}

static void test_sha1(void) {
  unsigned char d[20];
  char hex[41];
  sha1_ctx c;

  puts("SHA-1 (RFC 3174 test vectors)");

  sha1_init(&c);
  sha1_update(&c, (const unsigned char *)"abc", 3);
  sha1_final(&c, d);
  hexify(d, 20, hex);
  check_str("sha1(\"abc\")", hex, "a9993e364706816aba3e25717850c26c9cd0d89d");

  sha1_init(&c);
  sha1_update(&c,
              (const unsigned char *)"abcdbcdecdefdefgefghfghighijhi"
                                     "jkijkljklmklmnlmnomnopnopq",
              56);
  sha1_final(&c, d);
  hexify(d, 20, hex);
  check_str("sha1(56-byte vector)", hex,
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1");

  sha1_init(&c);
  sha1_final(&c, d);
  hexify(d, 20, hex);
  check_str("sha1(\"\")", hex, "da39a3ee5e6b4b0d3255bfef95601890afd80709");

  /* multi-chunk update must agree with a single update: this is what
   * exercises the partial-block buffering path */
  sha1_init(&c);
  for (int i = 0; i < 100000; i++)
    sha1_update(&c, (const unsigned char *)"aaaaaaaaaa", 10);
  sha1_final(&c, d);
  hexify(d, 20, hex);
  check_str("sha1(1e6 x 'a', chunked)", hex,
            "34aa973cd4c4daa4f61eeb2bdbad27316534016f");
}

static void test_sha256(void) {
  unsigned char d[SHA256_DIGEST_LEN];
  char hex[65];

  puts("SHA-256 (FIPS 180-4 test vectors)");

  sha256("abc", 3, d);
  hexify(d, sizeof(d), hex);
  check_str("sha256(\"abc\")", hex,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

  sha256("", 0, d);
  hexify(d, sizeof(d), hex);
  check_str("sha256(\"\")", hex,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

  sha256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56, d);
  hexify(d, sizeof(d), hex);
  check_str("sha256(56-byte vector)", hex,
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
}

static void test_base64(void) {
  char out[64];

  puts("base64");

  ws_base64_encode((const unsigned char *)"", 0, out);
  check_str("b64(\"\")", out, "");
  ws_base64_encode((const unsigned char *)"f", 1, out);
  check_str("b64(\"f\")", out, "Zg==");
  ws_base64_encode((const unsigned char *)"fo", 2, out);
  check_str("b64(\"fo\")", out, "Zm8=");
  ws_base64_encode((const unsigned char *)"foo", 3, out);
  check_str("b64(\"foo\")", out, "Zm9v");
  ws_base64_encode((const unsigned char *)"foob", 4, out);
  check_str("b64(\"foob\")", out, "Zm9vYg==");
  ws_base64_encode((const unsigned char *)"fooba", 5, out);
  check_str("b64(\"fooba\")", out, "Zm9vYmE=");
  ws_base64_encode((const unsigned char *)"foobar", 6, out);
  check_str("b64(\"foobar\")", out, "Zm9vYmFy");
}

static void test_accept_key(void) {
  char accept[29];

  puts("RFC 6455 section 1.3 handshake vector");

  /* The example from the RFC itself: the client sends
   *   Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
   * and the server must answer
   *   Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
   * If this line passes, a real browser will complete the upgrade. */
  ws_accept_key("dGhlIHNhbXBsZSBub25jZQ==", accept);
  check_str("Sec-WebSocket-Accept", accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
}

static void test_query(void) {
  char v[64];

  puts("query string parsing");

  check_int("token found", ws_query_param("token=abc123", "token", v, sizeof v),
            1);
  check_str("token value", v, "abc123");

  check_int("token among others",
            ws_query_param("a=1&token=xyz&b=2", "token", v, sizeof v), 1);
  check_str("token value 2", v, "xyz");

  check_int("absent token", ws_query_param("a=1&b=2", "token", v, sizeof v), 0);

  /* a key that is a suffix/prefix of another must not match */
  check_int("no prefix confusion",
            ws_query_param("mytoken=nope", "token", v, sizeof v), 0);

  check_int("percent decoding",
            ws_query_param("token=a%2Bb%20c", "token", v, sizeof v), 1);
  check_str("decoded value", v, "a+b c");

  /* present-but-empty is "found" with an empty value, not "absent". The
   * distinction matters at the call site: an empty token must produce an
   * authentication FAILURE (ws_token_check rejects it), never a silent fall
   * through to some other credential path. */
  check_int("empty value is still found",
            ws_query_param("token=", "token", v, sizeof v), 1);
  check_str("empty value is empty", v, "");
}

/* --- frame round trip over a socketpair --------------------------------
 *
 * ws_send_frame() writes a SERVER frame (unmasked) and ws_read_message()
 * expects a CLIENT frame (masked), so the test masks by hand on the way in.
 * That asymmetry is the point: a server that accepts unmasked client frames
 * is a spec violation with a real attack behind it, and the test below
 * asserts we reject them. */

static void send_client_frame(int fd, int opcode, bool fin,
                              const unsigned char *payload, size_t len,
                              bool masked) {
  unsigned char hdr[14];
  size_t h = 0;
  unsigned char mask[4] = {0x37, 0xfa, 0x21, 0x3d};
  unsigned char body[512];

  hdr[h++] = (unsigned char)((fin ? 0x80 : 0x00) | opcode);
  if (len < 126)
    hdr[h++] = (unsigned char)((masked ? 0x80 : 0x00) | len);
  else {
    hdr[h++] = (unsigned char)((masked ? 0x80 : 0x00) | 126);
    hdr[h++] = (unsigned char)(len >> 8);
    hdr[h++] = (unsigned char)(len & 0xFF);
  }
  if (masked) {
    memcpy(hdr + h, mask, 4);
    h += 4;
  }
  if (write(fd, hdr, h) < 0)
    return;

  for (size_t i = 0; i < len; i++)
    body[i] = masked ? (unsigned char)(payload[i] ^ mask[i & 3]) : payload[i];
  if (len && write(fd, body, len) < 0)
    return;
}

static void test_frames(void) {
  int sp[2];
  ws_conn c;
  unsigned char out[WS_MAX_PAYLOAD + 1];
  size_t len = 0;
  int op = 0, rc;

  puts("frame parsing");

  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) != 0) {
    puts("  SKIP (socketpair failed)");
    return;
  }

  /* a normal masked text frame */
  ws_conn_init(&c, sp[0]);
  send_client_frame(sp[1], WS_OP_TEXT, true, (const unsigned char *)"{\"a\":1}",
                    7, true);
  rc = ws_read_message(&c, &op, out, sizeof out, &len, 500);
  check_int("masked text frame accepted", rc, WS_OK);
  check_int("opcode is TEXT", op, WS_OP_TEXT);
  check_int("length", (long)len, 7);
  check_str("payload", (const char *)out, "{\"a\":1}");

  /* fragmented message: TEXT(!fin) + CONT(fin) */
  send_client_frame(sp[1], WS_OP_TEXT, false, (const unsigned char *)"{\"a\":",
                    5, true);
  send_client_frame(sp[1], WS_OP_CONT, true, (const unsigned char *)"1}", 2,
                    true);
  rc = ws_read_message(&c, &op, out, sizeof out, &len, 500);
  check_int("fragmented message reassembled", rc, WS_OK);
  check_str("reassembled payload", (const char *)out, "{\"a\":1}");

  /* a PING must be answered with a PONG and must not surface to the caller;
   * the timeout path then reports WS_AGAIN */
  send_client_frame(sp[1], WS_OP_PING, true, NULL, 0, true);
  rc = ws_read_message(&c, &op, out, sizeof out, &len, 200);
  check_int("ping swallowed, then timeout", rc, WS_AGAIN);
  {
    unsigned char pong[8];
    ssize_t n = read(sp[1], pong, sizeof pong);
    check_int("pong emitted", (long)n, 2);
    check_int("pong opcode", pong[0], 0x80 | WS_OP_PONG);
    check_int("pong is unmasked", pong[1] & 0x80, 0);
  }

  /* CLOSE terminates */
  send_client_frame(sp[1], WS_OP_CLOSE, true, NULL, 0, true);
  rc = ws_read_message(&c, &op, out, sizeof out, &len, 500);
  check_int("close reported", rc, WS_CLOSED);

  close(sp[0]);
  close(sp[1]);

  /* an UNMASKED client frame must be refused (RFC 6455 section 5.1) */
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0) {
    ws_conn_init(&c, sp[0]);
    send_client_frame(sp[1], WS_OP_TEXT, true, (const unsigned char *)"hi", 2,
                      false);
    rc = ws_read_message(&c, &op, out, sizeof out, &len, 500);
    check_int("unmasked client frame rejected", rc, WS_EPROTO);
    close(sp[0]);
    close(sp[1]);
  }

  /* an oversized frame must be refused rather than truncated or allocated */
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0) {
    unsigned char hdr[8] = {0x81, 0xFE, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00};
    ws_conn_init(&c, sp[0]);
    /* declares a 65535-byte payload, far over WS_MAX_PAYLOAD */
    if (write(sp[1], hdr, 8) > 0) {
      rc = ws_read_message(&c, &op, out, sizeof out, &len, 500);
      check_int("oversized frame rejected", rc, WS_ETOOBIG);
    }
    close(sp[0]);
    close(sp[1]);
  }

  /* a server frame must go out unmasked with the right header shape */
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0) {
    unsigned char hdr[4];
    ws_send_text(sp[0], "hello");
    if (read(sp[1], hdr, 2) == 2) {
      check_int("server frame FIN+TEXT", hdr[0], 0x81);
      check_int("server frame unmasked, len 5", hdr[1], 5);
    }
    close(sp[0]);
    close(sp[1]);
  }
}

int main(void) {
  test_sha1();
  test_sha256();
  test_base64();
  test_accept_key();
  test_query();
  test_frames();

  printf("\n%d checks, %d failure(s)\n", checks, failures);
  return failures ? 1 : 0;
}


#include "MPC_SHA256.h"
#include "shared.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// XOR combine three 32-byte digests
static void xor3_digest(uint32_t out[8], uint32_t *d0, uint32_t *d1,
                        uint32_t *d2) {
  for (int i = 0; i < 8; i++) {
    out[i] = d0[i] ^ d1[i] ^ d2[i];
  }
}

static void hexprint(const unsigned char *buf, size_t n) {
  for (size_t i = 0; i < n; i++)
    printf("%02x", buf[i]);
  printf("\n");
}

static void hexprint_digest(const uint32_t digest[8]) {
  for (size_t i = 0; i < 8; i++)
    printf("%02x", digest[i]);
  printf("\n");
}


inline void store_u32_be(const uint32_t src, unsigned char *dst) {
  dst[0] = src >> 24;
  dst[1] = src >> 16;
  dst[2] = src >> 8;
  dst[3] = src;
}

static void make_xor_shares(unsigned char m[3][L_BYTES],
                            const unsigned char *msg) {
  for (size_t i = 0; i < L_BYTES; i++) {
    unsigned char r0 = (unsigned char)(rand() & 0xff);
    unsigned char r1 = (unsigned char)(rand() & 0xff);
    m[0][i] = r0;
    m[1][i] = r1;
    m[2][i] = msg[i] ^ r0 ^ r1;
  }
}

void bytes_to_hex(char out[65], const uint8_t in[32]) {
  static const char hexd[] = "0123456789abcdef";
  for (int i = 0; i < 32; i++) {
    out[2 * i] = hexd[in[i] >> 4];
    out[2 * i + 1] = hexd[in[i] & 0xF];
  }
  out[64] = '\0';
}

void test_vector(const unsigned char *msg, const char *expected_hex,
                 unsigned char *randomness[3], uint8_t rs[3][4], View *views[3],
                 int *countY) {

  unsigned char shares[3][L_BYTES];
  make_xor_shares(shares, msg);

  commit(shares, randomness, rs, views);

  uint32_t digest[8];
  xor3_digest(digest, &views[0]->y[ySize - 8], &views[1]->y[ySize - 8],
              &views[2]->y[ySize - 8]);

  unsigned char digestChar[32] = {0};
  for (int i = 0; i < 8; i++) {
    store_u32_be(digest[i], &digestChar[i * 4]);
  }
  char digestStr[65] = {0};
  bytes_to_hex(digestStr, digestChar);

  if (memcmp(digestStr, expected_hex, 65)) {
    // hexprint(digestChar, 32);
    printf("Digest: %s\n", digestStr);
    printf("Expected: %s\n", expected_hex);
    exit(EXIT_FAILURE);
  }
}

int main() {
  srand((unsigned)time(NULL));

  View *views[3] = {malloc(sizeof(View)), malloc(sizeof(View)),
                    malloc(sizeof(View))};
  int countY = 0;

  unsigned char *randomness[3] = {malloc(RAND_BYTES), malloc(RAND_BYTES),
                                  malloc(RAND_BYTES)};

  uint8_t rs[3][4];

  // Important: each test vector must have size L_BYTES
  unsigned char msg_as[L_BYTES];
  memset(msg_as, 'a', L_BYTES);

  test_vector(
      msg_as,
      "6836cf13bac400e9105071cd6af47084dfacad4e5e302c94bfed24e013afb73e",
      randomness, rs, views, &countY);

  unsigned char msg_bs[L_BYTES];
  memset(msg_bs, 'b', L_BYTES);
  test_vector(
      msg_bs,
      "70ae1c5307f5250d5cb9e40742ba9613fcdf9b8d9eb6dd393330443b2d5effbd",
      randomness, rs, views, &countY);

  return 0;
}

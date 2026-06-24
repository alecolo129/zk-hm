#include "mpc_sha256.h"
#include "shared.h"
#include <gtest/gtest.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdio.h>

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define SHR(x, n) ((x) >> (n))

static const uint32_t K0[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

static const uint32_t H0[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                               0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

static uint32_t load_be32(const unsigned char *p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8) | ((uint32_t)p[3] << 0);
}

static void print_state(int round, uint32_t a, uint32_t b, uint32_t c,
                        uint32_t d, uint32_t e, uint32_t f, uint32_t g,
                        uint32_t h, uint32_t temp1, uint32_t temp2) {
  printf("round %2d: "
         "a=%08x b=%08x c=%08x d=%08x "
         "e=%08x f=%08x g=%08x h=%08x "
         "t1=%08x t2=%08x\n",
         round, a, b, c, d, e, f, g, h, temp1, temp2);
}

void sha256_trace_block(const unsigned char block[64], uint32_t H[8]) {
  uint32_t W[64];

  for (int i = 0; i < 16; ++i) {
    W[i] = load_be32(block + 4 * i);
    printf("W[%2d] = %08x\n", i, W[i]);
  }

  for (int i = 16; i < 64; ++i) {
    uint32_t s0 = ROTR(W[i - 15], 7) ^ ROTR(W[i - 15], 18) ^ SHR(W[i - 15], 3);
    uint32_t s1 = ROTR(W[i - 2], 17) ^ ROTR(W[i - 2], 19) ^ SHR(W[i - 2], 10);
    W[i] = W[i - 16] + s0 + W[i - 7] + s1;
    printf("W[%2d] = %08x\n", i, W[i]);
  }

  uint32_t a = H[0];
  uint32_t b = H[1];
  uint32_t c = H[2];
  uint32_t d = H[3];
  uint32_t e = H[4];
  uint32_t f = H[5];
  uint32_t g = H[6];
  uint32_t h = H[7];

  for (int i = 0; i < 64; ++i) {
    uint32_t S1 = ROTR(e, 6) ^ ROTR(e, 11) ^ ROTR(e, 25);
    uint32_t ch = (e & f) ^ ((~e) & g);
    uint32_t temp1 = h + S1 + ch + K0[i] + W[i];
    uint32_t S0 = ROTR(a, 2) ^ ROTR(a, 13) ^ ROTR(a, 22);
    uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
    uint32_t temp2 = S0 + maj;

    uint32_t new_h = g;
    uint32_t new_g = f;
    uint32_t new_f = e;
    uint32_t new_e = d + temp1;
    uint32_t new_d = c;
    uint32_t new_c = b;
    uint32_t new_b = a;
    uint32_t new_a = temp1 + temp2;

    a = new_a;
    b = new_b;
    c = new_c;
    d = new_d;
    e = new_e;
    f = new_f;
    g = new_g;
    h = new_h;

    print_state(i, a, b, c, d, e, f, g, h, temp1, temp2);
  }

  H[0] += a;
  H[1] += b;
  H[2] += c;
  H[3] += d;
  H[4] += e;
  H[5] += f;
  H[6] += g;
  H[7] += h;

  printf("H = %08x %08x %08x %08x %08x %08x %08x %08x\n", H[0], H[1], H[2],
         H[3], H[4], H[5], H[6], H[7]);
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

inline void store_u32_be(const uint32_t src, unsigned char *dst) {
  dst[0] = src >> 24;
  dst[1] = src >> 16;
  dst[2] = src >> 8;
  dst[3] = src;
}

// XOR combine three 32-byte digests
static void xor3_digest(uint32_t out[8], uint32_t *d0, uint32_t *d1,
                        uint32_t *d2) {
  for (int i = 0; i < 8; i++) {
    out[i] = d0[i] ^ d1[i] ^ d2[i];
  }
}

static void hexprint_digest(const uint32_t digest[8]) {
  for (size_t i = 0; i < 8; i++)
    printf("%02x", digest[i]);
  printf("\n");
}

void bytes_to_hex(char out[65], const uint8_t *in) {
  static const char hexd[] = "0123456789abcdef";
  for (int i = 0; i < 32; i++) {
    out[2 * i] = hexd[in[i] >> 4];
    out[2 * i + 1] = hexd[in[i] & 0xF];
  }
  out[64] = '\0';
}

TEST(MPCSha256Test, test) {
  srand((unsigned)time(NULL));

  View *views[3] = {(View *)malloc(sizeof(View)), (View *)malloc(sizeof(View)),
                    (View *)malloc(sizeof(View))};

  unsigned char *randomness[3] = {(unsigned char *)malloc(RAND_BYTES),
                                  (unsigned char *)malloc(RAND_BYTES),
                                  (unsigned char *)malloc(RAND_BYTES)};

  // pick and share a random message
  unsigned char msg_as[L_BYTES];
  RAND_bytes(msg_as, L_BYTES);
  unsigned char shares[3][L_BYTES];
  make_xor_shares(shares, msg_as);

  // generate zk-prove
  mpc_sha256_prove(shares, randomness, views);
  uint32_t mpc_digets[8];
  xor3_digest(mpc_digets, &views[0]->y[ySize - 8], &views[1]->y[ySize - 8],
              &views[2]->y[ySize - 8]);
  unsigned char actual[32];
  for (int i = 0; i < 8; ++i) {
    store_u32_be(mpc_digets[i], &actual[i * 4]);
  }

  uint8_t expected_digest[32];
  SHA256(msg_as, L_BYTES, expected_digest);

  EXPECT_EQ(memcmp(expected_digest, actual, 32), 0)
      << (int)expected_digest[0] << " - " << (int)actual[0];
}
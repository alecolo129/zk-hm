#include "mpc_sha256.h"
#include "mpc_core_funcs.h"
#include "prg.h"
#include "shared.h"
#include <gtest/gtest.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdio.h>

static void make_xor_shares(RVec shares[3], const RVec *msg) {
  RAND_bytes((uint8_t *)shares[0].words, sizeof(shares[0].words));
  RAND_bytes((uint8_t *)shares[1].words, sizeof(shares[1].words));
  rvec_normalize(&shares[0]);
  rvec_normalize(&shares[1]);

  for (int i = 0; i < L_WORDS; i++) {
    shares[2].words[i] =
        msg->words[i] ^ shares[0].words[i] ^ shares[1].words[i];
  }
  rvec_normalize(&shares[2]);
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
  RVec msg_as;
  RAND_bytes((uint8_t *)msg_as.words, sizeof(msg_as.words));
  rvec_normalize(&msg_as);
  RVec shares[3];
  make_xor_shares(shares, &msg_as);

  // generate zk-prove
  mpc_sha256_prove(shares, randomness, views);
  uint32_t mpc_digest[8];
  xor3_digest(mpc_digest, &views[0]->y[ySize - 8], &views[1]->y[ySize - 8],
              &views[2]->y[ySize - 8]);
  unsigned char actual[32];
  for (int i = 0; i < 8; ++i) {
    store_u32_be(mpc_digest[i], &actual[i * 4]);
  }

  uint8_t expected_digest[32];
  SHA256(rvec_const_bytes(&msg_as), L_BYTES, expected_digest);

  EXPECT_EQ(memcmp(expected_digest, actual, 32), 0)
      << (int)expected_digest[0] << " - " << (int)actual[0];
}

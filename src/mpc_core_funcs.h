#pragma once
#include "random_oracle.h"
#include "shared.h"
#include "string.h"

static inline void generate_keys_and_rs(uint8_t keys[NUM_ROUNDS][3][16],
                                        uint8_t keyH[16],
                                        uint8_t rs[NUM_ROUNDS][3][4]) {
  RAND_bytes((uint8_t *)keys, NUM_ROUNDS * 3 * 16);
  RAND_bytes((uint8_t *)keyH, 16);
  RAND_bytes((uint8_t *)rs, NUM_ROUNDS * 3 * 4);
}

static inline void share_secrets(uint8_t rShares[3][L_BYTES],
                                 uint32_t msgShares[MSG_WORDS][3],
                                 const uint8_t rBytes[L_BYTES],
                                 const uint8_t msg[MSG_BYTES]) {

  RAND_bytes((uint8_t *)rShares, 3 * L_BYTES * sizeof(uint8_t));
  for (int j = 0; j < L_BYTES; j++) {
    rShares[2][j] = rBytes[j] ^ rShares[0][j] ^ rShares[1][j];
  }

  RAND_bytes((uint8_t *)msgShares, 3 * MSG_WORDS * sizeof(uint32_t));
  uint32_t mask =
      (MSG_BITS % 32) ? ((1ul << (MSG_BITS % 32)) - 1) : 0xFFFFFFFFu;
  msgShares[MSG_WORDS - 1][0] &= mask;
  msgShares[MSG_WORDS - 1][1] &= mask;
  for (int j = 0; j < MSG_WORDS; j++) {
    load_u32_le(&msgShares[j][2], &msg[j * 4]);
    msgShares[j][2] ^= msgShares[j][0] ^ msgShares[j][1];
  }
}

static inline void generate_challenge(ZkBooCommit *a, int *e, EVP_MD_CTX *ctx) {
  uint32_t finalHash[8];
  for (int j = 0; j < 8; j++) {
    finalHash[j] = a->yp[0][j] ^ a->yp[1][j] ^ a->yp[2][j];
  }
  H3(ctx, finalHash, a, 1, e);
}

static inline void open(ZkBooOpen *z, int e, const unsigned char keys[3][16],
                        const unsigned char rs[3][4], View *views[3]) {
  memcpy(z->ke, keys[e], 16);
  memcpy(z->ke1, keys[(e + 1) % 3], 16);
  z->ve = views[e];
  z->ve1 = views[(e + 1) % 3];
  memcpy(z->re, rs[e], 4);
  memcpy(z->re1, rs[(e + 1) % 3], 4);
}

static inline void output(View *v, uint32_t *result) {
  memcpy(result, &v->y[ySize - 8], 32);
}

static inline void reconstruct(uint32_t *y0, uint32_t *y1, uint32_t *y2,
                               uint32_t *result) {
  for (int i = 0; i < 8; i++) {
    result[i] = y0[i] ^ y1[i] ^ y2[i];
  }
}
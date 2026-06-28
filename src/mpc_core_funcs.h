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

static inline void share_secrets(RVec rShares[3],
                                 uint32_t msgShares[MSG_WORDS][3],
                                 const RVec *r,
                                 const uint8_t msg[MSG_BYTES]) {

  RAND_bytes((uint8_t *)rShares[0].words, sizeof(rShares[0].words));
  RAND_bytes((uint8_t *)rShares[1].words, sizeof(rShares[1].words));
  rvec_normalize(&rShares[0]);
  rvec_normalize(&rShares[1]);

  for (int j = 0; j < L_WORDS; j++) {
    rShares[2].words[j] =
        r->words[j] ^ rShares[0].words[j] ^ rShares[1].words[j];
  }
  rvec_normalize(&rShares[2]);

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

static inline void generate_challenge(EVP_MD_CTX *ctx, int *e, const ZkBooCommit *a, const uint8_t* finalHash) {
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

static inline void reconstruct(const uint32_t *y0, const uint32_t *y1, const uint32_t *y2,
                               uint8_t *result) {
                                
  for (int i = 0; i < 8; i++) {
    store_u32_be(y0[i] ^ y1[i] ^ y2[i], &result[i * 4]);
  }
}

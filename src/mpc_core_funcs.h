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

static inline void load_digest_words(const uint8_t digest[SHA256_DIGEST_LENGTH],
                                     uint32_t words[SHA256_DIGEST_WORDS]) {
  for (int i = 0; i < SHA256_DIGEST_WORDS; i++) {
    load_u32_be(&words[i], &digest[i * sizeof(uint32_t)]);
  }
}

static inline void reconstruct_sha256_output_shares(
    const ZkBooCommit *a, const uint8_t digest[SHA256_DIGEST_LENGTH],
    uint32_t output_shares[3][SHA256_DIGEST_WORDS]) {
  uint32_t digest_words[SHA256_DIGEST_WORDS];
  load_digest_words(digest, digest_words);

  for (int i = 0; i < SHA256_DIGEST_WORDS; i++) {
    output_shares[0][i] = a->yp[0][i];
    output_shares[1][i] = a->yp[1][i];
    output_shares[2][i] = digest_words[i] ^ a->yp[0][i] ^ a->yp[1][i];
  }
}

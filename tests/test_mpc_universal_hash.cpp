#include "mpc_universal_hash.h"
#include <gtest/gtest.h>

TEST(MPCUniversalHashTest, SeededHashMatchesReferenceAndShares) {
  uint8_t key[16] = {0};
  uint8_t message[MSG_BYTES] = {1};
  RVec r;
  RVec shares[3];
  for (size_t j = 0; j < L_WORDS; ++j) {
    r.words[j] = 0x89abcdefu ^ static_cast<uint32_t>(j);
    shares[0].words[j] = 0xfedcba98u ^ static_cast<uint32_t>(j);
    shares[1].words[j] = 0x76543210u ^ static_cast<uint32_t>(j);
    shares[2].words[j] = r.words[j] ^ shares[0].words[j] ^ shares[1].words[j];
  }
  rvec_normalize(&r);
  for (auto &share : shares) {
    rvec_normalize(&share);
  }

  UniversalHash h = {};
  mpc_hm_hash_init(h.A, h.b, key, message, &r);
  EXPECT_EQ(h.A[A_WORDS - 1], 0u);
  for (size_t i = 0; i < MSG_BITS; ++i) {
    uint32_t expected = (message[i / 8] >> (i % 8)) & 1u;
    for (size_t j = 0; j < L_BITS; ++j) {
      expected ^= ((h.A[(i + j) / 32] >> ((i + j) % 32)) & 1u) &
                  ((r.words[j / 32] >> (j % 32)) & 1u);
    }
    EXPECT_EQ((h.b[i / 8] >> (i % 8)) & 1u, expected);
  }

  uint32_t message_shares[MSG_WORDS][3] = {};
  message_shares[0][0] = 1;
  message_shares[0][1] = 1;
  message_shares[0][2] = 1;
  uint32_t output[MSG_WORDS][3];
  mpc_universal_hash_prove(&h, message_shares, shares, output);
  EXPECT_EQ(output[0][0] ^ output[0][1] ^ output[0][2], h.b[0] & 1u);
  for (uint32_t e = 0; e < 3; ++e) {
    RVec opened[2] = {shares[e], shares[(e + 1) % 3]};
    uint32_t opened_message[MSG_WORDS][2] = {};
    for (size_t j = 0; j < MSG_WORDS; ++j) {
      opened_message[j][0] = message_shares[j][e];
      opened_message[j][1] = message_shares[j][(e + 1) % 3];
    }
    EXPECT_EQ(mpc_universal_hash_verify(&h, opened_message, opened, output, e),
              0);
    output[0][e] ^= 1;
    EXPECT_EQ(mpc_universal_hash_verify(&h, opened_message, opened, output, e),
              -1);
    output[0][e] ^= 1;
  }
}

TEST(MPCUniversalHashTest, InnerProductUsesWordBackedShares) {
  for (int iter = 0; iter < 32; iter++) {
    uint8_t msg[MSG_BYTES] = {0};
    ASSERT_EQ(RAND_bytes(msg, sizeof(msg)), 1);
    msg[0] &= 1;

    RVec r;
    ASSERT_EQ(RAND_bytes((uint8_t *)r.words, sizeof(r.words)), 1);
    rvec_normalize(&r);

    uint8_t keyA[16];
    ASSERT_EQ(RAND_bytes(keyA, sizeof(keyA)), 1);

    UniversalHash h = {};
    mpc_hm_hash_init(h.A, h.b, keyA, msg, &r);

    RVec rShares[3];
    ASSERT_EQ(RAND_bytes((uint8_t *)rShares[0].words, sizeof(rShares[0].words)),
              1);
    ASSERT_EQ(RAND_bytes((uint8_t *)rShares[1].words, sizeof(rShares[1].words)),
              1);
    rvec_normalize(&rShares[0]);
    rvec_normalize(&rShares[1]);
    for (int j = 0; j < L_WORDS; j++) {
      rShares[2].words[j] =
          r.words[j] ^ rShares[0].words[j] ^ rShares[1].words[j];
    }
    rvec_normalize(&rShares[2]);

    for (int j = 0; j < L_WORDS; j++) {
      EXPECT_EQ(
          (rShares[0].words[j] ^ rShares[1].words[j] ^ rShares[2].words[j]),
          r.words[j]);
    }
    for (int j = 0; j < L_BYTES; j++) {
      EXPECT_EQ((rvec_const_bytes(&rShares[0])[j] ^
                 rvec_const_bytes(&rShares[1])[j] ^
                 rvec_const_bytes(&rShares[2])[j]),
                rvec_const_bytes(&r)[j]);
    }

    uint32_t msgShares[3];
    ASSERT_EQ(RAND_bytes((uint8_t *)msgShares, sizeof(msgShares)), 1);
    msgShares[0] &= 1;
    msgShares[1] &= 1;
    msgShares[2] = (msg[0] & 1) ^ msgShares[0] ^ msgShares[1];

    uint32_t y[3];
    mpc_inner_prod_prove(&h, msgShares, rShares, y);
    EXPECT_EQ((y[0] ^ y[1] ^ y[2] ^ (h.b[0] & 1)), 0u);

    for (uint32_t e = 0; e < 3; e++) {
      RVec openedR[2] = {rShares[e], rShares[(e + 1) % 3]};

      uint32_t openedM[2] = {msgShares[e], msgShares[(e + 1) % 3]};
      EXPECT_EQ(mpc_inner_prod_verify(&h, openedM, openedR, y, e), 0);
    }
  }
}

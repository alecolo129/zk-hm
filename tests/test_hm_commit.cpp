#include <gtest/gtest.h>
#include <openssl/rand.h>
#include <cstring>

#include "hm.h"
#include "mpc_universal_hash.h"

class HMCommit : public ::testing::Test {
protected:
  static void TearDownTestSuite() {
    remove("out_test.bin");
    remove("out_test1.bin");
    remove("out_test2.bin");
  }
};

TEST_F(HMCommit, BitCommitVerifyCorrectnessTest) {
  hm_buffer_t commitment;
  hm_buffer_t opening;

  for (int i = 0; i < 2; i++) {
    int bit = i % 2;

    // commit
    ASSERT_EQ(hm_bit_commit(bit, "out_test.bin", &commitment, &opening), 0);

    // verify zk proof
    EXPECT_EQ(hm_bit_verify(commitment.data, commitment.len, "out_test.bin"),
              0);

    // verify commitment given opening
    EXPECT_EQ(hm_bit_open(bit, commitment.data, commitment.len, opening.data,
                          opening.len),
              0);
    // cleanup
    hm_buffer_free(&commitment);
    hm_buffer_free(&opening);
  }
}

TEST_F(HMCommit, BitCommitVerifySoundnessTest) {
  hm_buffer_t commitment1;
  hm_buffer_t commitment2;

  hm_buffer_t opening1;
  hm_buffer_t opening2;

  for (int i = 0; i < 2; i++) {
    int bit = i % 2;

    // commit
    ASSERT_EQ(hm_bit_commit(bit, "out_test1.bin", &commitment1, &opening1), 0);
    ASSERT_EQ(hm_bit_commit(bit, "out_test2.bin", &commitment2, &opening2), 0);

    // wrong zk proof
    ASSERT_EQ(hm_bit_verify(commitment1.data, commitment1.len, "out_test2.bin"),
              -1);

    // wrong zk proof
    ASSERT_EQ(hm_bit_verify(commitment2.data, commitment2.len, "out_test1.bin"),
              -1);

    // wrong input bit
    EXPECT_EQ(hm_bit_open((bit + 1) % 2, commitment1.data, commitment1.len,
                          opening1.data, opening1.len),
              -1);

    // wrong opening
    EXPECT_EQ(hm_bit_open(bit, commitment1.data, commitment1.len, opening2.data,
                          opening2.len),
              -1);

    hm_buffer_free(&commitment1);
    hm_buffer_free(&opening1);
    hm_buffer_free(&commitment2);
    hm_buffer_free(&opening2);
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
    generate_H(h.A, h.b, keyA, msg, &r);

    RVec rShares[3];
    ASSERT_EQ(RAND_bytes((uint8_t *)rShares[0].words,
                         sizeof(rShares[0].words)),
              1);
    ASSERT_EQ(RAND_bytes((uint8_t *)rShares[1].words,
                         sizeof(rShares[1].words)),
              1);
    rvec_normalize(&rShares[0]);
    rvec_normalize(&rShares[1]);
    for (int j = 0; j < L_WORDS; j++) {
      rShares[2].words[j] =
          r.words[j] ^ rShares[0].words[j] ^ rShares[1].words[j];
    }
    rvec_normalize(&rShares[2]);

    for (int j = 0; j < L_WORDS; j++) {
      EXPECT_EQ((rShares[0].words[j] ^ rShares[1].words[j] ^
                 rShares[2].words[j]),
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

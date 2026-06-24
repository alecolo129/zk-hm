#include <gtest/gtest.h>

#include "hm.h"

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
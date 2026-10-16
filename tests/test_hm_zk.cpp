#include "hm_zk.h"
#include <cstdio>
#include <filesystem>
#include <gtest/gtest.h>

class HMZkCommit : public ::testing::Test {
protected:
  static void TearDownTestSuite() {
    remove("out_test.bin");
    remove("out_test1.bin");
    remove("out_test2.bin");
  }
};

TEST_F(HMZkCommit, BitCommitVerifyCorrectnessTest) {
  hm_buffer_t commitment;
  hm_buffer_t opening;

  for (int i = 0; i < 2; i++) {
    uint8_t bit = i % 2;

    // commit
    ASSERT_EQ(hm_bit_commit(bit, "out_test.bin", &commitment, &opening), 0);

    // verify zk proof
    EXPECT_EQ(hm_bit_verify(commitment.data, commitment.len, "out_test.bin"),
              0);

    // cleanup
    hm_buffer_free(&commitment);
    hm_buffer_free(&opening);
  }
}

TEST_F(HMZkCommit, BitCommitVerifySoundnessTest) {
  hm_buffer_t commitment1;
  hm_buffer_t commitment2;

  hm_buffer_t opening1;
  hm_buffer_t opening2;

  for (int i = 0; i < 2; i++) {
    uint8_t bit = i % 2;

    // commit
    ASSERT_EQ(hm_bit_commit(bit, "out_test1.bin", &commitment1, &opening1), 0);
    ASSERT_EQ(hm_bit_commit(bit, "out_test2.bin", &commitment2, &opening2), 0);

    // wrong zk proof
    ASSERT_EQ(hm_bit_verify(commitment1.data, commitment1.len, "out_test2.bin"),
              -1);

    // wrong zk proof
    ASSERT_EQ(hm_bit_verify(commitment2.data, commitment2.len, "out_test1.bin"),
              -1);

    hm_buffer_free(&commitment1);
    hm_buffer_free(&opening1);
    hm_buffer_free(&commitment2);
    hm_buffer_free(&opening2);
  }
}

TEST_F(HMZkCommit, RejectsModifiedAndTruncatedProofs) {
  const char *path = "out_test.bin";
  hm_buffer_t commitment = {};
  hm_buffer_t opening = {};
  ASSERT_EQ(hm_bit_commit(1, path, &commitment, &opening), 0);

  FILE *file = fopen(path, "r+b");
  ASSERT_NE(file, nullptr);
  int original = fgetc(file);
  ASSERT_NE(original, EOF);
  rewind(file);
  ASSERT_NE(fputc(original ^ 1, file), EOF);
  ASSERT_EQ(fclose(file), 0);
  EXPECT_EQ(hm_bit_verify(commitment.data, commitment.len, path), -1);

  // Restore the valid proof before testing a partial final record.
  file = fopen(path, "r+b");
  ASSERT_NE(file, nullptr);
  ASSERT_NE(fputc(original, file), EOF);
  ASSERT_EQ(fclose(file), 0);
  ASSERT_EQ(hm_bit_verify(commitment.data, commitment.len, path), 0);
  std::filesystem::resize_file(path, std::filesystem::file_size(path) - 1);
  EXPECT_EQ(hm_bit_verify(commitment.data, commitment.len, path), -1);

  std::filesystem::resize_file(path, 0);
  EXPECT_EQ(hm_bit_verify(commitment.data, commitment.len, path), -1);
  hm_buffer_free(&commitment);
  hm_buffer_free(&opening);
}

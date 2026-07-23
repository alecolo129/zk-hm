#include <algorithm>
#include <cstring>
#include <gtest/gtest.h>
#include <openssl/rand.h>
#include <vector>

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
    uint8_t bit = i % 2;

    // commit
    ASSERT_EQ(hm_bit_commit(bit, "out_test.bin", &commitment, &opening), 0);

    // verify zk proof
    EXPECT_EQ(hm_bit_verify(commitment.data, commitment.len, "out_test.bin"),
              0);

    // verify commitment given opening
    EXPECT_EQ(hm_verify(&bit, 1, commitment.data, commitment.len, opening.data,
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

    // wrong input bit
    uint8_t wrong_bit = (bit + 1) % 2;
    EXPECT_EQ(hm_verify(&wrong_bit, 1, commitment1.data, commitment1.len,
                        opening1.data, opening1.len),
              -1);

    // wrong opening
    EXPECT_EQ(hm_verify(&bit, 1, commitment1.data, commitment1.len,
                        opening2.data, opening2.len),
              -1);

    hm_buffer_free(&commitment1);
    hm_buffer_free(&opening1);
    hm_buffer_free(&commitment2);
    hm_buffer_free(&opening2);
  }
}

static constexpr size_t ceil_bits_to_bytes(size_t bit_len) {
  return (bit_len + 7u) / 8u;
}

static size_t opening_bytes_non_zk(size_t message_bit_len) {
  return (4u * K + 2u * message_bit_len + 4u + 7u) / 8u;
}

static std::vector<uint8_t> make_message(size_t bit_len) {
  std::vector<uint8_t> message(ceil_bits_to_bytes(bit_len));
  EXPECT_EQ(RAND_bytes(message.data(), message.size()), 1);
  return message;
}

TEST_F(HMCommit, PlainCommitVerifyVariableBitLengths) {
  const size_t bit_lengths[] = {1, 4, 7, 8, 9, 31, 32, 33, 257, 1024};

  for (size_t bit_len : bit_lengths) {
    std::vector<uint8_t> message = make_message(bit_len);
    hm_commit_sizes_t sizes = {};
    ASSERT_EQ(hm_commit_get_sizes(bit_len, &sizes), 0);

    EXPECT_EQ(sizes.commitment_len,
              16u + ceil_bits_to_bytes(bit_len) + SHA256_DIGEST_LENGTH);
    EXPECT_EQ(sizes.opening_len, opening_bytes_non_zk(bit_len));

    std::vector<uint8_t> commitment(sizes.commitment_len);
    std::vector<uint8_t> opening(sizes.opening_len);

    ASSERT_EQ(hm_commit(message.data(), bit_len, commitment.data(),
                        commitment.size(), opening.data(), opening.size()),
              0)
        << "bit_len=" << bit_len;

    EXPECT_EQ(hm_verify(message.data(), bit_len, commitment.data(),
                        commitment.size(), opening.data(), opening.size()),
              0)
        << "bit_len=" << bit_len;
  }
}

TEST_F(HMCommit, PlainVerifyRejectsTampering) {
  std::vector<uint8_t> message = make_message(1024);
  hm_commit_sizes_t sizes = {};
  ASSERT_EQ(hm_commit_get_sizes(1024, &sizes), 0);
  std::vector<uint8_t> commitment(sizes.commitment_len);
  std::vector<uint8_t> opening(sizes.opening_len);

  ASSERT_EQ(hm_commit(message.data(), 1024, commitment.data(),
                      commitment.size(), opening.data(), opening.size()),
            0);

  std::vector<uint8_t> tampered_commitment = commitment;
  tampered_commitment[0] ^= 0x01u;
  EXPECT_EQ(hm_verify(message.data(), 1024, tampered_commitment.data(),
                      tampered_commitment.size(), opening.data(),
                      opening.size()),
            -1);

  tampered_commitment = commitment;
  tampered_commitment[16] ^= 0x01u;
  EXPECT_EQ(hm_verify(message.data(), 1024, tampered_commitment.data(),
                      tampered_commitment.size(), opening.data(),
                      opening.size()),
            -1);

  tampered_commitment = commitment;
  tampered_commitment[tampered_commitment.size() - 1u] ^= 0x01u;
  EXPECT_EQ(hm_verify(message.data(), 1024, tampered_commitment.data(),
                      tampered_commitment.size(), opening.data(),
                      opening.size()),
            -1);

  std::vector<uint8_t> tampered_opening = opening;
  tampered_opening[0] ^= 0x01u;
  EXPECT_EQ(hm_verify(message.data(), 1024, commitment.data(),
                      commitment.size(), tampered_opening.data(),
                      tampered_opening.size()),
            -1);
}

TEST_F(HMCommit, PlainVerifyRejectsWrongMessageBit) {
  std::vector<uint8_t> message = make_message(33);
  hm_commit_sizes_t sizes = {};
  ASSERT_EQ(hm_commit_get_sizes(33, &sizes), 0);
  std::vector<uint8_t> commitment(sizes.commitment_len);
  std::vector<uint8_t> opening(sizes.opening_len);

  ASSERT_EQ(hm_commit(message.data(), 33, commitment.data(), commitment.size(),
                      opening.data(), opening.size()),
            0);

  std::vector<uint8_t> wrong_message = message;
  wrong_message[2] ^= 0x04u;
  EXPECT_EQ(hm_verify(wrong_message.data(), 33, commitment.data(),
                      commitment.size(), opening.data(), opening.size()),
            -1);
}

TEST_F(HMCommit, PlainCommitRejectsInvalidSizesBeforeWriting) {
  hm_commit_sizes_t sizes = {};
  ASSERT_EQ(hm_commit_get_sizes(33, &sizes), 0);
  EXPECT_EQ(hm_commit_get_sizes(0, &sizes), -1);
  EXPECT_EQ(sizes.commitment_len, 0u);
  EXPECT_EQ(sizes.opening_len, 0u);
  EXPECT_EQ(hm_commit_get_sizes(33, nullptr), -1);
  EXPECT_EQ(hm_commit_get_sizes(SIZE_MAX, &sizes), -1);

  ASSERT_EQ(hm_commit_get_sizes(33, &sizes), 0);
  std::vector<uint8_t> message = make_message(33);
  std::vector<uint8_t> commitment(sizes.commitment_len + 2u, 0xa5u);
  std::vector<uint8_t> opening(sizes.opening_len + 2u, 0x5au);

  EXPECT_EQ(hm_commit(message.data(), 33, commitment.data() + 1u,
                      sizes.commitment_len - 1u, opening.data() + 1u,
                      sizes.opening_len),
            -1);
  EXPECT_TRUE(std::all_of(commitment.begin(), commitment.end(),
                          [](uint8_t v) { return v == 0xa5u; }));
  EXPECT_TRUE(std::all_of(opening.begin(), opening.end(),
                          [](uint8_t v) { return v == 0x5au; }));

  EXPECT_EQ(hm_commit(message.data(), 33, commitment.data() + 1u,
                      sizes.commitment_len, opening.data() + 1u,
                      sizes.opening_len - 1u),
            -1);
  EXPECT_TRUE(std::all_of(commitment.begin(), commitment.end(),
                          [](uint8_t v) { return v == 0xa5u; }));
  EXPECT_TRUE(std::all_of(opening.begin(), opening.end(),
                          [](uint8_t v) { return v == 0x5au; }));

  ASSERT_EQ(hm_commit(message.data(), 33, commitment.data() + 1u,
                      sizes.commitment_len, opening.data() + 1u,
                      sizes.opening_len),
            0);
  EXPECT_EQ(commitment.front(), 0xa5u);
  EXPECT_EQ(commitment.back(), 0xa5u);
  EXPECT_EQ(opening.front(), 0x5au);
  EXPECT_EQ(opening.back(), 0x5au);
}

TEST_F(HMCommit, PlainCommitSupportsContiguousBatchBuffers) {
  constexpr size_t bit_len = 33;
  constexpr size_t count = 64;

  hm_commit_sizes_t sizes = {};
  ASSERT_EQ(hm_commit_get_sizes(bit_len, &sizes), 0);
  std::vector<uint8_t> messages(count * ceil_bits_to_bytes(bit_len));
  ASSERT_EQ(RAND_bytes(messages.data(), messages.size()), 1);

  //allocate enough size for batch commitments and openings
  std::vector<uint8_t> commitments(count * sizes.commitment_len);
  std::vector<uint8_t> openings(count * sizes.opening_len);

  for (size_t i = 0; i < count; i++) {
    const uint8_t *message = messages.data() + i * ceil_bits_to_bytes(bit_len);
    uint8_t *commitment = commitments.data() + i * sizes.commitment_len;
    uint8_t *opening = openings.data() + i * sizes.opening_len;
    ASSERT_EQ(hm_commit(message, bit_len, commitment, sizes.commitment_len,
                        opening, sizes.opening_len),
              0)
        << "i=" << i;
  }

  for (size_t i = 0; i < count; i++) {
    const uint8_t *message = messages.data() + i * ceil_bits_to_bytes(bit_len);
    const uint8_t *commitment = commitments.data() + i * sizes.commitment_len;
    const uint8_t *opening = openings.data() + i * sizes.opening_len;
    EXPECT_EQ(hm_verify(message, bit_len, commitment, sizes.commitment_len,
                        opening, sizes.opening_len),
              0)
        << "i=" << i;
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

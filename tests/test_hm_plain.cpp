#include "hm_plain.h"
#include <algorithm>
#include <cstring>
#include <gtest/gtest.h>
#include <memory>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <vector>

namespace {

using Context = std::unique_ptr<hm_context_t, decltype(&hm_context_free)>;

Context make_context(size_t bits) {
  hm_context_t *ctx = nullptr;
  EXPECT_EQ(hm_context_create(bits, &ctx), 0);
  return Context(ctx, hm_context_free);
}

Context import_context(size_t bits, const std::vector<uint8_t> &matrix) {
  hm_context_t *ctx = nullptr;
  EXPECT_EQ(hm_context_from_matrix(bits, matrix.data(), matrix.size(), &ctx),
            0);
  return Context(ctx, hm_context_free);
}

size_t bytes_for_bits(size_t bits) { return (bits + 7u) / 8u; }
size_t opening_bits(size_t bits) { return 4u * 256u + 2u * bits + 4u; }
size_t matrix_bits(size_t bits) { return opening_bits(bits) + bits - 1u; }

uint8_t bit_at(const std::vector<uint8_t> &bytes, size_t bit) {
  return (bytes[bit / 8u] >> (bit % 8u)) & 1u;
}

void expect_zero_padding(const std::vector<uint8_t> &bytes, size_t bits) {
  if (bits % 8u) {
    EXPECT_EQ(bytes[bytes_for_bits(bits) - 1u] >> (bits % 8u), 0u);
  }
}

std::vector<uint8_t> make_message(size_t bits) {
  std::vector<uint8_t> message(bytes_for_bits(bits));
  EXPECT_EQ(RAND_bytes(message.data(), static_cast<int>(message.size())), 1);
  return message;
}

} // namespace

TEST(HMPlainTest, MatchesBitwiseToeplitzReference) {
  const size_t bit_lengths[] = {1,  2,  3,   4,   7,   8,   9,  15,
                                16, 17, 30,  31,  32,  33,  34, 63,
                                64, 65, 255, 256, 257, 1024};
  for (size_t bits : bit_lengths) {
    SCOPED_TRACE(bits);
    auto message = make_message(bits);
    hm_commit_sizes_t sizes{};
    ASSERT_EQ(hm_commit_get_sizes(bits, &sizes), 0);
    EXPECT_EQ(sizes.commitment_len, bytes_for_bits(bits) + 32u);
    EXPECT_EQ(sizes.opening_len, bytes_for_bits(opening_bits(bits)));
    EXPECT_EQ(sizes.toeplitz_matrix_len, bytes_for_bits(matrix_bits(bits)));

    auto sender = make_context(bits);
    ASSERT_NE(sender, nullptr);
    std::vector<uint8_t> matrix(sizes.toeplitz_matrix_len);
    ASSERT_EQ(
        hm_context_export_matrix(sender.get(), matrix.data(), matrix.size()),
        0);
    auto receiver = import_context(bits, matrix);
    ASSERT_NE(receiver, nullptr);
    std::vector<uint8_t> roundtrip(matrix.size());
    ASSERT_EQ(hm_context_export_matrix(receiver.get(), roundtrip.data(),
                                       roundtrip.size()),
              0);
    EXPECT_EQ(roundtrip, matrix);
    std::vector<uint8_t> commitment(sizes.commitment_len);
    std::vector<uint8_t> opening(sizes.opening_len);

    // Reuse both contexts, including commit after verify on the sender.
    for (int repeat = 0; repeat < 3; ++repeat) {
      ASSERT_EQ(hm_commit(sender.get(), message.data(), commitment.data(),
                          commitment.size(), opening.data(), opening.size()),
                0);
      for (size_t i = 0; i < bits; ++i) {
        uint8_t expected = bit_at(message, i);
        for (size_t j = 0; j < opening_bits(bits); ++j) {
          expected ^= bit_at(matrix, bits - 1u - i + j) & bit_at(opening, j);
        }
        EXPECT_EQ(bit_at(commitment, i), expected) << "row=" << i;
      }
      uint8_t digest[32];
      ASSERT_NE(SHA256(opening.data(), opening.size(), digest), nullptr);
      EXPECT_EQ(memcmp(commitment.data() + bytes_for_bits(bits), digest, 32),
                0);
      expect_zero_padding(matrix, matrix_bits(bits));
      expect_zero_padding(opening, opening_bits(bits));
      expect_zero_padding(commitment, bits);
      EXPECT_EQ(hm_verify(receiver.get(), message.data(), commitment.data(),
                          commitment.size(), opening.data(), opening.size()),
                0);
      EXPECT_EQ(hm_verify(sender.get(), message.data(), commitment.data(),
                          commitment.size(), opening.data(), opening.size()),
                0);
    }
    // Import owns its matrix: changing the source does not change the receiver.
    matrix.assign(matrix.size(), 0);
    EXPECT_EQ(hm_verify(receiver.get(), message.data(), commitment.data(),
                        commitment.size(), opening.data(), opening.size()),
              0);
    // Unused input message bits do not affect the n-bit message.
    if (bits % 8u) {
      message.back() ^= static_cast<uint8_t>(0xffu << (bits % 8u));
      EXPECT_EQ(hm_verify(receiver.get(), message.data(), commitment.data(),
                          commitment.size(), opening.data(), opening.size()),
                0);
    }
  }
}

TEST(HMPlainTest, RejectsTamperingAndNoncanonicalEncodings) {
  constexpr size_t bits = 33;
  auto message = make_message(bits);
  hm_commit_sizes_t sizes{};
  ASSERT_EQ(hm_commit_get_sizes(bits, &sizes), 0);
  auto sender = make_context(bits);
  ASSERT_NE(sender, nullptr);
  std::vector<uint8_t> matrix(sizes.toeplitz_matrix_len);
  ASSERT_EQ(
      hm_context_export_matrix(sender.get(), matrix.data(), matrix.size()), 0);
  std::vector<uint8_t> commitment(sizes.commitment_len);
  std::vector<uint8_t> opening(sizes.opening_len);
  ASSERT_EQ(hm_commit(sender.get(), message.data(), commitment.data(),
                      commitment.size(), opening.data(), opening.size()),
            0);
  auto verify = [&](const std::vector<uint8_t> &m,
                    const std::vector<uint8_t> &c,
                    const std::vector<uint8_t> &r) {
    return hm_verify(sender.get(), m.data(), c.data(), c.size(), r.data(),
                     r.size());
  };
  auto changed_message = message;
  changed_message[2] ^= 0x04;
  EXPECT_EQ(verify(changed_message, commitment, opening), -1);
  for (size_t offset :
       {size_t{0}, bytes_for_bits(bits), commitment.size() - 1u}) {
    auto changed = commitment;
    changed[offset] ^= 1;
    EXPECT_EQ(verify(message, changed, opening), -1);
  }
  auto changed_opening = opening;
  changed_opening[0] ^= 1;
  EXPECT_EQ(verify(message, commitment, changed_opening), -1);

  auto changed_commitment = commitment;
  changed_commitment[bytes_for_bits(bits) - 1u] |= 0x80;
  EXPECT_EQ(verify(message, changed_commitment, opening), -1);

  // Even a matching digest cannot make an opening outside {0,1}^L valid.
  changed_opening = opening;
  changed_opening.back() |= 0x80;
  changed_commitment = commitment;
  SHA256(changed_opening.data(), changed_opening.size(),
         changed_commitment.data() + bytes_for_bits(bits));
  EXPECT_EQ(verify(message, changed_commitment, changed_opening), -1);

  // Flip a diagonal whose contribution to row zero is known to be one.
  size_t j = 0;
  while (j < opening_bits(bits) && bit_at(opening, j) == 0) {
    ++j;
  }
  ASSERT_LT(j, opening_bits(bits));
  size_t diagonal = bits - 1u + j;
  auto changed_matrix = matrix;
  changed_matrix[diagonal / 8u] ^= static_cast<uint8_t>(1u << (diagonal % 8u));
  auto receiver = import_context(bits, changed_matrix);
  ASSERT_NE(receiver, nullptr);
  EXPECT_EQ(hm_verify(receiver.get(), message.data(), commitment.data(),
                      commitment.size(), opening.data(), opening.size()),
            -1);

  hm_context_t *invalid = nullptr;
  matrix.back() |= 0x80;
  EXPECT_EQ(
      hm_context_from_matrix(bits, matrix.data(), matrix.size(), &invalid), -1);
  EXPECT_EQ(invalid, nullptr);
  EXPECT_EQ(verify(message, commitment, opening), 0);
}

TEST(HMPlainTest, ValidatesDimensionsAndBuffersBeforeWriting) {
  hm_commit_sizes_t sizes{1, 2, 3};
  EXPECT_EQ(hm_commit_get_sizes(0, &sizes), -1);
  EXPECT_EQ(sizes.commitment_len, 0u);
  EXPECT_EQ(sizes.opening_len, 0u);
  EXPECT_EQ(sizes.toeplitz_matrix_len, 0u);
  EXPECT_EQ(hm_commit_get_sizes(SIZE_MAX, &sizes), -1);
  EXPECT_EQ(hm_commit_get_sizes(33, nullptr), -1);
  EXPECT_EQ(hm_commit_get_sizes(10000000, &sizes), 0);
  EXPECT_EQ(hm_commit_get_sizes(10000001, &sizes), -1);
  hm_context_t *invalid = nullptr;
  EXPECT_EQ(hm_context_create(0, &invalid), -1);
  EXPECT_EQ(invalid, nullptr);
  EXPECT_EQ(hm_context_create(SIZE_MAX, &invalid), -1);
  EXPECT_EQ(hm_context_create(33, nullptr), -1);
  hm_context_free(nullptr);

  ASSERT_EQ(hm_commit_get_sizes(33, &sizes), 0);
  auto message = make_message(33);
  auto ctx = make_context(33);
  ASSERT_NE(ctx, nullptr);
  std::vector<uint8_t> matrix(sizes.toeplitz_matrix_len + 2u, 0xcc);
  EXPECT_EQ(hm_context_export_matrix(ctx.get(), matrix.data() + 1u,
                                     sizes.toeplitz_matrix_len - 1u),
            -1);
  EXPECT_TRUE(std::all_of(matrix.begin(), matrix.end(),
                          [](uint8_t v) { return v == 0xcc; }));
  ASSERT_EQ(hm_context_export_matrix(ctx.get(), matrix.data() + 1u,
                                     sizes.toeplitz_matrix_len + 1u),
            0);
  EXPECT_EQ(matrix.front(), 0xcc);
  EXPECT_EQ(matrix.back(), 0xcc);
  EXPECT_EQ(hm_context_export_matrix(nullptr, matrix.data(), matrix.size()),
            -1);
  EXPECT_EQ(hm_context_export_matrix(ctx.get(), nullptr, matrix.size()), -1);
  EXPECT_EQ(
      hm_context_from_matrix(33, nullptr, sizes.toeplitz_matrix_len, &invalid),
      -1);
  EXPECT_EQ(hm_context_from_matrix(33, matrix.data() + 1u,
                                   sizes.toeplitz_matrix_len - 1u, &invalid),
            -1);
  EXPECT_EQ(hm_context_from_matrix(33, matrix.data() + 1u,
                                   sizes.toeplitz_matrix_len + 1u, &invalid),
            -1);
  EXPECT_EQ(hm_context_from_matrix(33, matrix.data() + 1u,
                                   sizes.toeplitz_matrix_len, nullptr),
            -1);

  std::vector<uint8_t> commitment(sizes.commitment_len + 2u, 0xa5);
  std::vector<uint8_t> opening(sizes.opening_len + 2u, 0x5a);
  auto commit = [&](hm_context_t *c, const uint8_t *m, size_t c_len,
                    size_t r_len) {
    return hm_commit(c, m, commitment.data() + 1u, c_len, opening.data() + 1u,
                     r_len);
  };
  EXPECT_EQ(
      commit(nullptr, message.data(), sizes.commitment_len, sizes.opening_len),
      -1);
  EXPECT_EQ(commit(ctx.get(), nullptr, sizes.commitment_len, sizes.opening_len),
            -1);
  EXPECT_EQ(commit(ctx.get(), message.data(), sizes.commitment_len - 1u,
                   sizes.opening_len),
            -1);
  EXPECT_EQ(commit(ctx.get(), message.data(), sizes.commitment_len,
                   sizes.opening_len - 1u),
            -1);
  EXPECT_EQ(hm_commit(ctx.get(), message.data(), nullptr, sizes.commitment_len,
                      opening.data(), sizes.opening_len),
            -1);
  EXPECT_EQ(hm_commit(ctx.get(), message.data(), commitment.data(),
                      sizes.commitment_len, nullptr, sizes.opening_len),
            -1);
  EXPECT_TRUE(std::all_of(commitment.begin(), commitment.end(),
                          [](uint8_t v) { return v == 0xa5; }));
  EXPECT_TRUE(std::all_of(opening.begin(), opening.end(),
                          [](uint8_t v) { return v == 0x5a; }));
  ASSERT_EQ(commit(ctx.get(), message.data(), sizes.commitment_len + 1u,
                   sizes.opening_len + 1u),
            0);
  EXPECT_EQ(commitment.front(), 0xa5);
  EXPECT_EQ(commitment.back(), 0xa5);
  EXPECT_EQ(opening.front(), 0x5a);
  EXPECT_EQ(opening.back(), 0x5a);

  auto verify = [&](hm_context_t *c, const uint8_t *m, size_t c_len,
                    size_t r_len) {
    return hm_verify(c, m, commitment.data() + 1u, c_len, opening.data() + 1u,
                     r_len);
  };
  EXPECT_EQ(
      verify(nullptr, message.data(), sizes.commitment_len, sizes.opening_len),
      -1);
  EXPECT_EQ(verify(ctx.get(), nullptr, sizes.commitment_len, sizes.opening_len),
            -1);
  for (size_t len : {sizes.commitment_len - 1u, sizes.commitment_len + 1u}) {
    EXPECT_EQ(verify(ctx.get(), message.data(), len, sizes.opening_len), -1);
  }
  for (size_t len : {sizes.opening_len - 1u, sizes.opening_len + 1u}) {
    EXPECT_EQ(verify(ctx.get(), message.data(), sizes.commitment_len, len), -1);
  }
  EXPECT_EQ(verify(ctx.get(), message.data(), sizes.commitment_len,
                   sizes.opening_len),
            0);
}

TEST(HMPlainTest, SupportsContiguousBatchBuffers) {
  constexpr size_t bits = 33;
  constexpr size_t count = 64;
  hm_commit_sizes_t sizes{};
  ASSERT_EQ(hm_commit_get_sizes(bits, &sizes), 0);
  std::vector<uint8_t> messages(count * bytes_for_bits(bits));
  ASSERT_EQ(RAND_bytes(messages.data(), static_cast<int>(messages.size())), 1);
  // Include equal messages committed under the same public matrix.
  memcpy(messages.data() + bytes_for_bits(bits), messages.data(),
         bytes_for_bits(bits));
  auto sender = make_context(bits);
  ASSERT_NE(sender, nullptr);
  std::vector<uint8_t> matrix(sizes.toeplitz_matrix_len);
  ASSERT_EQ(
      hm_context_export_matrix(sender.get(), matrix.data(), matrix.size()), 0);
  auto receiver = import_context(bits, matrix);
  ASSERT_NE(receiver, nullptr);
  std::vector<uint8_t> commitments(count * sizes.commitment_len);
  std::vector<uint8_t> openings(count * sizes.opening_len);
  for (size_t i = 0; i < count; ++i) {
    ASSERT_EQ(
        hm_commit(sender.get(), messages.data() + i * bytes_for_bits(bits),
                  commitments.data() + i * sizes.commitment_len,
                  sizes.commitment_len, openings.data() + i * sizes.opening_len,
                  sizes.opening_len),
        0);
  }
  EXPECT_NE(memcmp(openings.data(), openings.data() + sizes.opening_len,
                   sizes.opening_len),
            0);
  for (size_t i = 0; i < count; ++i) {
    EXPECT_EQ(
        hm_verify(receiver.get(), messages.data() + i * bytes_for_bits(bits),
                  commitments.data() + i * sizes.commitment_len,
                  sizes.commitment_len, openings.data() + i * sizes.opening_len,
                  sizes.opening_len),
        0)
        << i;
  }
  std::vector<uint8_t> after(matrix.size());
  ASSERT_EQ(hm_context_export_matrix(sender.get(), after.data(), after.size()),
            0);
  EXPECT_EQ(after, matrix);
}

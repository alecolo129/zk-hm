#include "hm.h"

#include <bitset>
#include <cstdint>
#include <cstdio>
#include <iostream>
#include <vector>

int main() {
  // commit to msg 0b11 (little-endian)
  const uint8_t message = 0x03;
  const std::size_t message_bit_len = 2;

  hm_commit_sizes_t sizes{};
  if (hm_commit_get_sizes(message_bit_len, &sizes) != 0) {
    std::cerr << "hm_commit_get_sizes failed\n";
    return 1;
  }

  std::vector<uint8_t> toeplitz_matrix(sizes.toeplitz_matrix_len);
  std::vector<uint8_t> commitment(sizes.commitment_len);
  std::vector<uint8_t> opening(sizes.opening_len);

  if (hm_pick_universal_hash(message_bit_len, toeplitz_matrix.data(),
                             toeplitz_matrix.size()) != 0) {
    std::cerr << "hm_pick_universal_hash failed\n";
    return 1;
  }

  if (hm_commit(toeplitz_matrix.data(), toeplitz_matrix.size(), &message,
                message_bit_len, commitment.data(), commitment.size(),
                opening.data(), opening.size()) != 0) {
    std::cerr << "hm_commit failed\n";
    return 1;
  }

  std::cout << "Committed to msg " << std::bitset<2>(message) << '\n';
  std::cout << "commitment: " << sizes.commitment_len << " bytes\n";
  std::cout << "opening: " << sizes.opening_len << " bytes\n";

  if (hm_verify(toeplitz_matrix.data(), toeplitz_matrix.size(), &message,
                message_bit_len, commitment.data(), sizes.commitment_len,
                opening.data(), sizes.opening_len) != 0) {
    std::cerr << "hm_verify failed\n";
    return 1;
  }

  std::cout << "Proof verified successfully\n";
  return 0;
}

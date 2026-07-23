#include "hm.h"

#include <bitset>
#include <cstdint>
#include <cstdio>
#include <iostream>
#include <vector>

int main() {
  // commit to msg 0b11 (little-endian)
  const uint8_t msg = 0x03;
  const std::size_t msg_bit_len = 2;

  hm_commit_sizes_t sizes{};
  if (hm_commit_get_sizes(msg_bit_len, &sizes) != 0) {
    std::cerr << "hm_commit_get_sizes failed\n";
    return 1;
  }

  std::vector<uint8_t> commitment(sizes.commitment_len);
  std::vector<uint8_t> opening(sizes.opening_len);

  if (hm_commit(&msg, msg_bit_len, commitment.data(), commitment.size(),
                opening.data(), opening.size()) != 0) {
    std::cerr << "hm_commit failed\n";
    return 1;
  }

  std::cout << "Committed to msg " << std::bitset<2>(msg) << '\n';
  std::cout << "commitment: " << sizes.commitment_len << " bytes\n";
  std::cout << "opening: " << sizes.opening_len << " bytes\n";

  if (hm_verify(&msg, msg_bit_len, commitment.data(), sizes.commitment_len,
                opening.data(), sizes.opening_len) != 0) {
    std::cerr << "hm_verify failed\n";
    return 1;
  }

  std::cout << "Proof verified successfully\n";
  return 0;
}

#include "hm.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <vector>

int main() {
  constexpr std::size_t commitment_count = 100;
  constexpr std::size_t message_bit_len = 2;

  std::array<uint8_t, commitment_count> messages{};
  for (std::size_t i = 0; i < messages.size(); ++i) {
    messages[i] = static_cast<uint8_t>(i & 0x03u);
  }

  hm_commit_sizes_t sizes{};
  if (hm_commit_get_sizes(message_bit_len, &sizes) != 0) {
    std::cerr << "hm_commit_get_sizes failed\n";
    return 1;
  }

  std::vector<uint8_t> commitments(commitment_count * sizes.commitment_len);
  std::vector<uint8_t> openings(commitment_count * sizes.opening_len);

  for (std::size_t i = 0; i < commitment_count; ++i) {
    uint8_t *commitment = commitments.data() + i * sizes.commitment_len;
    uint8_t *opening = openings.data() + i * sizes.opening_len;

    if (hm_commit(&messages[i], message_bit_len, commitment,
                  sizes.commitment_len, opening, sizes.opening_len) != 0) {
      std::cerr << "hm_commit failed at index " << i << '\n';
      return 1;
    }
  }

  for (std::size_t i = 0; i < commitment_count; ++i) {
    const uint8_t *commitment = commitments.data() + i * sizes.commitment_len;
    const uint8_t *opening = openings.data() + i * sizes.opening_len;

    if (hm_verify(&messages[i], message_bit_len, commitment,
                  sizes.commitment_len, opening, sizes.opening_len) != 0) {
      std::cerr << "hm_verify failed at index " << i << '\n';
      return 1;
    }
  }

  std::cout << "Created and verified " << commitment_count
            << " 2-bit commitments\n";
  std::cout << "commitments: " << commitments.size() << " bytes\n";
  std::cout << "openings: " << openings.size() << " bytes\n";
  return 0;
}

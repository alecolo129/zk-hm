#include "hm.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <memory>
#include <vector>

int main() {
  constexpr std::size_t message_bit_len = 2;
  constexpr std::size_t count = 1;
  const std::array<uint8_t, count> messages{0x03}; // Two bits, LSB-first.
  hm_commit_sizes_t sizes{};
  if (hm_commit_get_sizes(message_bit_len, &sizes) != 0) {
    std::cerr << "invalid message length\n";
    return 1;
  }
  std::vector<uint8_t> matrix(sizes.toeplitz_matrix_len);
  std::vector<uint8_t> commitments(count * sizes.commitment_len);
  std::vector<uint8_t> openings(count * sizes.opening_len);

  using Context = std::unique_ptr<hm_context_t, decltype(&hm_context_free)>;
  hm_context_t *raw = nullptr;
  if (hm_context_create(message_bit_len, &raw) != 0) {
    std::cerr << "context creation failed\n";
    return 1;
  }
  Context sender(raw, hm_context_free);
  for (std::size_t i = 0; i < count; ++i) {
    if (hm_commit(sender.get(), &messages[i],
                  commitments.data() + i * sizes.commitment_len,
                  sizes.commitment_len, openings.data() + i * sizes.opening_len,
                  sizes.opening_len) != 0) {
      std::cerr << "commit failed at index " << i << '\n';
      return 1;
    }
  }

  // Send one matrix with the batch, then open each coordinate independently.
  if (hm_context_export_matrix(sender.get(), matrix.data(), matrix.size()) !=
          0 ||
      hm_context_from_matrix(message_bit_len, matrix.data(), matrix.size(),
                             &raw) != 0) {
    std::cerr << "matrix transfer failed\n";
    return 1;
  }
  Context receiver(raw, hm_context_free);
  for (std::size_t i = 0; i < count; ++i) {
    if (hm_verify(receiver.get(), &messages[i],
                  commitments.data() + i * sizes.commitment_len,
                  sizes.commitment_len, openings.data() + i * sizes.opening_len,
                  sizes.opening_len) != 0) {
      std::cerr << "verification failed at index " << i << '\n';
      return 1;
    }
  }
  std::cout << "Created and verified " << count << " two-bit commitments\n";
  std::cout << "shared matrix: " << matrix.size() << " bytes\n";
  std::cout << "commitments: " << commitments.size() << " bytes\n";
  std::cout << "openings: " << openings.size() << " bytes\n";
  return 0;
}

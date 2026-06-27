#include "hm.h"

#include <cstdint>
#include <cstdio>
#include <iostream>

class HmBuffer {
public:
  HmBuffer() = default;
  HmBuffer(const HmBuffer &) = delete;
  HmBuffer &operator=(const HmBuffer &) = delete;

  HmBuffer(HmBuffer &&other) noexcept : buf_(other.buf_) {
    other.buf_ = {};
  }

  HmBuffer &operator=(HmBuffer &&other) noexcept {
    if (this != &other) {
      hm_buffer_free(&buf_);
      buf_ = other.buf_;
      other.buf_ = {};
    }
    return *this;
  }

  ~HmBuffer() {
    hm_buffer_free(&buf_);
  }

  hm_buffer_t *out() {
    return &buf_;
  }

  const uint8_t *data() const {
    return buf_.data;
  }

  std::size_t size() const {
    return buf_.len;
  }

private:
  hm_buffer_t buf_{};
};

int main() {
  constexpr uint8_t bit = 1;
  constexpr const char *proof_path = "hm_cpp_example_proof.bin";

  HmBuffer commitment;
  HmBuffer opening;

  if (hm_bit_commit(bit, proof_path, commitment.out(), opening.out()) != 0) {
    std::cerr << "hm_bit_commit failed\n";
    std::remove(proof_path);
    return 1;
  }

  std::cout << "Committed to bit " << static_cast<unsigned>(bit) << '\n';
  std::cout << "commitment: " << commitment.size() << " bytes\n";
  std::cout << "opening: " << opening.size() << " bytes\n";

  if (hm_bit_verify(commitment.data(), commitment.size(), proof_path) != 0) {
    std::cerr << "hm_bit_verify failed\n";
    std::remove(proof_path);
    return 1;
  }

  if (hm_bit_open(bit, commitment.data(), commitment.size(), opening.data(),
                  opening.size()) != 0) {
    std::cerr << "hm_bit_open failed\n";
    std::remove(proof_path);
    return 1;
  }

  std::cout << "Proof verified and commitment opened successfully\n";
  std::remove(proof_path);
  return 0;
}

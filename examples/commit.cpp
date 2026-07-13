#include "hm.h"

#include <bitset>
#include <cstdint>
#include <cstdio>
#include <iostream>

class HmBuffer {
public:
  HmBuffer() = default;
  HmBuffer(const HmBuffer &) = delete;
  HmBuffer &operator=(const HmBuffer &) = delete;

  HmBuffer(HmBuffer &&other) noexcept : buf_(other.buf_) { other.buf_ = {}; }

  HmBuffer &operator=(HmBuffer &&other) noexcept {
    if (this != &other) {
      hm_buffer_free(&buf_);
      buf_ = other.buf_;
      other.buf_ = {};
    }
    return *this;
  }

  ~HmBuffer() { hm_buffer_free(&buf_); }

  hm_buffer_t *out() { return &buf_; }

  const uint8_t *data() const { return buf_.data; }

  std::size_t size() const { return buf_.len; }

private:
  hm_buffer_t buf_{};
};

int main() {
  // commit to msg 0b11 (little-endian)
  const uint8_t msg = 0x03;
  const ssize_t msg_bit_len = 2;

  HmBuffer commitment;
  HmBuffer opening;

  if (hm_commit(&msg, msg_bit_len, commitment.out(), opening.out()) != 0) {
    std::cerr << "hm_commit failed\n";
    return 1;
  }

  std::cout << "Committed to msg " << std::bitset<2>(msg) << '\n';
  std::cout << "commitment: " << commitment.size() << " bytes\n";
  std::cout << "opening: " << opening.size() << " bytes\n";

  if (hm_verify(&msg, msg_bit_len, commitment.data(), commitment.size(),
                opening.data(), opening.size()) != 0) {
    std::cerr << "hm_verify failed\n";
    return 1;
  }

  std::cout << "Proof verified successfully\n";
  return 0;
}

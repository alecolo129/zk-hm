#include "toeplitz_internal.h"
#include <gtest/gtest.h>

TEST(ToeplitzTest, WindowsMatchBitwiseReferenceAtEveryShift) {
  const uint32_t words[] = {0x89abcdefu, 0x01234567u, 0xfedcba98u, 0x76543210u,
                            0u};
  for (size_t base = 0; base < 4; ++base) {
    for (size_t shift = 0; shift < 32; ++shift) {
      uint32_t expected = 0;
      for (size_t bit = 0; bit < 32; ++bit) {
        size_t offset = base * 32 + shift + bit;
        uint32_t value = (words[offset / 32] >> (offset % 32)) & 1u;
        expected |= value << bit;
      }
      EXPECT_EQ(toeplitz_load_window32(words, base, shift), expected)
          << "base=" << base << " shift=" << shift;
    }
  }
}

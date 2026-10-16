#pragma once
#include <stddef.h>
#include <stdint.h>

/* Load a 32-bit window from padded diagonal words. The caller supplies a
 * readable lookahead word at idx + 1 and a shift in the range 0..31. */
static inline uint32_t toeplitz_load_window32(const uint32_t *A, size_t idx,
                                              size_t rShift) {
  // Build 64 bits: [A[idx+1] | A[idx]] and shift right by rShift
  // Works for rShift == 0..31 safely.
  uint64_t lane = ((uint64_t)A[idx + 1] << 32) | A[idx];
  return (uint32_t)(lane >> rShift);
}

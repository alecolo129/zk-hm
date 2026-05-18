#include "MPC_universal_hash.h"
#include "MPC_arithmetic.h"
#include "shared.h"
#include "stdbool.h"
#include <stdint.h>
#include <stdio.h>

static inline void mpc_parity(uint32_t x[3], uint32_t z[3]) {
  z[0] = __builtin_parity(x[0]);
  z[1] = __builtin_parity(x[1]);
  z[2] = __builtin_parity(x[2]);
}

static inline void mpc_parity2(uint32_t x[2], uint32_t z[2]) {
  z[0] = __builtin_parity(x[0]);
  z[1] = __builtin_parity(x[1]);
}

static inline void mpc_ANDK(const uint32_t x[3], const uint32_t y,
                            uint32_t z[3]) {
  z[0] = x[0] & y;
  z[1] = x[1] & y;
  z[2] = x[2] & y;
}

static inline void mpc_ANDK2(const uint32_t x[2], const uint32_t y,
                             uint32_t z[2]) {
  z[0] = x[0] & y;
  z[1] = x[1] & y;
}

static inline void mpc_XORK(const uint32_t x[3], const uint32_t y,
                            uint32_t z[3]) {
  z[0] = x[0] ^ y;
}

static inline void mpc_XORK2(const uint32_t x[2], const uint32_t y,
                             uint32_t z[2]) {
  z[0] = x[0] ^ y;
}

static inline void mpc_XOR2_const(uint32_t x[2], const uint32_t y[2],
                                  uint32_t z[2]) {
  z[0] = x[0] ^ y[0];
  z[1] = x[1] ^ y[1];
}

void expand_A(uint32_t A[A_WORDS], const uint8_t keyA[16]) {
  EVP_CIPHER_CTX *ctx = setupAES(keyA);

  uint8_t *bytesA = (uint8_t *)A;
  const uint8_t zero[4096] = {0};
  size_t outBytesLen = A_BYTES;
  while (outBytesLen) {
    int chunk =
        (outBytesLen > sizeof(zero)) ? (int)sizeof(zero) : (int)outBytesLen;
    int produced = 0;
    if (1 != EVP_EncryptUpdate(ctx, bytesA, &produced, zero, chunk)) {
      handleErrors();
    }
    bytesA += produced;
    outBytesLen -= (size_t)produced;
  }
  A[A_WORDS - 1] = 0; // Set padding word to 0
  EVP_CIPHER_CTX_free(ctx);
}

static inline uint32_t load_window32(const uint32_t *A, int idx,
                                     uint32_t rShift) {
  // Build 64 bits: [A[idx+1] | A[idx]] and shift right by rShift
  // Works for rShift == 0..31 safely.
  uint64_t lane = ((uint64_t)A[idx + 1] << 32) | A[idx];
  return (uint32_t)(lane >> rShift);
}

void generate_H(uint32_t A[A_WORDS], uint8_t b[MSG_BYTES],
                const uint8_t keyH[16], const uint8_t m[MSG_BYTES],
                const uint32_t r[L_WORDS]) {
  expand_A(A, keyH);
  for (int i = 0; i < MSG_BITS; i++) {
    uint32_t rShift = i % 32;
    uint32_t base = i / 32;

    // b[i] = A[i..i+L) * r[0..L) - m[i]
    uint32_t acc = 0;
    for (int j = 0; j < L_WORDS; j++) {
      acc ^= load_window32(A, base + j, rShift) & r[j];
    }
    uint32_t bi = __builtin_parity(acc);
    bi ^= GETBIT(m[i / 8], i % 8);
    SETBIT(b[i / 8], i % 8, bi);
  }
}

void mpc_inner_prod_prover(const UniversalHash *h, const uint32_t m[3],
                           const uint32_t r[L_WORDS][3], uint32_t y[3]) {
  uint32_t t1[3] = {0};
  memset(y, 0, 3 * sizeof(uint32_t));
  for (int i = 0; i < L_WORDS; i++) {
    mpc_ANDK(r[i], h->A[i], t1);
    mpc_XOR(y, t1, y);
  }
  mpc_parity(y, y);
  mpc_XOR((uint32_t *)m, y, y);
}
bool mpc_inner_prod_verify(const UniversalHash *h, const uint32_t m[2],
                           const uint32_t r[L_WORDS][2], const uint32_t y[3],
                           const uint32_t e) {
  uint32_t y_rec[2] = {0};
  uint32_t t1[2];
  for (int i = 0; i < L_WORDS; i++) {
    mpc_ANDK2(r[i], h->A[i], t1);
    mpc_XOR2_const(y_rec, t1, y_rec);
  }
  mpc_parity2(y_rec, y_rec);
  mpc_XOR2_const(y_rec, m, y_rec);
  if (y[e] != y_rec[0] || y[(e + 1) % 3] != y_rec[1]) {
    printf("Failed at line %d\n", __LINE__);
    return false;
  }
  mpc_XORK2(y_rec, h->b[0], y_rec);

  return y_rec[0] ^ y_rec[1] ^ y[(e + 2) % 3] == 0;
}

void mpc_universal_hash_prover(const UniversalHash *h,
                               const uint32_t m[MSG_WORDS][3],
                               const uint32_t r[L_WORDS][3],
                               uint32_t y[MSG_WORDS][3]) {
  memset(y, 0, 3 * MSG_WORDS * sizeof(uint32_t));
  for (int i = 0; i < MSG_BITS; i++) {
    uint32_t yi[3] = {0};
    uint32_t t1[3] = {0};
    uint32_t wordIdx = i / 32;
    uint32_t bitIdx = i % 32;

    for (int j = 0; j < L_WORDS; j++) {
      uint32_t A_ij = load_window32(h->A, wordIdx + j, bitIdx);
      mpc_ANDK(r[j], A_ij, t1);
      mpc_XOR(yi, t1, yi);
    }
    mpc_parity(yi, yi);

    uint32_t mi[3];
    mpc_GETBIT(mi, m[wordIdx], bitIdx);

    mpc_XOR(mi, yi, yi);

    mpc_SETBIT(y[wordIdx], yi, bitIdx);
  }
}

bool mpc_universal_hash_verifier(const UniversalHash *h,
                                 const uint32_t m[MSG_WORDS][2],
                                 const uint32_t r[L_WORDS][2],
                                 const uint32_t y[MSG_WORDS][3],
                                 const uint32_t e) {

  for (int i = 0; i < MSG_BITS; i++) {
    uint32_t y_rec[2] = {0};
    uint32_t t1[2];
    uint32_t wordIdx = i / 32;
    uint32_t bitIdx = i % 32;

    /* y_rec = A[i] * r */
    for (int j = 0; j < L_WORDS; j++) {
      uint32_t A_ij = load_window32(h->A, wordIdx + j, bitIdx);
      mpc_ANDK2(r[j], A_ij, t1);
      mpc_XOR2_const(y_rec, t1, y_rec);
    }
    mpc_parity2(y_rec, y_rec);

    uint32_t mi[2] = {GETBIT(m[wordIdx][0], bitIdx),
                      GETBIT(m[wordIdx][1], bitIdx)};
    uint32_t yi[3] = {GETBIT(y[wordIdx][0], bitIdx),
                      GETBIT(y[wordIdx][1], bitIdx),
                      GETBIT(y[wordIdx][2], bitIdx)};
    uint32_t bi = GETBIT(h->b[i / 8], i % 8);

    /* y_rec = (A[i] * r) ^ b[i] ^ m[i] */
    mpc_XOR2_const(y_rec, mi, y_rec);

    /*
    check y_rec is consistent with the opened shares of commitment to 0
    */
    if (yi[e] != y_rec[0] || yi[(e + 1) % 3] != y_rec[1]) {
      LOG_ERRF("mismatch between committed and reconsturcted bit %d!\n", i);
      return false;
    }

    if ((y_rec[0] ^ y_rec[1] ^ yi[(e + 2) % 3] ^ bi) != 0) {
      LOG_ERRF("result %d != 0!\n", y_rec[0] ^ y_rec[1] ^ yi[(e + 2) % 3] ^ bi);
      return false;
    }
  }
  return true;
}
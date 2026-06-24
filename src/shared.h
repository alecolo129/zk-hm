#pragma once
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdint.h>

#ifdef VERBOSE
#define LOG_ERRF(fmt, ...)                                                     \
  do {                                                                         \
    flockfile(stderr);                                                         \
    fprintf(stderr, "%s:%d:%s(): " fmt "\n", __FILE_NAME__, __LINE__,          \
            __func__, ##__VA_ARGS__);                                          \
    fflush(stderr);                                                            \
    funlockfile(stderr);                                                       \
  } while (0)
#else
#define LOG_ERRF(fmt, ...)
#endif

// Security parameters

/* Number of repetition to achieve desired soundness error.
 * With 136 round, soundness error = 2^{-80}*/
#define NUM_ROUNDS 136

/* Number of bits of the comitted message. */
#define MSG_BITS 1u
#define MSG_WORDS ((MSG_BITS + 31) / 32)
#define MSG_BYTES ((MSG_BITS + 7) / 8)

/* Bindness security parameter, we have k/2 of collision resistance.
 * Note: For bit commitments, we save 1 SHA block if we accept k=238 (i.e., 119
 * bits of collision resistance).
 */
#define K 256

/* Required length of the Halevi-Micali random vector 'r' (i.e., the opening). */
#define L_BITS ((((4 * K + 2 * MSG_BITS + 4) + 31) / 32) * 32) // word -alligned
#define L_BYTES (L_BITS / 8)
#define L_WORDS ((L_BYTES + 3) / 4)

/* Required number of SHA256 blocks to hash the committed vector 'r'. */
#define NUM_SHA256_BLOCKS                                                      \
  ((L_BITS + 1 + 64 + 511) / 512) // ceil((L + 1 + 54) / 512)

/* Required number of random bytes to proof knowledge of the committed message.
 * Note: for each SHA256 block we need 2912 bytes of randomness */
#define RAND_BYTES (2912 * NUM_SHA256_BLOCKS)
/* Size of the circuit output in 32-bit words.
 * We need 'RAND_BYTES/4' words to store all the AND/ADD openings + 8 words to
 * store the SHA256 output. */
#define ySize (RAND_BYTES / 4 + 8)

#define A_ROWS ((MSG_BITS - 1 + 31) / 32)
#define A_WORDS (A_ROWS + L_WORDS + 1) // Additional padding word
#define A_BYTES (A_ROWS + L_WORDS + 1) * 4

typedef struct {
  uint8_t keyA[16]; // PRG key used to generate random matrix A
  uint32_t A[A_WORDS]; // Toeplitz matrix
  uint8_t b[MSG_BYTES];
} UniversalHash;

// views
typedef struct {
  unsigned char x[L_BYTES]; // secret input share = SHA256 input
  uint8_t msg[MSG_BYTES];   // share of the committed message
  uint32_t y[ySize]; // output share (i.e., all the ADD/AND commits + the SHA256
                     // output)
} View;

// TODO: remove
typedef struct {
  unsigned char *x[3];
  uint32_t *y[3];
} ViewsPtr;

// commitment
typedef struct {
  uint32_t yp[3][8]; // SHA256 output of each party (output shares of MD(r))
  uint32_t y2p[MSG_WORDS][3]; // Commitment to zero (output shares of h(r) ^ m
                              // where h is UHF)
  unsigned char h[3][32]; // SHA256 of each party's key and view with commitment
                          // randomnes k
} ZkBooCommit;

// open
typedef struct {
  // keys can be used by verifier to obtain random tapes
  unsigned char ke[16];  // key party i
  unsigned char ke1[16]; // key party i+1
  View *ve;              // view party i
  View *ve1;             // view party i+1
  // randomness used in commitments
  unsigned char re[4];
  unsigned char re1[4];
} ZkBooOpen;

typedef struct {
  unsigned char ke[16];
  unsigned char ke1[16];
  unsigned char re[4];
  unsigned char re1[4];
  View ve;  // embedded bytes
  View ve1; // embedded bytes
} ZkBooOpenDisk;

#define RIGHTROTATE(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define GETBIT(x, i) (((x) >> (i)) & 0x01)
#define SETBIT(x, i, b)                                                        \
  do {                                                                         \
    (x) = ((x) & ~(1u << (i))) | ((b) << (i));                                 \
  } while (0)

static inline void handleErrors(void) {
  ERR_print_errors_fp(stderr);
  abort();
}

/* Helper: write 64-bit big-endian */
static inline void store_u64_be(unsigned char *dst, uint64_t x) {
  dst[0] = (unsigned char)(x >> 56);
  dst[1] = (unsigned char)(x >> 48);
  dst[2] = (unsigned char)(x >> 40);
  dst[3] = (unsigned char)(x >> 32);
  dst[4] = (unsigned char)(x >> 24);
  dst[5] = (unsigned char)(x >> 16);
  dst[6] = (unsigned char)(x >> 8);
  dst[7] = (unsigned char)(x);
}

/* Helper: write 32-bit big-endian */
static inline void load_u32_be(uint32_t *dst, const unsigned char *src) {
  *dst = ((uint32_t)src[0] << 24) | ((uint32_t)src[1] << 16) |
         ((uint32_t)src[2] << 8) | (uint32_t)src[3];
}

/* Helper: write 32-bit big-endian */
static inline void load_u32_le(uint32_t *dst, const unsigned char *src) {
  *dst = ((uint32_t)src[3] << 24) | ((uint32_t)src[2] << 16) |
         ((uint32_t)src[1] << 8) | (uint32_t)src[0];
}

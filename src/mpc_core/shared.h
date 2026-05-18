/*
============================================================================
Name        : shared.h
Author      : Sobuno
Version     : 0.1
Description : Common functions for the SHA-256 prover and verifier
============================================================================
*/

#ifndef SHARED_H_
#define SHARED_H_
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#ifdef _WIN32
#include <openssl/applink.c>
#endif
#include <openssl/rand.h>
#include <stdint.h>
#include <string.h>

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

/* A 128 bit IV for randomness generation */
static const unsigned char iv[17] = "0123456789012345";

static const uint32_t hA[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                               0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

static const uint32_t k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

// Security parameters

/* Number of repetition to achieve desired soundness error.
 * With 136 round, soundness error = 2^{-80}*/
#define NUM_ROUNDS 136
/* Number of bits of the comitted message. */
#define MSG_BITS 100000u
#define MSG_WORDS ((MSG_BITS + 31) / 32)
#define MSG_BYTES ((MSG_BITS + 7) / 8)
/* Bindness security parameter, we have k/2 of collision resistance.
 * Note: For bit commitments, we save 1 SHA block if we accept k=238 (i.e., 119
 * bits of collision resistance).
 */
#define K 256
/* Reuired length of the Halevi-Micali random vector 'r' (i.e., the opening). */
#define L_BITS (4 * K + 2 * MSG_BITS + 4)
#define L_BYTES (L_BITS / 8)
#define L_WORDS (L_BITS / 32)
/* Reuired number of SHA256 blocks to hash the committed vector 'r'. */
#define NUM_SHA256_BLOCKS                                                      \
  ((L_BITS + 1 + 64 + 511) / 512) // ceil((L + 1 + 54) / 512)
/* Reuired number of random bytes to proof knowledge of the committed message.
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

// commitment
typedef struct {
  uint32_t yp[3][8]; // SHA256 output of each party
  uint32_t y2p[MSG_WORDS][3];
  unsigned char h[3][32]; // SHA256 of each party's key and view with commitment
                          // randomnes k
} a;

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
} z;

typedef struct {
  unsigned char ke[16];
  unsigned char ke1[16];
  unsigned char re[4];
  unsigned char re1[4];
  View ve;  // embedded bytes
  View ve1; // embedded bytes
} z_disk;

// TODO: This part needs to be updated
// ---- pre-image equality => prove m : c1 = SHA256(m,r) & c2 = SHA256(m, r')
// for some randomness r,r'

#define y2Size L_WORDS // TODO: this is outdated

// views
typedef struct {
  unsigned char x[64];  // secret input share = SHA256 input chunk (padded and
                        // pre-processed)
  uint32_t y[2][ySize]; // output share (i.e., all the ADD/AND commits + the
                        // SHA256 output)
} View2;

// commitment
typedef struct {
  uint32_t yp[2][3][8];   // SHA256 output of each party
  unsigned char h[3][32]; // SHA256 of each party's key and view with commitment
                          // randomnes k
} a2;

// open
// TODO: key and randomness should be different per each commit
typedef struct {
  // keys can be used by verifier to obtain random tapes
  unsigned char ke[16];  // key party i
  unsigned char ke1[16]; // key party i+1
  View2 ve;              // view party i
  View2 ve1;             // view party i+1
  // randomness used in commitments
  unsigned char re[4];
  unsigned char re1[4];
} z2;

typedef struct {
  unsigned char *x[3];
  uint32_t *y[3];
} ViewsPtr;

typedef struct {
  uint32_t *yp[3][8];      // SHA256 output of each party
  unsigned char hà[3][32]; // SHA256 of each party's key and view with
                           // commitment randomnes k
} aPtr;

#define RIGHTROTATE(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define GETBIT(x, i) (((x) >> (i)) & 0x01)
#define SETBIT(x, i, b)                                                        \
  do {                                                                         \
    (x) = ((x) & ~(1 << (i))) | ((b) << (i));                                  \
  } while (0)

void handleErrors(void);

EVP_CIPHER_CTX *setupAES(const unsigned char key[16]);

void getAllRandomness(unsigned char key[16],
                      unsigned char randomness[RAND_BYTES]);
void getAllRandomness2(unsigned char key[16], unsigned char *randomness,
                       int randSize);

uint32_t getRandom32(unsigned char randomness[RAND_BYTES], int randCount);

void init_EVP();

void cleanup_EVP();

// Hash
EVP_MD_CTX *setupSHA256();

void MD(const unsigned char *r, uint32_t r_len,
        unsigned char hash[SHA256_DIGEST_LENGTH]);
void H(unsigned char k[16], View *v, unsigned char r[4],
       unsigned char hash[SHA256_DIGEST_LENGTH]);
void HH(EVP_MD_CTX *ctx, unsigned char k[16], View *v, unsigned char r[4],
        unsigned char hash[SHA256_DIGEST_LENGTH]);
void H2(unsigned char k[16], View2 v, unsigned char r[4],
        unsigned char hash[SHA256_DIGEST_LENGTH]);

void H3(EVP_MD_CTX *ctx, uint32_t y[8], a *as, int s, int *es);
void H3_2(uint32_t y[8], a2 *as, int s, int *es);

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

static inline void output2(View2 v[3], a2 *a) {
  for (int c = 0; c < 2; c++) {
    memcpy(a->yp[c][0], &v[0].y[c][ySize - 8], 32);
    memcpy(a->yp[c][1], &v[1].y[c][ySize - 8], 32);
    memcpy(a->yp[c][2], &v[2].y[c][ySize - 8], 32);
  }
}

static inline void output(View *v, uint32_t *result) {
  memcpy(result, &v->y[ySize - 8], 32);
}

static inline void reconstruct(uint32_t *y0, uint32_t *y1, uint32_t *y2,
                               uint32_t *result) {
  for (int i = 0; i < 8; i++) {
    result[i] = y0[i] ^ y1[i] ^ y2[i];
  }
}

void openmp_locking_callback(int mode, int type, char *file, int line);

unsigned long openmp_thread_id(void);

void openmp_thread_setup(void);

void openmp_thread_cleanup(void);

#endif /* SHARED_H_ */

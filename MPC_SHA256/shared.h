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
#include "omp.h"
#include <openssl/rand.h>
#include <stdint.h>
#include <string.h>

#define VERBOSE FALSE

static const int NUM_ROUNDS = 136;

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

#define ySize 736

// views
typedef struct {
  unsigned char x[64]; // secret input share = SHA256 input chunk (padded and
                       // pre-processed)
  uint32_t y[ySize]; // output share (i.e., all the ADD/AND commits + the SHA256
                     // output)
} View;

// commitment
typedef struct {
  uint32_t yp[3][8];      // SHA256 output of each party
  unsigned char h[3][32]; // SHA256 of each party's key and view with commitment
                          // randomnes k
} a;

// open
typedef struct {
  // keys can be used by verifier to obtain random tapes
  unsigned char ke[16];  // key party i
  unsigned char ke1[16]; // key party i+1
  View ve;               // view party i
  View ve1;              // view party i+1
  // randomness used in commitments
  unsigned char re[4];
  unsigned char re1[4];
} z;

// ---- pre-image equality => prove m : c1 = SHA256(m,r) & c2 = SHA256(m, r')
// for some randomness r,r'

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
#define SETBIT(x, i, b) x = (b) & 1 ? (x) | (1 << (i)) : (x) & (~(1 << (i)))

void handleErrors(void);

EVP_CIPHER_CTX setupAES(unsigned char key[16]);

void getAllRandomness(unsigned char key[16], unsigned char randomness[2912]);

uint32_t getRandom32(unsigned char randomness[2912], int randCount);

void init_EVP();

void cleanup_EVP();

// Hash

void H(unsigned char k[16], View v, unsigned char r[4],
       unsigned char hash[SHA256_DIGEST_LENGTH]);
void H2(unsigned char k[16], View2 v, unsigned char r[4],
        unsigned char hash[SHA256_DIGEST_LENGTH]);

void H3(uint32_t y[8], a *as, int s, int *es);
void H3_2(uint32_t y[8], a2 *as, int s, int *es);

inline void output2(View2 v[3], a2 *a) {
  for (int c = 0; c < 2; c++) {
    memcpy(a->yp[c][0], &v[0].y[c][ySize - 8], 32);
    memcpy(a->yp[c][1], &v[1].y[c][ySize - 8], 32);
    memcpy(a->yp[c][2], &v[2].y[c][ySize - 8], 32);
  }
}

inline void output(View v, uint32_t *result) {
  memcpy(result, &v.y[ySize - 8], 32);
}

inline void reconstruct(uint32_t *y0, uint32_t *y1, uint32_t *y2,
                        uint32_t *result) {
  for (int i = 0; i < 8; i++) {
    result[i] = y0[i] ^ y1[i] ^ y2[i];
  }
}

inline void mpc_XOR2(uint32_t x[2], uint32_t y[2], uint32_t z[2]) {
  z[0] = x[0] ^ y[0];
  z[1] = x[1] ^ y[1];
}

inline void mpc_NEGATE2(uint32_t x[2], uint32_t z[2]) {
  z[0] = ~x[0];
  z[1] = ~x[1];
}

void openmp_locking_callback(int mode, int type, char *file, int line);

unsigned long openmp_thread_id(void);

void openmp_thread_setup(void);

void openmp_thread_cleanup(void);

#endif /* SHARED_H_ */

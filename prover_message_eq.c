#include "MPC_SHA256.h"
#include "shared.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static int totalCrypto = 0;
static int totalRandom = 0;
static int totalSha = 0;
static int totalSS = 0;
static int totalHash = 0;

static int inMilliA = 0;
static int inMilliE = 0;
static int inMilliZ = 0;
static int inMilliWrite = 0;
static int inMilli = 0;

void init() {
  setbuf(stdout, NULL);
  srand((unsigned)time(NULL));
  openmp_thread_setup();
}

void cleanup() { openmp_thread_cleanup(); }

inline void update_clock(clock_t beginClock, int *clockToUpdate) {
  clock_t deltaT = clock() - beginClock;
  int inMilli = deltaT * 1000 / CLOCKS_PER_SEC;
  *clockToUpdate += inMilli;
}

void print_runtime(const char *outputFile) {

  int sumOfParts = 0;

  printf("Generating A: %ju\n", (uintmax_t)inMilliA);
  printf("	Generating keys: %ju\n", (uintmax_t)totalCrypto);
  sumOfParts += totalCrypto;
  printf("	Generating randomness: %ju\n", (uintmax_t)totalRandom);
  sumOfParts += totalRandom;
  printf("	Sharing secrets: %ju\n", (uintmax_t)totalSS);
  sumOfParts += totalSS;
  printf("	Running MPC-SHA2: %ju\n", (uintmax_t)totalSha);
  sumOfParts += totalSha;
  printf("	Committing: %ju\n", (uintmax_t)totalHash);
  sumOfParts += totalHash;
  printf("	*Accounted for*: %ju\n", (uintmax_t)sumOfParts);
  printf("Generating E: %ju\n", (uintmax_t)inMilliE);
  printf("Packing Z: %ju\n", (uintmax_t)inMilliZ);
  printf("Writing file: %ju\n", (uintmax_t)inMilliWrite);
  printf("Total: %d\n", inMilli);
  printf("\n");
  printf("Proof output to file %s\n", outputFile);
}

// TODO: avoid potential leakages
inline void RAND_bytes_no_fail(unsigned char *buf, int num) {
  if (!RAND_bytes(buf, 1)) {
    printf("RAND_bytes failed crypto, aborting\n");
    exit(1);
  }
}

void generate_keys_and_rs(unsigned char keys[NUM_ROUNDS][3][16],
                          unsigned char rs[NUM_ROUNDS][3][4]) {
  RAND_bytes_no_fail((unsigned char *)keys, NUM_ROUNDS * 3 * 16);
  RAND_bytes_no_fail((unsigned char *)rs, NUM_ROUNDS * 3 * 4);
}

void share_secret(unsigned char shares[NUM_ROUNDS][3][L_BYTES],
                  const unsigned char input[L_BYTES]) {
  if (RAND_bytes((unsigned char *)shares, NUM_ROUNDS * 3 * L_BYTES) != 1) {
    printf("RAND_bytes failed crypto, aborting\n");
    exit(1);
  }
#pragma omp parallel for
  for (int k = 0; k < NUM_ROUNDS; k++) {

    for (int j = 0; j < L_BYTES; j++) {
      shares[k][2][j] =
          input[j] ^ shares[k][0][j] ^
          shares[k][1][j]; // for each round, set share party_2 to input ^ share
                           // party_0 ^ share party_1
    }
  }
}

void mpc_sha256_prover(unsigned char shares[NUM_ROUNDS][3][L_BYTES],
                       unsigned char *randomness[NUM_ROUNDS][3],
                       View2 localViews[NUM_ROUNDS][3], a2 as[NUM_ROUNDS]) {

#pragma omp parallel for
  for (int k = 0; k < NUM_ROUNDS; k++) {
    commit2(shares[k], randomness[k], localViews[k]);
    output2(localViews[k], &as[k]);

    for (int j = 0; j < 3; j++) {
      free(randomness[k][j]);
    }
  }
}

void hash_views(unsigned char keys[NUM_ROUNDS][3][16],
                unsigned char rs[NUM_ROUNDS][3][4],
                View2 localViews[NUM_ROUNDS][3], a2 as[NUM_ROUNDS]) {
#pragma omp parallel for
  for (int k = 0; k < NUM_ROUNDS; k++) {
    unsigned char hash1[SHA256_DIGEST_LENGTH];
    H2(keys[k][0], localViews[k][0], rs[k][0], hash1);
    memcpy(as[k].h[0], &hash1, 32);
    H2(keys[k][1], localViews[k][1], rs[k][1], hash1);
    memcpy(as[k].h[1], &hash1, 32);
    H2(keys[k][2], localViews[k][2], rs[k][2], hash1);
    memcpy(as[k].h[2], &hash1, 32);
  }
}

void generate_challenge(a2 as[NUM_ROUNDS], int es[NUM_ROUNDS]) {
  uint32_t finalHash[8];
  for (int j = 0; j < 8; j++) {
    finalHash[j] = as[0].yp[0][0][j] ^ as[0].yp[0][1][j] ^ as[0].yp[0][2][j];
    finalHash[j] ^= as[0].yp[1][0][j] ^ as[0].yp[1][1][j] ^ as[0].yp[1][2][j];
  }
  H3_2(finalHash, as, NUM_ROUNDS, es);
  printf("%d %d %d %d\n", es[0], es[1], es[2], es[3]);
}

void write_to_file(a2 as[NUM_ROUNDS], z2 *zs,
                   char outputFile[3 * sizeof(int) + 8]) {
  FILE *file;

  sprintf(outputFile, "out%i_eq.bin", NUM_ROUNDS);
  file = fopen(outputFile, "wb");
  if (!file) {
    printf("Unable to open file!");
    exit(1);
  }
  fwrite(as, sizeof(a2), NUM_ROUNDS, file);
  fwrite(zs, sizeof(z2), NUM_ROUNDS, file);

  fclose(file);
}
// TODO: This file is outdated
int main(void) {
  init();

  unsigned char input[L_BYTES];

  printf("Committing to byte: %02x\n", input[0]);
  printf("Iterations of SHA: %d\n", NUM_ROUNDS);

  clock_t begin = clock();
  // randomness for commitments to view,
  unsigned char rs[NUM_ROUNDS][3][4]; // NUM_ROUNDS rounds * 3 parties * 32bits
  unsigned char keys[NUM_ROUNDS][3]
                    [16]; // NUM_ROUNDS rounds * 3 parties * 128bits
  View2 localViews[NUM_ROUNDS][3];

  // Generating keys
  clock_t beginCrypto = clock();
  generate_keys_and_rs(keys, rs);
  update_clock(beginCrypto, &totalCrypto);

  // Sharing secrets
  clock_t beginSS = clock();
  unsigned char shares[NUM_ROUNDS][3]
                      [L_BYTES]; // 3 shares of len(user_input) bytes
  share_secret(shares, input);
  update_clock(beginSS, &totalSS);

  unsigned char
      *randomness[NUM_ROUNDS][3]; // Randomness should have additional dimension

  // Generating randomness i.e., random tapes
  clock_t beginRandom = clock();
  generate_randomness(NUM_ROUNDS, keys, randomness);
  update_clock(beginRandom, &totalRandom);

  // Running MPC-SHA2
  a2 as[NUM_ROUNDS];
  clock_t beginSha = clock();
  mpc_sha256_prover(shares, randomness, localViews, as);
  update_clock(beginSha, &totalSha);

  // Committing
  clock_t beginHash = clock();
  hash_views(keys, rs, localViews, as);
  update_clock(beginSha, &totalHash);
  update_clock(begin, &inMilliA);

  // Generating E
  //  Note: E is the challenge that determines which 2 of the 3 views must be
  //  opened.
  clock_t beginE = clock();
  int es[NUM_ROUNDS];
  generate_challenge(as, es);
  update_clock(beginE, &inMilliE);

  // Packing Z
  clock_t beginZ;
  z2 *zs = malloc(sizeof(z2) * NUM_ROUNDS);
// Generate proof
#pragma omp parallel for
  for (int i = 0; i < NUM_ROUNDS; i++) {
    // create proof struct with view, key and randomness for parties es[i],
    // es[i]+1%3
    zs[i] = prove2(es[i], keys[i], rs[i], localViews[i]);
  }
  update_clock(beginZ, &inMilliZ);

  // Writing to file
  clock_t beginWrite = clock();
  char outputFile[3 * sizeof(int) + 8];
  write_to_file(as, zs, outputFile);
  update_clock(beginWrite, &inMilliWrite);

  free(zs);

  update_clock(begin, &inMilli);
  print_runtime(outputFile);
  cleanup();

  return EXIT_SUCCESS;
}

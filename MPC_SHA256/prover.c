#include "MPC_SHA256.h"
#include "omp.h"
#include "shared.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

const int NUM_ROUNDS = 136;

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
  init_EVP();
  openmp_thread_setup();
}

void cleanup() {
  openmp_thread_cleanup();
  cleanup_EVP();
}

void test_randomness() {
  unsigned char garbage[4];
  if (RAND_bytes(garbage, 4) != 1) {
    printf("RAND_bytes failed crypto, aborting\n");
    exit(1);
  }
}

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
  RAND_bytes_no_fail((unsigned char*) keys, NUM_ROUNDS * 3 * 16);
  RAND_bytes_no_fail((unsigned char*) rs, NUM_ROUNDS * 3 * 4);
}

void share_secret(int userInputLen,
                  unsigned char shares[NUM_ROUNDS][3][userInputLen],
                  const unsigned char input[userInputLen]) {
  if (RAND_bytes((unsigned char*) shares, NUM_ROUNDS * 3 * userInputLen) != 1) {
    printf("RAND_bytes failed crypto, aborting\n");
    exit(1);
  }
#pragma omp parallel for
  for (int k = 0; k < NUM_ROUNDS; k++) {

    for (int j = 0; j < userInputLen; j++) {
      shares[k][2][j] =
          input[j] ^ shares[k][0][j] ^
          shares[k][1][j]; // for each round, set share party_2 to input ^ share
                           // party_0 ^ share party_1
    }
  }
}

void mpc_sha256_prover(int userInputLen,
                unsigned char shares[NUM_ROUNDS][3][userInputLen],
                unsigned char *randomness[NUM_ROUNDS][3],
                unsigned char rs[NUM_ROUNDS][3][4],
                View localViews[NUM_ROUNDS][3], a as[NUM_ROUNDS]) {
#pragma omp parallel for
  for (int k = 0; k < NUM_ROUNDS; k++) {
    as[k] =
        commit(userInputLen, shares[k], randomness[k], rs[k], localViews[k]);

    // TODO: free and allocate once
    for (int j = 0; j < 3; j++) {
      free(randomness[k][j]);
    }
  }
}

void hash_views(unsigned char keys[NUM_ROUNDS][3][16],
                unsigned char rs[NUM_ROUNDS][3][4],
                View localViews[NUM_ROUNDS][3], a as[NUM_ROUNDS]) {
#pragma omp parallel for
  for (int k = 0; k < NUM_ROUNDS; k++) {
    unsigned char hash1[SHA256_DIGEST_LENGTH];
    H(keys[k][0], localViews[k][0], rs[k][0], hash1);
    memcpy(as[k].h[0], &hash1, 32);
    H(keys[k][1], localViews[k][1], rs[k][1], hash1);
    memcpy(as[k].h[1], &hash1, 32);
    H(keys[k][2], localViews[k][2], rs[k][2], hash1);
    memcpy(as[k].h[2], &hash1, 32);
  }
}

void generate_challenge(a as[NUM_ROUNDS], int es[NUM_ROUNDS]) {
  uint32_t finalHash[8];
  for (int j = 0; j < 8; j++) {
    finalHash[j] = as[0].yp[0][j] ^ as[0].yp[1][j] ^ as[0].yp[2][j];
  }
  H3(finalHash, as, NUM_ROUNDS, es);
}

void write_to_file(a as[NUM_ROUNDS], z *zs,
                   char outputFile[3 * sizeof(int) + 8]) {
  FILE *file;

  sprintf(outputFile, "out%i.bin", NUM_ROUNDS);
  file = fopen(outputFile, "wb");
  if (!file) {
    printf("Unable to open file!");
    exit(1);
  }
  fwrite(as, sizeof(a), NUM_ROUNDS, file);
  fwrite(zs, sizeof(z), NUM_ROUNDS, file);

  fclose(file);
}

int main(void) {
  init();

  test_randomness();

  printf("Enter the string to be hashed (Max 55 characters): ");
  char userInput[55]; // 55 is max length as we only support 447 bits = 55.875
                      // bytes
  fgets(userInput, sizeof(userInput), stdin);

  int userInputLen = strlen(userInput) - 1;
  printf("String length: %d\n", userInputLen);

  printf("Iterations of SHA: %d\n", NUM_ROUNDS);

  unsigned char input[userInputLen];
  for (int j = 0; j < userInputLen; j++) {
    input[j] = userInput[j];
  }

  clock_t begin = clock();
  // randomness for commitments to views: Com(x,r) = SHA-256(x,r)
  unsigned char rs[NUM_ROUNDS][3][4]; // NUM_ROUNDS rounds * 3 parties * 32bits
  unsigned char keys[NUM_ROUNDS][3]
                    [16]; // NUM_ROUNDS rounds * 3 parties * 128bits
  a as[NUM_ROUNDS];       // containes 32 bytes ouput for each view and the
                          // commitments to the views
  View localViews[NUM_ROUNDS][3];

  // Generating keys
  clock_t beginCrypto = clock();
  generate_keys_and_rs(keys, rs);
  update_clock(beginCrypto, &totalCrypto);

  // Sharing secrets
  clock_t beginSS = clock();
  unsigned char shares[NUM_ROUNDS][3]
                      [userInputLen]; // 3 shares of len(user_input) bytes
  share_secret(userInputLen, shares, input);
  update_clock(beginSS, &totalSS);

  unsigned char *randomness[NUM_ROUNDS][3];

  // Generating randomness i.e., random tapes
  clock_t beginRandom = clock();
  generate_randomness(NUM_ROUNDS, keys, randomness);
  update_clock(beginRandom, &totalRandom);

  // Running MPC-SHA2
  clock_t beginSha = clock();
  mpc_sha256_prover(userInputLen, shares, randomness, rs, localViews, as);
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
  z *zs = malloc(sizeof(z) * NUM_ROUNDS);

// Generate proof
#pragma omp parallel for
  for (int i = 0; i < NUM_ROUNDS; i++) {
    // create proof struct with view, key and randomness for parties es[i],
    // es[i]+1%3
    zs[i] = prove(es[i], keys[i], rs[i], localViews[i]);
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

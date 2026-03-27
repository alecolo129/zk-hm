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

static int totalRandom = 0;
static int totalSha = 0;
static int totalSS = 0;
static int totalHash = 0;

inline void update_clock(clock_t beginClock, int *clockToUpdate) {
  clock_t deltaT = clock() - beginClock;
  int inMilli = deltaT * 1000 / CLOCKS_PER_SEC;
  *clockToUpdate += inMilli;
}

int main(void) {
  setbuf(stdout, NULL);
  srand((unsigned)time(NULL));
  init_EVP();
  openmp_thread_setup();

  //
  unsigned char garbage[4];
  if (RAND_bytes(garbage, 4) != 1) {
    printf("RAND_bytes failed crypto, aborting\n");
    return 0;
  }

  printf("Enter the string to be hashed (Max 55 characters): ");
  char userInput[55]; // 55 is max length as we only support 447 bits = 55.875
                      // bytes
  fgets(userInput, sizeof(userInput), stdin);

  int i = strlen(userInput) - 1;
  printf("String length: %d\n", i);

  printf("Iterations of SHA: %d\n", NUM_ROUNDS);

  unsigned char input[i];
  for (int j = 0; j < i; j++) {
    input[j] = userInput[j];
  }

  clock_t begin = clock(), delta, deltaA;
  // randomness for commitments to views: Com(x,r) = SHA-256(x,r)
  unsigned char rs[NUM_ROUNDS][3][4]; // NUM_ROUNDS rounds * 3 parties * 32bits
  unsigned char keys[NUM_ROUNDS][3]
                    [16]; // NUM_ROUNDS rounds * 3 parties * 128bits
  a as[NUM_ROUNDS];       // containes 32 bytes ouput for each view and the
                          // commitments to the views
  View localViews[NUM_ROUNDS][3];
  int totalCrypto = 0;

  // Generating keys
  clock_t beginCrypto = clock(), deltaCrypto;
  if (RAND_bytes(keys, NUM_ROUNDS * 3 * 16) != 1) {
    printf("RAND_bytes failed crypto, aborting\n");
    return 0;
  }
  if (RAND_bytes(rs, NUM_ROUNDS * 3 * 4) != 1) {
    printf("RAND_bytes failed crypto, aborting\n");
    return 0;
  }
  deltaCrypto = clock() - beginCrypto;
  int inMilliCrypto = deltaCrypto * 1000 / CLOCKS_PER_SEC;
  totalCrypto = inMilliCrypto;

  // Sharing secrets
  clock_t beginSS = clock(), deltaSS;
  unsigned char shares[NUM_ROUNDS][3][i]; // 3 shares of len(user_input) bytes
  if (RAND_bytes(shares, NUM_ROUNDS * 3 * i) != 1) {
    printf("RAND_bytes failed crypto, aborting\n");
    return 0;
  }
#pragma omp parallel for
  for (int k = 0; k < NUM_ROUNDS; k++) {

    for (int j = 0; j < i; j++) {
      shares[k][2][j] =
          input[j] ^ shares[k][0][j] ^
          shares[k][1][j]; // for each round, set share party_2 to input ^ share
                           // party_0 ^ share party_1
    }
  }
  deltaSS = clock() - beginSS;
  int inMilli = deltaSS * 1000 / CLOCKS_PER_SEC;
  totalSS = inMilli;

  unsigned char *randomness[NUM_ROUNDS][3];
  int inMilliA;
  for (int n_commit = 0; n_commit < 1; n_commit++) {
    // Generating randomness i.e., random tapes
    // Note: In the MPC protocol we need 32 bit of randomness for each ADD/AND
    // operation in SHA256 (operates on 32bit words). We have 64 AND gates and
    // 664 ADD gates, so we need 728 * 32 / 8 = 2912 bytes of randomness.
    clock_t beginRandom = clock();
    generate_randomness(NUM_ROUNDS, keys, randomness);
    update_clock(beginRandom, &totalRandom);

    clock_t beginSha = clock(), deltaSha;
    // Running MPC-SHA2
#pragma omp parallel for
    for (int k = 0; k < NUM_ROUNDS; k++) {
      as[k] = commit(i, shares[k], randomness[k], rs[k], localViews[k]);

      // TODO: free and allocate once
      for (int j = 0; j < 3; j++) {
        free(randomness[k][j]);
      }
    }
    update_clock(beginSha, &totalSha);

    // Committing
    clock_t beginHash = clock();
#pragma omp parallel for
    for (int k = 0; k < NUM_ROUNDS; k++) {
      unsigned char hash1[SHA256_DIGEST_LENGTH];
      H(keys[k][0], localViews[k][0], rs[k][0], &hash1);
      memcpy(as[k].h[0], &hash1, 32);
      H(keys[k][1], localViews[k][1], rs[k][1], &hash1);
      memcpy(as[k].h[1], &hash1, 32);
      H(keys[k][2], localViews[k][2], rs[k][2], &hash1);
      memcpy(as[k].h[2], &hash1, 32);
    }

    update_clock(beginSha, &totalHash);
    update_clock(begin, &inMilliA);
  }

  // unsigned char **randomness = commit_randomness[0];

  // Generating E
  //  note: E is the challenge that determines which 2 of the 3 views must be
  //  opened.
  clock_t beginE = clock(), deltaE;
  int es[NUM_ROUNDS];
  uint32_t finalHash[8];
  for (int j = 0; j < 8; j++) {
    finalHash[j] = as[0].yp[0][j] ^ as[0].yp[1][j] ^ as[0].yp[2][j];
  }
  H3(finalHash, as, NUM_ROUNDS, es);
  deltaE = clock() - beginE;
  int inMilliE = deltaE * 1000 / CLOCKS_PER_SEC;

  // Packing Z
  clock_t beginZ = clock(), deltaZ;
  z *zs = malloc(sizeof(z) * NUM_ROUNDS);

#pragma omp parallel for
  for (int i = 0; i < NUM_ROUNDS; i++) {
    // create proof struct with view, key and randomness for parties es[i],
    // es[i]+1%3
    zs[i] = prove(es[i], keys[i], rs[i], localViews[i]);
  }
  deltaZ = clock() - beginZ;
  int inMilliZ = deltaZ * 1000 / CLOCKS_PER_SEC;

  // Writing to file
  clock_t beginWrite = clock();
  FILE *file;

  char outputFile[3 * sizeof(int) + 8];
  sprintf(outputFile, "out%i.bin", NUM_ROUNDS);
  file = fopen(outputFile, "wb");
  if (!file) {
    printf("Unable to open file!");
    return 1;
  }
  fwrite(as, sizeof(a), NUM_ROUNDS, file);
  fwrite(zs, sizeof(z), NUM_ROUNDS, file);

  fclose(file);

  clock_t deltaWrite = clock() - beginWrite;
  free(zs);
  int inMilliWrite = deltaWrite * 1000 / CLOCKS_PER_SEC;

  delta = clock() - begin;
  inMilli = delta * 1000 / CLOCKS_PER_SEC;

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
  printf("Proof output to file %s", outputFile);

  openmp_thread_cleanup();
  cleanup_EVP();
  return EXIT_SUCCESS;
}

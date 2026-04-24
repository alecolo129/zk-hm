#include "MPC_SHA256.h"
#include "MPC_inner_prod.h"
#include "omp.h"
#include "shared.h"
#include <bits/time.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static double totalCrypto = 0;
static double totalRandom = 0;
static double totalHM = 0;
static double totalSS = 0;
static double totalHash = 0;

static double inMilliA = 0;
static double inMilliE = 0;
static double inMilliZ = 0;
static double inMilliWrite = 0;
static double inMilli = 0;

void test_randomness() {
  uint8_t garbage[4];
  if (RAND_bytes(garbage, 4) != 1) {
    printf("RAND_bytes failed crypto, aborting\n");
    exit(1);
  }
}

void init() {
  setbuf(stdout, NULL);
  srand((unsigned)time(NULL));
  openmp_thread_setup();

  test_randomness();
}

void cleanup() {
  openmp_thread_cleanup();
}

static inline void update_clock(double beginClock, double *clockToUpdate) {
  double deltaT = (omp_get_wtime() - beginClock) * 1000;
  *clockToUpdate += deltaT;
}

void print_runtime(const char *outputFile) {

  double sumOfParts = 0;

  printf("Generating A: %f\n", inMilliA);
  printf("	Generating keys: %f\n", totalCrypto);
  sumOfParts += totalCrypto;
  printf("	Generating randomness: %f\n", totalRandom);
  sumOfParts += totalRandom;
  printf("	Sharing secrets: %f\n", totalSS);
  sumOfParts += totalSS;
  printf("	Running MPC-HM: %f\n", totalHM);
  sumOfParts += totalHM;
  printf("	Committing: %f\n", totalHash);
  sumOfParts += totalHash;
  printf("	*Accounted for*: %f\n", sumOfParts);
  printf("Generating E: %f\n", inMilliE);
  printf("Packing Z: %f\n", inMilliZ);
  printf("Writing file: %f\n", inMilliWrite);
  printf("Total: %f\n", inMilli);
  printf("\n");
  printf("Proof output to file %s\n", outputFile);
}

// TODO: avoid potential leakages
inline void RAND_bytes_no_fail(uint8_t *buf, int num) {
  if (!RAND_bytes(buf, 1)) {
    printf("RAND_bytes failed crypto, aborting\n");
    exit(1);
  }
}

void generate_keys_and_rs(uint8_t keys[NUM_ROUNDS][3][16],
                          uint8_t rs[NUM_ROUNDS][3][4]) {
  RAND_bytes_no_fail((uint8_t *)keys, NUM_ROUNDS * 3 * 16);
  RAND_bytes_no_fail((uint8_t *)rs, NUM_ROUNDS * 3 * 4);
}

void share_secrets(uint8_t rShares[NUM_ROUNDS][3][L_BYTES],
                   uint32_t msgShares[NUM_ROUNDS][3],
                   const uint8_t rBytes[L_BYTES], const uint8_t msg) {
  if (RAND_bytes((uint8_t *)rShares, NUM_ROUNDS * 3 * L_BYTES) != 1) {
    printf("RAND_bytes failed crypto, aborting\n");
    exit(1);
  }
#pragma omp parallel for
  for (int k = 0; k < NUM_ROUNDS; k++) {
    for (int j = 0; j < L_BYTES; j++) {
      rShares[k][2][j] =
          rBytes[j] ^ rShares[k][0][j] ^
          rShares[k][1][j]; // for each round, set share party_2 to input ^
                            // share party_0 ^ share party_1
    }
    msgShares[k][2] = msg ^ msgShares[k][0] ^
                      msgShares[k][1]; // for each round, set share party_2 to
                                       // input ^ share party_0 ^ share party_1
  }
}

void bytes_to_words(uint32_t rWords[L_WORDS], const uint8_t rBytes[L_BYTES]) {
  for (int j = 0; j < L_WORDS; j++) {
    memcpy(&rWords[j], &rBytes[j * 4], sizeof(uint32_t));
  }
}

void mpc_halevi_micali_prover(View localViews[NUM_ROUNDS][3], a as[NUM_ROUNDS],
                              uint8_t *randomness[NUM_ROUNDS][3],
                              uint8_t rs[NUM_ROUNDS][3][4],
                              const UniversalHash h,
                              uint8_t rShares[NUM_ROUNDS][3][L_BYTES],
                              const uint32_t msgShares[NUM_ROUNDS][3]) {
#pragma omp parallel for
  for (int k = 0; k < NUM_ROUNDS; k++) {

    // prove y = SHA256(r)
    commit(L_BYTES, rShares[k], randomness[k], rs[k], localViews[k]);

    // copy last part of the view.y (i.e., SHA256 output) into a.yp
    output(localViews[k][0], as[k].yp[0]);
    output(localViews[k][1], as[k].yp[1]);
    output(localViews[k][2], as[k].yp[2]);

    // TODO: free and allocate once
    for (int j = 0; j < 3; j++) {
      free(randomness[k][j]);
    }

    // prove H(r) = m
    uint32_t rWords[L_WORDS][3];
    for (int i = 0; i < L_WORDS; i++) {
      memcpy(&rWords[i][0], &rShares[k][0][i * 4], sizeof(uint32_t));
      memcpy(&rWords[i][1], &rShares[k][1][i * 4], sizeof(uint32_t));
      memcpy(&rWords[i][2], &rShares[k][2][i * 4], sizeof(uint32_t));
    }
    // copy msg share into respective local view
    localViews[k][0].msg = msgShares[k][0];
    localViews[k][1].msg = msgShares[k][1];
    localViews[k][2].msg = msgShares[k][2];

    mpc_inner_prod_prover(h, msgShares[k], rWords, as[k].y2p);
  }
}

void hash_views(uint8_t keys[NUM_ROUNDS][3][16], uint8_t rs[NUM_ROUNDS][3][4],
                View localViews[NUM_ROUNDS][3], a as[NUM_ROUNDS]) {
#pragma omp parallel for
  for (int k = 0; k < NUM_ROUNDS; k++) {
    uint8_t hash1[SHA256_DIGEST_LENGTH];
    H(keys[k][0], localViews[k][0], rs[k][0], hash1);
    memcpy(as[k].h[0], &hash1, 32);
    H(keys[k][1], localViews[k][1], rs[k][1], hash1);
    memcpy(as[k].h[1], &hash1, 32);
    H(keys[k][2], localViews[k][2], rs[k][2], hash1);
    memcpy(as[k].h[2], &hash1, 32);
  }
}

void generate_challenge(a as[NUM_ROUNDS], int es[NUM_ROUNDS],
                        const UniversalHash h) {
  uint32_t finalHash[8];
  for (int j = 0; j < 8; j++) {
    finalHash[j] = as[0].yp[0][j] ^ as[0].yp[1][j] ^ as[0].yp[2][j];
  }
  H3(finalHash, as, NUM_ROUNDS, h, es);
}

void pick_universal_hash(UniversalHash h, const uint8_t msg,
                         const uint8_t rBytes[L_BYTES]) {
  uint32_t rWords[L_WORDS];
  bytes_to_words(rWords, rBytes);
  RAND_bytes((uint8_t *)h.A, L_BYTES); // TODO: generate A from PRG and seed
  generate_H(msg, rWords, h.A, &h.b);
}

void write_to_file(char outputFile[3 * sizeof(int) + 8], const a as[NUM_ROUNDS],
                   const z *zs, const UniversalHash h) {
  FILE *file;

  sprintf(outputFile, "out%i.bin", NUM_ROUNDS);
  file = fopen(outputFile, "wb");
  if (!file) {
    printf("Unable to open file!");
    exit(EXIT_FAILURE);
  }

  uint32_t nWrite = fwrite(&h, sizeof(h), 1, file);
  nWrite += fwrite(as, sizeof(a), NUM_ROUNDS, file);
  nWrite += fwrite(zs, sizeof(z), NUM_ROUNDS, file);
  fclose(file);

  if (nWrite != 2 * NUM_ROUNDS + 1) {
    printf("Failed to write proof!\n");
    exit(EXIT_FAILURE);
  }
}

int main(void) {
  init();

  uint8_t rBytes[L_BYTES]; // take random r in {0,1}^L
  RAND_bytes_no_fail((uint8_t *)rBytes, sizeof(rBytes));
  uint8_t msg;
  RAND_bytes_no_fail(&msg, sizeof(msg));

  printf("Iterations of SHA: %d\n", NUM_ROUNDS);

  double begin = omp_get_wtime();
  // randomness for commitments to secret input: Com(x,r) = SHA-256(x,r)
  uint8_t rs[NUM_ROUNDS][3][4];    // NUM_ROUNDS rounds * 3 parties * 32bits
  uint8_t keys[NUM_ROUNDS][3][16]; // NUM_ROUNDS rounds * 3 parties * 128bits
  a as[NUM_ROUNDS]; // containes 32 bytes ouput for each view and the
                    // commitments to the views
  View localViews[NUM_ROUNDS][3];

  // Generating keys
  double beginCrypto = omp_get_wtime();
  generate_keys_and_rs(keys, rs);
  update_clock(beginCrypto, &totalCrypto);

  // Sharing secrets
  double beginSS = omp_get_wtime();
  uint8_t rShares[NUM_ROUNDS][3][L_BYTES];
  uint32_t msgShares[NUM_ROUNDS][3];
  share_secrets(rShares, msgShares, rBytes, msg);
  update_clock(beginSS, &totalSS);

  // Generating randomness i.e., random tapes
  double beginRandom = omp_get_wtime();
  uint8_t *randomness[NUM_ROUNDS][3];
  generate_randomness(NUM_ROUNDS, keys, randomness);
  update_clock(beginRandom, &totalRandom);

  // Running HM commitment
  double beginHM = omp_get_wtime();
  UniversalHash h;
  pick_universal_hash(h, msg, rBytes); // pick universal hash function
  mpc_halevi_micali_prover(localViews, as, randomness, rs, h, rShares,
                           msgShares);
  update_clock(beginHM, &totalHM);

  // Committing
  double beginHash = omp_get_wtime();
  hash_views(keys, rs, localViews, as);
  update_clock(beginHash, &totalHash);

  update_clock(begin, &inMilliA);

  // Generating E
  //  Note: E is the challenge that determines which 2 of the 3 views must be
  //  opened.
  double beginE = omp_get_wtime();
  int es[NUM_ROUNDS];
  generate_challenge(as, es, h);
  update_clock(beginE, &inMilliE);

  // Packing Z
  double beginZ = omp_get_wtime();
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
  double beginWrite = omp_get_wtime();
  char outputFile[3 * sizeof(int) + 8];
  write_to_file(outputFile, as, zs, h);
  update_clock(beginWrite, &inMilliWrite);

  free(zs);

  update_clock(begin, &inMilli);
  print_runtime(outputFile);
  cleanup();

  return EXIT_SUCCESS;
}

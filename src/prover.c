#include "MPC_SHA256.h"
#include "MPC_inner_prod.h"
#include "omp.h"
#include "shared.h"
#include <bits/time.h>
#include <openssl/evp.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

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

void cleanup() { openmp_thread_cleanup(); }

static inline void update_clock(double beginClock, double *clockToUpdate) {
  double deltaT = (omp_get_wtime() - beginClock) * 1000;
  *clockToUpdate += deltaT;
}

void print_runtime(const char *outputFile) {
  printf("Total: %f\n", inMilli);
  printf("\n");
  printf("Proof output to file %s\n", outputFile);
}

// TODO: avoid potential leakages
inline void RAND_bytes_no_fail(uint8_t *buf, int num) {
  if (RAND_bytes(buf, num) != 1) {
    printf("RAND_bytes failed crypto, aborting\n");
    exit(1);
  }
}

void generate_keys_and_rs(uint8_t keys[NUM_ROUNDS][3][16], uint8_t keyH[16],
                          uint8_t rs[NUM_ROUNDS][3][4]) {
  RAND_bytes_no_fail((uint8_t *)keys, NUM_ROUNDS * 3 * 16);
  RAND_bytes_no_fail((uint8_t *)keyH, 16);
  RAND_bytes_no_fail((uint8_t *)rs, NUM_ROUNDS * 3 * 4);
}

void share_secrets(uint8_t rShares[3][L_BYTES], uint32_t msgShares[3],
                   const uint8_t rBytes[L_BYTES], const uint8_t msg) {
  RAND_bytes_no_fail((uint8_t *)rShares, 3 * L_BYTES);
  RAND_bytes_no_fail((uint8_t *)msgShares, 3 * sizeof(uint32_t));

  for (int j = 0; j < L_BYTES; j++) {
    rShares[2][j] = rBytes[j] ^ rShares[0][j] ^ rShares[1][j];
  }
  msgShares[0] &= 1;
  msgShares[1] &= 1;
  msgShares[2] = msg ^ msgShares[0] ^ msgShares[1];
}

void bytes_to_words(uint32_t rWords[L_WORDS], const uint8_t rBytes[L_BYTES]) {
  for (int j = 0; j < L_WORDS; j++) {
    memcpy(&rWords[j], &rBytes[j * 4], sizeof(uint32_t));
  }
}

void mpc_halevi_micali_prover(View *localViews[3], a *as,
                              uint8_t *randomness[3], uint8_t rs[3][4],
                              const UniversalHash *h,
                              uint8_t rShares[3][L_BYTES],
                              const uint32_t msgShares[3]) {

  // prove y = SHA256(r)
  commit(rShares, randomness, rs, localViews);

  // copy last part of the view.y (i.e., SHA256 output) into a.yp
  output(localViews[0], as->yp[0]);
  output(localViews[1], as->yp[1]);
  output(localViews[2], as->yp[2]);

  // prove H(r) = m
  uint32_t rWords[L_WORDS][3];
  for (int i = 0; i < L_WORDS; i++) {
    memcpy(&rWords[i][0], &rShares[0][i * 4], sizeof(uint32_t));
    memcpy(&rWords[i][1], &rShares[1][i * 4], sizeof(uint32_t));
    memcpy(&rWords[i][2], &rShares[2][i * 4], sizeof(uint32_t));
  }
  // copy msg share into respective local view
  localViews[0]->msg = msgShares[0];
  localViews[1]->msg = msgShares[1];
  localViews[2]->msg = msgShares[2];
  mpc_inner_prod_prover(h, msgShares, rWords, as->y2p);
}

void hash_views(EVP_MD_CTX *ctx, uint8_t keys[3][16], uint8_t rs[3][4],
                View *localViews[3], a *as) {
  uint8_t hash1[SHA256_DIGEST_LENGTH];
  HH(ctx, keys[0], localViews[0], rs[0], hash1);
  memcpy(as->h[0], &hash1, 32);
  HH(ctx, keys[1], localViews[1], rs[1], hash1);
  memcpy(as->h[1], &hash1, 32);
  HH(ctx, keys[2], localViews[2], rs[2], hash1);
  memcpy(as->h[2], &hash1, 32);
}

void generate_challenge(a *a, int *e, EVP_MD_CTX *ctx) {
  uint32_t finalHash[8];
  for (int j = 0; j < 8; j++) {
    finalHash[j] = a->yp[0][j] ^ a->yp[1][j] ^ a->yp[2][j];
  }
  H3(ctx, finalHash, a, 1, e);
}

void pick_universal_hash(UniversalHash *h, const uint8_t keyA[16],
                         const uint8_t rBytes[L_BYTES], const uint8_t msg) {
  uint32_t rWords[L_WORDS];
  bytes_to_words(rWords, rBytes);
  generate_H(h->A, &h->b, keyA, msg, rWords);
}

void serialize_universal_hash(FILE *f, const uint8_t keyH[16],
                              const UniversalHash *H) {
  // Pack into one contiguous buffer to write once
  unsigned char buf[16 + sizeof(H->b)];
  memcpy(buf, keyH, 16);
  memcpy(buf + 16, &H->b, sizeof(H->b));

  uint32_t nWrite = fwrite(buf, 1, 16 + sizeof(H->b), f);
  if (nWrite != 16 + sizeof(H->b)) {
    fclose(f);
    fprintf(stderr, "Failed to serialize Universal Hash!\n");
    exit(EXIT_FAILURE);
  }
}

int serialize_zk_proof_at(FILE *f, unsigned char *buf, size_t buffSize, int k,
                          const a *a_ptr, const z *z_ptr) {
  off_t initial_offset =
      16 + 1; // TODO: this should not depend on H.b being 1 byte

  size_t proofSize = sizeof(a) + sizeof(z_disk);
  if (buffSize < proofSize) {
    fprintf(stderr, "allocated buffer is %luB, required is %luB\n", buffSize,
            proofSize);
    return -1;
  }

  size_t bufIdx = 0;
  memcpy(buf, a_ptr, sizeof(*a_ptr));
  bufIdx += sizeof(*a_ptr);

  memcpy(buf + bufIdx, z_ptr->ke, sizeof(z_ptr->ke));
  bufIdx += sizeof(z_ptr->ke);
  memcpy(buf + bufIdx, z_ptr->ke1, sizeof(z_ptr->ke1));
  bufIdx += sizeof(z_ptr->ke1);

  memcpy(buf + bufIdx, z_ptr->re, sizeof(z_ptr->re));
  bufIdx += sizeof(z_ptr->re);
  memcpy(buf + bufIdx, z_ptr->re1, sizeof(z_ptr->re1));
  bufIdx += sizeof(z_ptr->re1);

  memcpy(buf + bufIdx, z_ptr->ve, sizeof(*z_ptr->ve));
  bufIdx += sizeof(*z_ptr->ve);
  memcpy(buf + bufIdx, z_ptr->ve1, sizeof(*z_ptr->ve1));
  bufIdx += sizeof(*z_ptr->ve1);

  int fd = fileno(f);
  off_t off = initial_offset + (off_t)k * proofSize;

  ssize_t nWrite = pwrite(fd, buf, proofSize, off);
  return (nWrite == (ssize_t)bufIdx) ? 0 : -1;
}

static void init_randomness(uint8_t *randomness[3]) {
  randomness[0] = malloc(3 * RAND_BYTES);
  if (!randomness[0]) {
    fprintf(stderr, "(%d) malloc failure...\n", __LINE__);
    exit(EXIT_FAILURE);
  }
  randomness[1] = randomness[0] + RAND_BYTES;
  randomness[2] = randomness[1] + RAND_BYTES;
}

static void free_randomness(uint8_t *randomness[3]) {
  if (randomness[0] != NULL)
    free(randomness[0]);
}

int main(void) {
  init();

  uint8_t rBytes[L_BYTES];
  uint8_t msg;
  RAND_bytes_no_fail((uint8_t *)rBytes,
                     sizeof(rBytes)); // take random r in {0,1}^L
  RAND_bytes_no_fail(&msg, sizeof(msg));
  msg &= 1;
  printf("Iterations of SHA: %d\n", NUM_ROUNDS);

  double begin = omp_get_wtime();
  uint8_t rs[NUM_ROUNDS][3][4]; // randomness internal commitments to views
  uint8_t keys[NUM_ROUNDS][3]
              [16]; // PRG keys to generate randomness for MPC protocol
  uint8_t keyH[16]; // key to generate universal hash function

  // Generating keys
  generate_keys_and_rs(keys, keyH, rs);
  UniversalHash h;
  pick_universal_hash(&h, keyH, rBytes, msg); // pick universal hash function

  char outputFile[3 * sizeof(int) + 8];
  sprintf(outputFile, "out%i.bin", NUM_ROUNDS);
  FILE *file = fopen(outputFile, "wb");
  if (!file) {
    fprintf(stderr, "Unable to open file!");
    exit(EXIT_FAILURE);
  }
  serialize_universal_hash(file, keyH, &h);

  atomic_int io_error = 0;

  EVP_MD_CTX *base_ctx = setupSHA256();
  EVP_DigestUpdate(base_ctx, h.A, sizeof(h.A));
  EVP_DigestUpdate(base_ctx, &h.b, sizeof(h.b));
#pragma omp parallel
  {
    // Init thread state
    uint8_t rShares[3][L_BYTES];
    uint32_t msgShares[3];
    uint8_t *randomness[3];
    View *bufViews = malloc(3 * sizeof(View));
    View *localView[3] = {bufViews, bufViews + 1, bufViews + 2};
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_MD_CTX *ctx2 = setupSHA256();
    // Pack into one contiguous buffer to write once
    size_t buffSize = sizeof(a) + sizeof(z_disk);
    unsigned char *bufWrite = malloc(buffSize);
    int e;
    init_randomness(randomness);
    a a; // containes 32 bytes ouput for each view and the
    // commitments to the views
    z z;
#pragma omp for
    for (int k = 0; k < NUM_ROUNDS; k++) {
      if (atomic_load(&io_error))
        continue;

      // Sharing secrets
      share_secrets(rShares, msgShares, rBytes, msg);
      // Generating randomness i.e., random tapes
      generate_randomness(keys[k], randomness);
      // Running HM commitment
      mpc_halevi_micali_prover(localView, &a, randomness, rs[k], &h, rShares,
                               msgShares);
      // Committing
      hash_views(ctx2, keys[k], rs[k], localView, &a);
      // Generating E
      //  Note: E is the challenge that determines which 2 of the 3 views must
      //  be opened.
      EVP_MD_CTX_copy_ex(ctx, base_ctx);
      generate_challenge(&a, &e, ctx);

      z = prove(e, keys[k], rs[k], localView);

      if (serialize_zk_proof_at(file, bufWrite, buffSize, k, &a, &z) != 0) {
        atomic_store(&io_error, 1);
      }
    }

    // Release thread state
    free(bufViews);
    free(bufWrite);
    free_randomness(randomness);
    EVP_MD_CTX_free(ctx);
  }

  if (io_error) {
    fprintf(stderr, "Failed to serialize zk proof!\n");
    fclose(file);
    cleanup();
    EVP_MD_CTX_free(base_ctx);
    exit(EXIT_FAILURE);
  }

  update_clock(begin, &inMilli);
  fclose(file);
  EVP_MD_CTX_free(base_ctx);
  print_runtime(outputFile);

  return EXIT_SUCCESS;
}

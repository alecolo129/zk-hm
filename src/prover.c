#include "MPC_SHA256.h"
#include "MPC_universal_hash.h"
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
    LOG_ERRF("RAND_bytes failed crypto, aborting\n");
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
static inline void RAND_bytes_no_fail(uint8_t *buf, int num) {
  if (RAND_bytes(buf, num) != 1) {
    LOG_ERRF("RAND_bytes failed crypto, aborting");
    exit(1);
  }
}

void generate_keys_and_rs(uint8_t keys[NUM_ROUNDS][3][16], uint8_t keyH[16],
                          uint8_t rs[NUM_ROUNDS][3][4]) {
  RAND_bytes_no_fail((uint8_t *)keys, NUM_ROUNDS * 3 * 16);
  RAND_bytes_no_fail((uint8_t *)keyH, 16);
  RAND_bytes_no_fail((uint8_t *)rs, NUM_ROUNDS * 3 * 4);
}

void share_secrets(uint8_t rShares[3][L_BYTES],
                   uint32_t msgShares[MSG_WORDS][3],
                   const uint8_t rBytes[L_BYTES],
                   const uint8_t msg[MSG_BYTES]) {
  RAND_bytes_no_fail((uint8_t *)rShares, 3 * L_BYTES * sizeof(uint8_t));
  for (int j = 0; j < L_BYTES; j++) {
    rShares[2][j] = rBytes[j] ^ rShares[0][j] ^ rShares[1][j];
  }

  RAND_bytes_no_fail((uint8_t *)msgShares, 3 * MSG_WORDS * sizeof(uint32_t));
  uint32_t mask = (MSG_BITS % 32) ? ((1ul << (MSG_BITS % 32)) - 1) : 0xFFFFFFFFu;
  msgShares[MSG_WORDS - 1][0] &= mask;
  msgShares[MSG_WORDS - 1][1] &= mask;
  for (int j = 0; j < MSG_WORDS; j++) {
    load_u32_le(&msgShares[j][2], &msg[j * 4]);
    msgShares[j][2] ^= msgShares[j][0] ^ msgShares[j][1];
  }
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
                              const uint32_t msgShares[MSG_WORDS][3]) {

  // prove y = SHA256(r)
  commit(rShares, randomness, rs, localViews);

  // copy last part of the view.y (i.e., SHA256 output) into a.yp
  output(localViews[0], as->yp[0]);
  output(localViews[1], as->yp[1]);
  output(localViews[2], as->yp[2]);

  // prove H(r) = m
  uint32_t rWords[L_WORDS][3] = {0};
  for (int i = 0; i < L_WORDS; i++) {
    memcpy(&rWords[i][0], &rShares[0][i * 4], sizeof(uint32_t));
    memcpy(&rWords[i][1], &rShares[1][i * 4], sizeof(uint32_t));
    memcpy(&rWords[i][2], &rShares[2][i * 4], sizeof(uint32_t));
  }
  // copy msg share into respective local view
  for (int i = 0; i < MSG_WORDS; i++) {
    memcpy(&localViews[0]->msg[i * 4], &msgShares[i][0], sizeof(uint32_t));
    memcpy(&localViews[1]->msg[i * 4], &msgShares[i][1], sizeof(uint32_t));
    memcpy(&localViews[2]->msg[i * 4], &msgShares[i][2], sizeof(uint32_t));
  }
  mpc_universal_hash_prover(h, msgShares, rWords, as->y2p);
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
                         const uint8_t rBytes[L_BYTES],
                         const uint8_t msg[MSG_BYTES]) {
  uint32_t rWords[L_WORDS];
  bytes_to_words(rWords, rBytes);
  generate_H(h->A, h->b, keyA, msg, rWords);
}

void serialize_universal_hash(FILE *f, const uint8_t keyH[16],
                              const UniversalHash *H) {
  // Pack into one contiguous buffer to write once
  unsigned char buf[16 + sizeof(H->b)];
  memcpy(buf, keyH, 16);
  memcpy(buf + 16, H->b, sizeof(H->b));

  uint32_t nWrite = fwrite(buf, 1, 16 + sizeof(H->b), f);
  if (nWrite != 16 + sizeof(H->b)) {
    fclose(f);
    LOG_ERRF("Failed to serialize Universal Hash!");
    exit(EXIT_FAILURE);
  }
}

int serialize_zk_proof_at(FILE *f, unsigned char *buf, size_t buffSize, int k,
                          const a *a_ptr, const z *z_ptr) {
  off_t initial_offset = 16 + MSG_BYTES;

  size_t proofSize = sizeof(a) + sizeof(z_disk);
  if (buffSize < proofSize) {
    LOG_ERRF("Allocated buffer is %luB, required is %luB\n", buffSize,
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
    LOG_ERRF("malloc failure");
    exit(EXIT_FAILURE);
  }
  randomness[1] = randomness[0] + RAND_BYTES;
  randomness[2] = randomness[1] + RAND_BYTES;
}

static void free_randomness(uint8_t *randomness[3]) {
  if (randomness[0] != NULL)
    free(randomness[0]);
}

typedef struct ProverThreadState {
  // Shares reused each iteration
  uint8_t rShares[3][L_BYTES];
  uint32_t msgShares[MSG_WORDS][3];

  // Randomness tapes (3 pointers into one block)
  uint8_t *rand_block;
  uint8_t *randomness[3];

  // 3 views in one contiguous block
  View *views_block;
  View *views[3];

  // Hash contexts
  EVP_MD_CTX *ctx_chal; // used with EVP_MD_CTX_copy_ex + H3
  EVP_MD_CTX *ctx_hash; // used by HH() inside hash_views()

  // Serialization buffer per thread
  unsigned char *bufWrite;
  size_t bufSize;
} ProverThreadState;

static void prover_thread_state_cleanup(ProverThreadState *st) {
  if (!st)
    return;

  if (st->ctx_chal)
    EVP_MD_CTX_free(st->ctx_chal);
  if (st->ctx_hash)
    EVP_MD_CTX_free(st->ctx_hash);

  if (st->bufWrite) {
    free(st->bufWrite);
  }

  if (st->views_block) {
    OPENSSL_cleanse(st->views_block, 3u * sizeof(View));
    free(st->views_block);
  }

  if (st->rand_block) {
    OPENSSL_cleanse(st->rand_block, 3u * RAND_BYTES);
    free(st->rand_block);
  }

  // Wipe stack-resident shares as well (optional)
  OPENSSL_cleanse(st->rShares, sizeof(st->rShares));
  OPENSSL_cleanse(st->msgShares, sizeof(st->msgShares));

  // Reset to a known state
  memset(st, 0, sizeof(*st));
}

static int prover_thread_state_init(ProverThreadState *st, size_t bufSize) {
  if (!st)
    return -1;
  memset(st, 0, sizeof(*st));

  st->bufSize = bufSize;

  // Allocate randomness block and set pointers
  st->rand_block = (uint8_t *)malloc(3u * RAND_BYTES);
  if (!st->rand_block)
    goto fail;
  st->randomness[0] = st->rand_block;
  st->randomness[1] = st->rand_block + RAND_BYTES;
  st->randomness[2] = st->rand_block + 2u * RAND_BYTES;

  // Allocate views block and set pointers
  st->views_block = (View *)malloc(3u * sizeof(View));
  if (!st->views_block)
    goto fail;
  st->views[0] = st->views_block;
  st->views[1] = st->views_block + 1;
  st->views[2] = st->views_block + 2;

  // Allocate write buffer (one per thread)
  st->bufWrite = (unsigned char *)malloc(bufSize);
  if (!st->bufWrite)
    goto fail;

  // Create contexts
  st->ctx_chal = EVP_MD_CTX_new();
  if (!st->ctx_chal)
    goto fail;

  st->ctx_hash = setupSHA256();
  if (!st->ctx_hash)
    goto fail;

  // Init shares to known values (not strictly necessary, but helps MSan/ASan)
  memset(st->rShares, 0, sizeof(st->rShares));
  memset(st->msgShares, 0, sizeof(st->msgShares));

  return 0;

fail:
  prover_thread_state_cleanup(st);
  return -1;
}

int main(void) {
  init();

  uint8_t rBytes[L_BYTES];
  uint8_t msg[MSG_WORDS * 4]; // 32-bit alligned

  RAND_bytes_no_fail(rBytes,
                     sizeof(rBytes)); // take random r in {0,1}^L
                
  RAND_bytes_no_fail(msg, MSG_BYTES); // take a random MSG
  if (MSG_BITS % 8 != 0) {            // clear highest bits if needed
    msg[MSG_BYTES - 1] &= (1 << MSG_BITS % 8) - 1;
  }

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
    LOG_ERRF("Unable to open file!");
    exit(EXIT_FAILURE);
  }
  serialize_universal_hash(file, keyH, &h);

  atomic_int error = 0;

  EVP_MD_CTX *base_ctx = setupSHA256();
  EVP_DigestUpdate(base_ctx, h.A, sizeof(h.A));
  EVP_DigestUpdate(base_ctx, h.b, sizeof(h.b));

  size_t buffSize = sizeof(a) + sizeof(z_disk);
#pragma omp parallel
  {
    ProverThreadState st;
    if (prover_thread_state_init(&st, buffSize) != 0) {
      LOG_ERRF("Thread init failed (malloc/ctx).");
      atomic_store(&error, 1);
    }

#pragma omp for
    for (int k = 0; k < NUM_ROUNDS; k++) {
      if (atomic_load(&error))
        continue;

      // Sharing secrets
      share_secrets(st.rShares, st.msgShares, rBytes, msg);
      // Generating randomness i.e., random tapes
      generate_randomness(keys[k], st.randomness);

      // Running HM commitment
      a a;
      z z;
      mpc_halevi_micali_prover(st.views, &a, st.randomness, rs[k], &h,
                               st.rShares, st.msgShares);
      // Committing
      hash_views(st.ctx_hash, keys[k], rs[k], st.views, &a);
      // Generating challenge (determines which 2 of the 3 views must be
      // opened).
      int e;
      EVP_MD_CTX_copy_ex(st.ctx_chal, base_ctx);
      generate_challenge(&a, &e, st.ctx_chal);

      z = prove(e, keys[k], rs[k], st.views);

      if (serialize_zk_proof_at(file, st.bufWrite, buffSize, k, &a, &z) != 0) {
        atomic_store(&error, 1);
        LOG_ERRF("Failed to serialize zk proof!\n");
      }
    }

    // Release thread state
    prover_thread_state_cleanup(&st);
  }

  update_clock(begin, &inMilli);
  fclose(file);
  EVP_MD_CTX_free(base_ctx);
  print_runtime(outputFile);

  if (error) {
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}

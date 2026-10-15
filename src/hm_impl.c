#include "hm.h"
#include "hm_buffer.h"
#include "mpc_core_funcs.h"
#include "mpc_halevi_micali.h"
#include "mpc_universal_hash.h"
#include "omp.h"
#include "prg.h"
#include "random_oracle.h"
#include "shared.h"
#include "thread_state.h"
#include "utils.h"
#include <limits.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

// TODO: consider adjusting this value
#define MAX_MSG_BITLEN 10000000

static inline int test_randomness() {
  uint8_t garbage[4];
  if (RAND_bytes(garbage, 4) != 1) {
    LOG_ERRF("RAND_bytes failed crypto, aborting\n");
    return -1;
  }
  return 0;
}

typedef struct {
  size_t message_byte_len;
  size_t l_bits;
  size_t opening_len;
  size_t l_words;
  size_t toeplitz_matrix_bit_len;
  size_t toeplitz_matrix_len;
  size_t toeplitz_matrix_words;
  size_t commitment_len;
} HmCommitLayout;

struct hm_context_t {
  size_t message_bit_len;
  HmCommitLayout layout;
  uint32_t *A;
  uint32_t *r_words;
};

static inline size_t ceil_div_size(size_t value, size_t divisor) {
  return value / divisor + (value % divisor != 0);
}

static int compute_sizes(size_t message_bit_len, HmCommitLayout *layout) {
  if (message_bit_len == 0 || message_bit_len > MAX_MSG_BITLEN) {
    return -1;
  }

  layout->message_byte_len = ceil_div_size(message_bit_len, 8u);
  layout->l_bits = 4u * (size_t)K + 2u * message_bit_len + 4u;
  layout->opening_len = ceil_div_size(layout->l_bits, 8u);
  layout->l_words = ceil_div_size(layout->l_bits, 32u);
  layout->toeplitz_matrix_bit_len = layout->l_bits + message_bit_len - 1u;
  layout->toeplitz_matrix_len =
      ceil_div_size(layout->toeplitz_matrix_bit_len, 8u);

  // Word windows read one extra word
  size_t max_base_word = (message_bit_len - 1u) / 32u;
  layout->toeplitz_matrix_words = max_base_word + layout->l_words + 1u;
  layout->commitment_len = layout->message_byte_len + SHA256_DIGEST_LENGTH;
  return 0;
}

static inline uint8_t last_byte_mask(size_t bit_len) {
  size_t used_bits = bit_len % 8u;
  return used_bits == 0u ? UINT8_MAX : (uint8_t)((1u << used_bits) - 1u);
}

int hm_commit_get_sizes(size_t message_bit_len, hm_commit_sizes_t *sizes_out) {
  if (!sizes_out) {
    LOG_ERRF("invalid output pointer\n");
    return -1;
  }
  *sizes_out = (hm_commit_sizes_t){0};
  HmCommitLayout layout;
  if (compute_sizes(message_bit_len, &layout) != 0) {
    LOG_ERRF("invalid message bit length\n");
    return -1;
  }
  sizes_out->commitment_len = layout.commitment_len;
  sizes_out->opening_len = layout.opening_len;
  sizes_out->toeplitz_matrix_len = layout.toeplitz_matrix_len;
  return 0;
}

void hm_context_free(hm_context_t *ctx) {
  if (ctx) {
    if (ctx->r_words) {
      OPENSSL_clear_free(ctx->r_words, ctx->layout.l_words * sizeof(uint32_t));
    }
    free(ctx->A);
    free(ctx);
  }
}

static int context_allocate(size_t message_bit_len, hm_context_t **ctx_out) {
  if (!ctx_out) {
    LOG_ERRF("invalid output pointer\n");
    return -1;
  }
  *ctx_out = NULL;
  HmCommitLayout layout;
  if (compute_sizes(message_bit_len, &layout) != 0) {
    LOG_ERRF("invalid message bit length\n");
    return -1;
  }
  hm_context_t *ctx = calloc(1, sizeof(*ctx));
  if (!ctx) {
    LOG_ERRF("allocation failure\n");
    return -1;
  }
  ctx->message_bit_len = message_bit_len;
  ctx->layout = layout;
  ctx->A = calloc(layout.toeplitz_matrix_words, sizeof(uint32_t));
  ctx->r_words = OPENSSL_zalloc(layout.l_words * sizeof(uint32_t));
  if (!ctx->A || !ctx->r_words) {
    LOG_ERRF("allocation failure\n");
    hm_context_free(ctx);
    return -1;
  }
  *ctx_out = ctx;
  return 0;
}

int hm_context_create(size_t message_bit_len, hm_context_t **ctx_out) {
  if (context_allocate(message_bit_len, ctx_out) != 0) {
    return -1;
  }
  hm_context_t *ctx = *ctx_out;
  // The repository targets little-endian hosts, so word storage is also the
  // canonical byte encoding. Sample the full diagonal description once.
  uint8_t *matrix = (uint8_t *)ctx->A;
  if (RAND_bytes(matrix, (int)ctx->layout.toeplitz_matrix_len) != 1) {
    LOG_ERRF("RAND_bytes failure\n");
    hm_context_free(ctx);
    *ctx_out = NULL;
    return -1;
  }
  matrix[ctx->layout.toeplitz_matrix_len - 1u] &=
      last_byte_mask(ctx->layout.toeplitz_matrix_bit_len);
  return 0;
}

int hm_context_from_matrix(size_t message_bit_len, const uint8_t *matrix,
                           size_t matrix_len, hm_context_t **ctx_out) {
  if (!ctx_out) {
    LOG_ERRF("invalid output pointer\n");
    return -1;
  }
  *ctx_out = NULL;
  HmCommitLayout layout;
  if (!matrix || compute_sizes(message_bit_len, &layout) != 0 ||
      matrix_len != layout.toeplitz_matrix_len) {
    LOG_ERRF("invalid inputs or sizes\n");
    return -1;
  }
  if (matrix[matrix_len - 1u] &
      ~last_byte_mask(layout.toeplitz_matrix_bit_len)) {
    LOG_ERRF("non-canonical matrix description\n");
    return -1;
  }
  if (context_allocate(message_bit_len, ctx_out) != 0) {
    return -1;
  }
  memcpy((*ctx_out)->A, matrix, matrix_len);
  return 0;
}

int hm_context_export_matrix(const hm_context_t *ctx, uint8_t *matrix_out,
                             size_t matrix_capacity) {
  if (!ctx || !matrix_out ||
      matrix_capacity < ctx->layout.toeplitz_matrix_len) {
    LOG_ERRF("invalid inputs or sizes\n");
    return -1;
  }
  memcpy(matrix_out, ctx->A, ctx->layout.toeplitz_matrix_len);
  return 0;
}

int hm_commit(hm_context_t *ctx, const uint8_t *message, uint8_t *commitment,
              size_t commitment_capacity, uint8_t *opening,
              size_t opening_capacity) {
  if (!ctx || !message || !commitment || !opening) {
    LOG_ERRF("invalid inputs\n");
    return -1;
  }
  if (commitment_capacity < ctx->layout.commitment_len ||
      opening_capacity < ctx->layout.opening_len) {
    LOG_ERRF("invalid input sizes\n");
    return -1;
  }
  const HmCommitLayout *layout = &ctx->layout;
  uint8_t *r = (uint8_t *)ctx->r_words;
  if (RAND_bytes(r, (int)layout->opening_len) != 1) {
    LOG_ERRF("RAND_bytes failure\n");
    return -1;
  }
  r[layout->opening_len - 1u] &= last_byte_mask(layout->l_bits);
  // Remaining bytes in the padded last word stay zero between calls.
  memcpy(opening, r, layout->opening_len);
  universal_hash_compute_b(commitment, ctx->A, ctx->r_words, layout->l_words,
                           message, ctx->message_bit_len);
  if (!SHA256(r, layout->opening_len, commitment + layout->message_byte_len)) {
    LOG_ERRF("SHA256 failure\n");
    return -1;
  }
  return 0;
}

int hm_verify(hm_context_t *ctx, const uint8_t *message,
              const uint8_t *commitment, size_t commitment_len,
              const uint8_t *opening, size_t opening_len) {
  if (!ctx || !message || !commitment || !opening) {
    LOG_ERRF("invalid inputs\n");
    return -1;
  }
  if (commitment_len != ctx->layout.commitment_len ||
      opening_len != ctx->layout.opening_len) {
    LOG_ERRF("invalid input sizes\n");
    return -1;
  }
  const HmCommitLayout *layout = &ctx->layout;
  if ((opening[opening_len - 1u] & ~last_byte_mask(layout->l_bits)) ||
      (commitment[layout->message_byte_len - 1u] &
       ~last_byte_mask(ctx->message_bit_len))) {
    LOG_ERRF("non-canonical commitment or opening\n");
    return -1;
  }
  uint8_t digest[SHA256_DIGEST_LENGTH];
  if (!SHA256(opening, opening_len, digest) ||
      memcmp(commitment + layout->message_byte_len, digest, sizeof(digest)) !=
          0) {
    LOG_ERRF("verification failed\n");
    return -1;
  }
  memcpy(ctx->r_words, opening, opening_len);
  int ret = universal_hash_verify_message(message, ctx->message_bit_len,
                                          commitment, ctx->A, ctx->r_words,
                                          layout->l_words);
  if (ret != 0) {
    LOG_ERRF("verification failed\n");
  }
  return ret;
}

static inline void pick_universal_hash(UniversalHash *h, const uint8_t keyA[16],
                                       const RVec *r,
                                       const uint8_t msg[MSG_BYTES]) {
  generate_H(h->A, h->b, keyA, msg, r);
}

static inline void hash_views(EVP_MD_CTX *ctx, uint8_t keys[3][16],
                              uint8_t rs[3][4], View *localViews[3],
                              ZkBooCommit *as) {
  uint8_t hash1[SHA256_DIGEST_LENGTH];
  HH(ctx, keys[0], localViews[0], rs[0], hash1);
  memcpy(as->h[0], &hash1, 32);
  HH(ctx, keys[1], localViews[1], rs[1], hash1);
  memcpy(as->h[1], &hash1, 32);
  HH(ctx, keys[2], localViews[2], rs[2], hash1);
  memcpy(as->h[2], &hash1, 32);
}

int hm_bit_commit(uint8_t bit, const char *proof_file_path,
                  hm_buffer_t *commitment_out, hm_buffer_t *opening_out) {
  FILE *file = NULL;
  EVP_MD_CTX *base_ctx = NULL;

  if (test_randomness() != 0) {
    return -1;
  }

  uint8_t msg[MSG_WORDS * 4] = {0}; // 32-bit alligned
  msg[0] ^= (bit & 1);

  RVec r;
  if (RAND_bytes((uint8_t *)r.words, sizeof(r.words)) !=
      1) { // take random r in {0,1}^L
    goto cleanup;
  }
  rvec_normalize(&r);

  /*
   * Return the HM opening randomness r to the caller.
   */
  if (hm_buffer_copy(opening_out, rvec_const_bytes(&r), L_BYTES) != 0) {
    LOG_ERRF("Could not copy opening into output buffer");
    goto cleanup;
  }

  uint8_t rs[NUM_ROUNDS][3][4]; // randomness internal commitments to views
  uint8_t keys[NUM_ROUNDS][3]
              [16]; // PRG keys to generate randomness for MPC protocol
  uint8_t keyH[16]; // key to generate universal hash function

  // Generating keys
  generate_keys_and_rs(keys, keyH, rs);

  // Generate halevi-micali commitment
  UniversalHash h;
  pick_universal_hash(&h, keyH, &r, msg); // pick universal hash function
  if (write_hm_commitment(commitment_out, keyH, &h, &r) != 0) {
    goto cleanup;
  }

  // Open proof file
  file = fopen(proof_file_path, "wb");
  if (!file) {
    goto cleanup;
  }

  // Initialise shared context
  base_ctx = setupSHA256();
  EVP_DigestUpdate(base_ctx, h.A, sizeof(h.A));
  EVP_DigestUpdate(base_ctx, h.b, sizeof(h.b));

  size_t buffSize = sizeof(ZkBooCommit) + sizeof(ZkBooOpenDisk);

  atomic_int error = 0;
#pragma omp parallel
  {
    ProverThreadState st;
    if (prover_thread_state_init(&st, buffSize) != 0) {
      LOG_ERRF("Thread init failed (malloc/ctx).");
      atomic_store(&error, 1);
    }

#pragma omp for
    for (int k = 0; k < NUM_ROUNDS; k++) {
      if (atomic_load(&error)) {
        continue;
      }

      // Sharing secrets
      share_secrets(st.rShares, st.msgShares, &r, msg);
      // Generating randomness i.e., random tapes
      generate_randomness(keys[k], st.randomness);

      // Running HM commitment
      ZkBooCommit a;
      mpc_hm_prove(st.views, &a, st.randomness, rs[k], &h, st.rShares,
                   st.msgShares);
      // Committing
      hash_views(st.ctx_hash, keys[k], rs[k], st.views, &a);

      // Generating challenge (determines which 2 of the 3 views must be
      // opened).
      int e;
      EVP_MD_CTX_copy_ex(st.ctx_chal, base_ctx);
      generate_challenge(st.ctx_chal, &e, &a, y_const_bytes(commitment_out));

      // Generate opening
      ZkBooOpen z;
      open(&z, e, keys[k], rs[k], st.views);

      // Write zk proof
      if (serialize_zk_proof_at(file, st.bufWrite, buffSize, k, &a, &z) != 0) {
        atomic_store(&error, 1);
        LOG_ERRF("Failed to serialize zk proof!\n");
      }
    }

    // Release thread state
    prover_thread_state_cleanup(&st);
  }

  EVP_MD_CTX_free(base_ctx);
  fclose(file);

  return error ? -1 : 0;

cleanup:
  if (file) {
    fclose(file);
  }

  if (base_ctx) {
    EVP_MD_CTX_free(base_ctx);
  }

  hm_buffer_free(commitment_out);
  hm_buffer_free(opening_out);

  return -1;
}

int hm_bit_verify(const uint8_t *commitment, size_t commitment_len,
                  const char *proof_file_path) {

  if (test_randomness() != 0) {
    return -1;
  }

  if (!commitment || commitment_len == 0 || !proof_file_path) {
    return -1;
  }

  FILE *file = fopen(proof_file_path, "rb");
  if (!file) {
    LOG_ERRF("Unable to open proof file!");
    goto fail;
  }

  UniversalHash h;
  uint8_t y[SHA256_DIGEST_LENGTH];
  if (read_hm_commitment(commitment, commitment_len, &h, y) != 0) {
    LOG_ERRF("Cannot read commitment");
    goto fail;
  }

  // Expend universal hash from key
  expand_A(h.A, A_WORDS, h.keyA);

  // Setup hash context
  EVP_MD_CTX *base_ctx = setupSHA256();
  EVP_DigestUpdate(base_ctx, h.A, sizeof(h.A));
  EVP_DigestUpdate(base_ctx, h.b, sizeof(h.b));

  atomic_int error = 0;
#pragma omp parallel
  {
    // Init thread state
    VerifierThreadState st;
    ssize_t bufSize =
        sizeof(ZkBooCommit) + sizeof(ZkBooOpen) + 2 * sizeof(View);
    if (verifier_thread_state_init(&st, bufSize) != 0) {
      LOG_ERRF("Thread init failed (malloc/ctx).");
      atomic_store(&error, 1);
    }

    // Pack into one contiguous buffer to write once

#pragma omp for
    for (int k = 0; k < NUM_ROUNDS; k++) {
      if (atomic_load(&error)) {
        continue;
      }

      if (read_zk_proof_at(file, st.bufWrite, bufSize, k, &st.a, &st.z) != 0) {
        atomic_store(&error, 1);
      }

      int e;
      EVP_MD_CTX_copy_ex(st.ctx_chal, base_ctx);
      H3(st.ctx_chal, y, &st.a, 1, &e);
      if (mpc_hm_verify(&h, &st.a, &st.z, y, e) != 0) {
        LOG_ERRF("Repetition #%d failed to verify!", k);
        atomic_store(&error, 1);
      }
    }

    // Clear state
    verifier_thread_state_cleanup(&st);
  }

  if (base_ctx)
    EVP_MD_CTX_free(base_ctx);
  fclose(file);
  return (error) ? -1 : 0;

fail:
  if (file)
    fclose(file);
  return -1;
}

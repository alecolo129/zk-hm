#include "hm_zk.h"
#include "hm_buffer.h"
#include "hm_zk_io.h"
#include "mpc_core_funcs.h"
#include "mpc_halevi_micali.h"
#include "mpc_universal_hash.h"
#include "prg.h"
#include "random_oracle.h"
#include "thread_state.h"
#include <stdatomic.h>
#include <stdio.h>

static inline int test_randomness() {
  uint8_t garbage[4];
  if (RAND_bytes(garbage, 4) != 1) {
    LOG_ERRF("RAND_bytes failed crypto, aborting\n");
    return -1;
  }
  return 0;
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
  mpc_hm_hash_init(h.A, h.b, keyH, msg, &r);
  if (hm_zk_write_commitment(commitment_out, keyH, &h, &r) != 0) {
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
      generate_challenge(st.ctx_chal, &e, &a,
                         hm_zk_commitment_digest(commitment_out));

      // Generate opening
      ZkBooOpen z;
      open(&z, e, keys[k], rs[k], st.views);

      // Write zk proof
      if (hm_zk_write_proof_round(file, st.bufWrite, buffSize, k, &a, &z) !=
          0) {
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
  if (hm_zk_read_commitment(commitment, commitment_len, &h, y) != 0) {
    LOG_ERRF("Cannot read commitment");
    goto fail;
  }

  // Expend universal hash from key
  mpc_hm_expand_matrix(h.A, A_WORDS, h.keyA);

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

      if (hm_zk_read_proof_round(file, st.bufWrite, bufSize, k, &st.a, &st.z) !=
          0) {
        atomic_store(&error, 1);
        continue;
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

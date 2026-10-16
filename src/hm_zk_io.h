#pragma once
#include "hm_zk.h"
#include "shared.h"
#include <stdio.h>

/* ZK commitments encode the seed, masked message, and opening digest.
 * Plain commitments have a separate format and never use these helpers. */
int hm_zk_read_commitment(const uint8_t *commitment, size_t commitment_len,
                          UniversalHash *h, uint8_t y[SHA256_DIGEST_LENGTH]);
int hm_zk_write_commitment(hm_buffer_t *commitment_out, const uint8_t keyH[16],
                           const UniversalHash *h, const RVec *r);
const uint8_t *hm_zk_commitment_digest(const hm_buffer_t *commitment);

/* Proof records are read/written at fixed round offsets for parallel I/O. */
int hm_zk_write_proof_round(FILE *f, unsigned char *buf, size_t buf_size,
                            int round, const ZkBooCommit *a,
                            const ZkBooOpen *z);
int hm_zk_read_proof_round(FILE *f, unsigned char *buf, size_t buf_size,
                           int round, ZkBooCommit *a, ZkBooOpen *z);

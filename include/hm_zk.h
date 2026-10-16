#pragma once
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Byte buffers owned by the library.
 *
 * The caller must release buffers using hm_buffer_free(). Plain commitments
 * use caller-owned buffers instead.
 */
typedef struct hm_buffer_t {
  uint8_t *data;
  size_t len;
} hm_buffer_t;

/**
 * Free any buffer allocated by the library.
 */
void hm_buffer_free(hm_buffer_t *buf);

/**
 * Commit to a bit and produce a ZK proof of knowledge of an opening.
 *
 * @param[in] bit                 The bit to commit. Must be 0 or 1.
 * @param[in] proof_file_path     The path where the MPCitH ZK proof will be
 * written
 * @param[out] commitment_out     The Halevi-Micali commitment
 * @param[out] opening_out        The Halevi-Micali opening
 *
 * @return Returns 0 if the proof was computed successfully, nonzero value
 * indicates failure.
 *
 * Note: the zk-proof itself is not returned in memory because it weighs
 * several MB.
 */
int hm_bit_commit(uint8_t bit, const char *proof_file_path,
                  hm_buffer_t *commitment_out, hm_buffer_t *opening_out);

/**
 * Verify a ZK proof of knowledge of an opening for the commitment.
 * The message and opening are not supplied to this function.
 *
 * @param[in] commitment          The Halevi-Micali commitment
 * @param[in] commitment_len      The length of Halevi-Micali commitment, in
 * bytes.
 * @param[in] proof_file_path     The path to the MPCitH ZK proof to read
 *
 * @return Returns 0 if verification executed successfully, or
 * a non-zero value indicating an error or an invalid proof.
 */
int hm_bit_verify(const uint8_t *commitment, size_t commitment_len,
                  const char *proof_file_path);

#ifdef __cplusplus
}
#endif

#pragma once
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif


/*
 * Byte buffers owned by the library.
 *
 * The caller must release buffers using hm_buffer_free().
 * TODO: specialize for bit commitment
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
 * Commit to a bit.
 *
 * @param[in] bit                 The bit to commit. Must be 0 or 1.
 * @param[in] proof_file_path     The path where the MPCitH ZK proof will be written
 * @param[out] commitment_out     The Halevi-Micali commitment
 * @param[out] opening_out        The Halevi-Micali opening
 *
 * @return Returns 0 if the proof was computed successfully, nonzero value indicates failure.
 *
 * Note: the zk-proof itself is not returned in memory because it weights
 * several MB.
 */
int hm_bit_commit(uint8_t bit, const char *proof_file_path,
                  hm_buffer_t *commitment_out, hm_buffer_t *opening_out);

/**
 * Verify that the MPCiTH ZK proof file is valid for the commitment.
 *
 * @param[in] commitment          The Halevi-Micali commitment
 * @param[in] commitment_len      The length of Halevi-Micali commitment, in bytes.
 * @param[in] proof_file_path     The Path where the MPCitH ZK proof will be written
 *
 * @return Returns 0 if verification executed successfully, or 
 * a non-zero value indicating an error or an invalid proof.
 */
int hm_bit_verify(const uint8_t *commitment, size_t commitment_len,
                  const char *proof_file_path);

/**
 * Open the Halevi-Micali commitment for a given input bit.
 *
 * @param[in] bit                 The bit to open
 * @param[in] commitment          The Halevi-Micali commitment
 * @param[in] commitment_len      The length of Halevi-Micali commitment, in bytes.
 * @param[in] opening             The Halevi-Micali opening
 * @param[in] opening_len         The length of Halevi-Micali opening, in bytes.
 *
 * @return Returns 0 if the bit was successfully openened, or 
 * a non-zero value indicating an error or invalid opening.
 */
int hm_bit_open(uint8_t bit, const uint8_t *commitment, size_t commitment_len,
                const uint8_t *opening, size_t opening_len);

#ifdef __cplusplus
}
#endif

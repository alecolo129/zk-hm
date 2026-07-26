#pragma once
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Required output sizes for a plain Halevi-Micali commitment.
 *
 * A plain commitment contains the complete uniformly sampled Toeplitz matrix
 * description, and the SHA-256 digest of the opening.
 */
typedef struct hm_commit_sizes_t {
  size_t commitment_len;
  size_t opening_len;
} hm_commit_sizes_t;

/**
 * Compute the output sizes required to commit to a bit string.
 *
 * @param[in] message_bit_len     The number of message bits to commit
 * @param[out] sizes_out          The required commitment and opening sizes
 *
 * @return Returns 0 if the sizes were computed successfully, or a non-zero
 * value if the input is invalid or the message length exceeds the maximum supported length.
 */
int hm_commit_get_sizes(size_t message_bit_len,
                        hm_commit_sizes_t *sizes_out);

/**
 * Commit to an arbitrary-length bit string using caller-owned output buffers.
 *
 * @param[in] message             The message bits. Bits are read LSB-first
 * @param[in] message_bit_len     The number of message bits to commit
 * @param[out] commitment         The buffer receiving the commitment
 * @param[in] commitment_capacity The vailable bytes in commitment buffer
 * @param[out] opening            The buffer receiving the opening
 * @param[in] opening_capacity    The available bytes in opening buffer
 *
 * @return Returns 0 if the commitment was computed successfully, nonzero value
 * indicates failure. On success, exactly the sizes returned by hm_commit_get_sizes()
 * are written. The library never frees the supplied buffers. The message, commitment,
 * and opening memory regions must not overlap.
 */
int hm_commit(const uint8_t *message, size_t message_bit_len,
              uint8_t *commitment, size_t commitment_capacity,
              uint8_t *opening, size_t opening_capacity);

/**
 * Verifies the commitment against the input bit string and opening.
 *
 * @param[in] message             The message bits. Bits are read LSB-first
 * @param[in] message_bit_len     The number of message bits to verify
 * @param[in] commitment          The Halevi-Micali commitment
 * @param[in] commitment_len      The length of Halevi-Micali commitment, in bytes
 * @param[in] opening             The Halevi-Micali opening
 * @param[in] opening_len         The length of Halevi-Micali opening, in bytes
 *
 * @return Returns 0 if the message was successfully verified, or a non-zero
 * value indicating an error or failed verification.
 */
int hm_verify(const uint8_t *message, size_t message_bit_len,
            const uint8_t *commitment, size_t commitment_len,
            const uint8_t *opening, size_t opening_len);




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
 * Commit to a bit producing a zk proof of pre-image knowledge.
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

#ifdef __cplusplus
}
#endif

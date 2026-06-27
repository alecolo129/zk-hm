#include "hm.h"

#include <stdint.h>
#include <stdio.h>

int main(void) {
  const uint8_t bit = 1;
  const char *proof_path = "hm_c_example_proof.bin";

  hm_buffer_t commitment = {0};
  hm_buffer_t opening = {0};
  int ret = 1;

  if (hm_bit_commit(bit, proof_path, &commitment, &opening) != 0) {
    fprintf(stderr, "hm_bit_commit failed\n");
    goto cleanup;
  }

  printf("Committed to bit %u\n", (unsigned)bit);
  printf("commitment: %zu bytes\n", commitment.len);
  printf("opening: %zu bytes\n", opening.len);

  if (hm_bit_verify(commitment.data, commitment.len, proof_path) != 0) {
    fprintf(stderr, "hm_bit_verify failed\n");
    goto cleanup;
  }

  if (hm_bit_open(bit, commitment.data, commitment.len, opening.data,
                  opening.len) != 0) {
    fprintf(stderr, "hm_bit_open failed\n");
    goto cleanup;
  }

  printf("Proof verified and commitment opened successfully\n");
  ret = 0;

cleanup:
  hm_buffer_free(&commitment);
  hm_buffer_free(&opening);
  remove(proof_path);
  return ret;
}

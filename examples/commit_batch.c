#include "hm.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

enum { COMMITMENT_COUNT = 100 };

int main(void) {
  const size_t message_bit_len = 2;
  uint8_t messages[COMMITMENT_COUNT];
  hm_commit_sizes_t sizes = {0};
  uint8_t *commitments = NULL;
  uint8_t *openings = NULL;
  int ret = 1;

  for (size_t i = 0; i < COMMITMENT_COUNT; i++) {
    messages[i] = (uint8_t)(i & 0x03u);
  }

  if (hm_commit_get_sizes(message_bit_len, &sizes) != 0) {
    fprintf(stderr, "hm_commit_get_sizes failed\n");
    goto cleanup;
  }

  const size_t commitments_len = COMMITMENT_COUNT * sizes.commitment_len;
  const size_t openings_len = COMMITMENT_COUNT * sizes.opening_len;
  commitments = malloc(commitments_len);
  openings = malloc(openings_len);
  if (!commitments || !openings) {
    fprintf(stderr, "allocation failed\n");
    goto cleanup;
  }

  for (size_t i = 0; i < COMMITMENT_COUNT; i++) {
    uint8_t *commitment = commitments + i * sizes.commitment_len;
    uint8_t *opening = openings + i * sizes.opening_len;

    if (hm_commit(&messages[i], message_bit_len, commitment,
                  sizes.commitment_len, opening, sizes.opening_len) != 0) {
      fprintf(stderr, "hm_commit failed at index %zu\n", i);
      goto cleanup;
    }
  }

  for (size_t i = 0; i < COMMITMENT_COUNT; i++) {
    const uint8_t *commitment = commitments + i * sizes.commitment_len;
    const uint8_t *opening = openings + i * sizes.opening_len;

    if (hm_verify(&messages[i], message_bit_len, commitment,
                  sizes.commitment_len, opening, sizes.opening_len) != 0) {
      fprintf(stderr, "hm_verify failed at index %zu\n", i);
      goto cleanup;
    }
  }

  printf("Created and verified %d 2-bit commitments\n", COMMITMENT_COUNT);
  printf("commitments: %zu bytes\n", commitments_len);
  printf("openings: %zu bytes\n", openings_len);
  ret = 0;

cleanup:
  free(commitments);
  free(openings);
  return ret;
}

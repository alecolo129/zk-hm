#include "hm.h"

#include <stdint.h>
#include <stdio.h>

void print_bits_mask(int n) {
    unsigned int mask = 1 << (sizeof(int) * 8 - 1);
    for (int i = 0; i < sizeof(int) * 8; i++) {
        printf("%d", (n & mask) ? 1 : 0);
        mask >>= 1;
    }
    printf("\n");
}

int main(void) {
  // commit to msg 0b11 (little-endian)
  const uint8_t msg = 0x03;
  const ssize_t msg_bit_len = 2;

  hm_buffer_t commitment = {0};
  hm_buffer_t opening = {0};
  int ret = 1;

  if (hm_commit(&msg, msg_bit_len, &commitment, &opening) != 0) {
    fprintf(stderr, "hm_commit failed\n");
    goto cleanup;
  }

  printf("Committed to msg %x\n", msg);
  printf("commitment: %zu bytes\n", commitment.len);
  printf("opening: %zu bytes\n", opening.len);

  if (hm_verify(&msg, msg_bit_len, commitment.data, commitment.len, opening.data,
                  opening.len) != 0) {
    fprintf(stderr, "hm_verify failed\n");
    goto cleanup;
  }

  printf("Commitment verified successfully\n");
  ret = 0;

cleanup:
  hm_buffer_free(&commitment);
  hm_buffer_free(&opening);
  return ret;
}

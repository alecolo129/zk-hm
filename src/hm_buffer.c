#include "hm.h"
#include "shared.h"
#include <stdlib.h>
#include "string.h"

void hm_buffer_free(hm_buffer_t *buf) {
  if (!buf) {
    return;
  }

  free(buf->data);
  buf->data = NULL;
  buf->len = 0;
}

int hm_buffer_copy(hm_buffer_t *out, const uint8_t *src,
                                 size_t src_len) {
  if (!out || (!src && src_len != 0)) {
    LOG_ERRF("Invalid input/output pointers");
    return -1;
  }

  out->data = NULL;
  out->len = 0;

  if (src_len == 0) {
    return 0;
  }

  out->data = malloc(src_len);
  if (!out->data) {
    LOG_ERRF("malloc failure");
    return -1;
  }

  memcpy(out->data, src, src_len);
  out->len = src_len;

  return 0;
}
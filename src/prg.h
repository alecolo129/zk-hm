#pragma once
#include <openssl/evp.h>
#include <shared.h>

/* A 128 bit IV for randomness generation */
static const unsigned char iv[17] = "0123456789012345";

EVP_CIPHER_CTX *setupAES(const unsigned char key[16]);

void getAllRandomness(unsigned char key[16],
                      unsigned char randomness[RAND_BYTES]);

static inline void generate_randomness(unsigned char keys[3][16],
                                       unsigned char *randomness[3]) {
  for (int j = 0; j < 3; j++) {
    // Note: In the MPC protocol we need 32 bit of randomness for each ADD/AND
    // operation in SHA256 (operates on 32bit words). We have 64 AND gates and
    // 664 ADD gates, so we need 728 * 32 / 8 = 2912 bytes of randomness.
    getAllRandomness(keys[j], randomness[j]);
  }
}

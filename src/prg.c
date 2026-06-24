#include "prg.h"
#include "string.h"

EVP_CIPHER_CTX *setupAES(const unsigned char key[16]) {
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (ctx == NULL)
    handleErrors();

  if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv))
    handleErrors();

  return ctx;
}

void getAllRandomness(unsigned char key[16],
                      unsigned char randomness[RAND_BYTES]) {
  // Generate randomness: We use SHA256_ROUNDS * (728*32) = SHA256_ROUNDS * 2912
  // bit of randomness per key.

  EVP_CIPHER_CTX *ctx = setupAES(key);

  // TODO: define 4096 as AES chunk constant
  unsigned char plaintext[4096] = {0};
  size_t outlen = RAND_BYTES;
  while (outlen) {
    int chunk =
        (outlen > sizeof(plaintext)) ? (int)sizeof(plaintext) : (int)outlen;
    int produced = 0;
    if (1 != EVP_EncryptUpdate(ctx, randomness, &produced, plaintext, chunk)) {
      handleErrors();
    }
    randomness += produced;
    outlen -= (size_t)produced;
  }

  EVP_CIPHER_CTX_free(ctx);
}
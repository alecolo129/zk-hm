#include "crypto.h"

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

uint32_t getRandom32(unsigned char randomness[RAND_BYTES], int randCount) {
  uint32_t ret;
  memcpy(&ret, &randomness[randCount], 4);
  return ret;
}

EVP_MD_CTX *setupSHA256() {
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (ctx == NULL)
    handleErrors();

  if (1 != EVP_DigestInit_ex(ctx, EVP_sha256(), NULL))
    handleErrors();
  return ctx;
}

void MD(const unsigned char *r, uint32_t r_len,
        unsigned char hash[SHA256_DIGEST_LENGTH]) {
  SHA256(r, r_len, hash);
}

void H(unsigned char k[16], View *v, unsigned char r[4],
       unsigned char hash[SHA256_DIGEST_LENGTH]) {
  EVP_MD_CTX *ctx = setupSHA256();
  EVP_DigestUpdate(ctx, k, 16);
  EVP_DigestUpdate(ctx, v, sizeof(View));
  EVP_DigestUpdate(ctx, r, 4);
  uint32_t outlen = 0;
  EVP_DigestFinal_ex(ctx, hash, &outlen);
  EVP_MD_CTX_free(ctx);
}

void HH(EVP_MD_CTX *ctx, unsigned char k[16], View *v, unsigned char r[4],
        unsigned char hash[SHA256_DIGEST_LENGTH]) {
  EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
  EVP_DigestUpdate(ctx, k, 16);
  EVP_DigestUpdate(ctx, v, sizeof(View));
  EVP_DigestUpdate(ctx, r, 4);
  uint32_t outlen = 0;
  EVP_DigestFinal_ex(ctx, hash, &outlen);
}

void H3(EVP_MD_CTX *ctx, uint32_t y[8], a *as, int s, int *es) {
  unsigned char hash[SHA256_DIGEST_LENGTH];
  EVP_DigestUpdate(ctx, y, 32);
  EVP_DigestUpdate(ctx, as, sizeof(a) * s);
  uint32_t outlen = 0;
  EVP_DigestFinal_ex(ctx, hash, &outlen);

  // Pick bits from hash
  int i = 0;
  int bitTracker = 0;
  while (i < s) {
    if (bitTracker >=
        SHA256_DIGEST_LENGTH * 8) { // Generate new hash as we have run out of
                                    // bits in the previous hash
      EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
      EVP_DigestUpdate(ctx, hash, sizeof(hash));
      EVP_DigestFinal_ex(ctx, hash, &outlen);
      bitTracker = 0;
    }

    int b1 = GETBIT(hash[bitTracker / 8], bitTracker % 8);
    int b2 = GETBIT(hash[(bitTracker + 1) / 8], (bitTracker + 1) % 8);
    if (b1 == 0) {
      if (b2 == 0) {
        es[i] = 0;
        bitTracker += 2;
        i++;
      } else {
        es[i] = 1;
        bitTracker += 2;
        i++;
      }
    } else {
      if (b2 == 0) {
        es[i] = 2;
        bitTracker += 2;
        i++;
      } else {
        bitTracker += 2;
      }
    }
  }
}
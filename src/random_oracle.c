#include "random_oracle.h"
#include "string.h"

EVP_MD_CTX *setupSHA256() {
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (ctx == NULL)
    handleErrors();

  if (1 != EVP_DigestInit_ex(ctx, EVP_sha256(), NULL))
    handleErrors();
  return ctx;
}

void H(const unsigned char k[16], const View *v, const unsigned char r[4],
       unsigned char hash[SHA256_DIGEST_LENGTH]) {
  EVP_MD_CTX *ctx = setupSHA256();
  EVP_DigestUpdate(ctx, k, 16);
  EVP_DigestUpdate(ctx, v, sizeof(View));
  EVP_DigestUpdate(ctx, r, 4);
  uint32_t outlen = 0;
  EVP_DigestFinal_ex(ctx, hash, &outlen);
  EVP_MD_CTX_free(ctx);
}

void HH(EVP_MD_CTX *ctx, const unsigned char k[16], const View *v, const unsigned char r[4],
        unsigned char hash[SHA256_DIGEST_LENGTH]) {
  EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
  EVP_DigestUpdate(ctx, k, 16);
  EVP_DigestUpdate(ctx, v, sizeof(View));
  EVP_DigestUpdate(ctx, r, 4);
  uint32_t outlen = 0;
  EVP_DigestFinal_ex(ctx, hash, &outlen);
}

void H3(EVP_MD_CTX *ctx, const uint32_t y[8], const ZkBooCommit *as, int s, int *es) {
  unsigned char hash[SHA256_DIGEST_LENGTH];
  EVP_DigestUpdate(ctx, y, 32);
  EVP_DigestUpdate(ctx, as, sizeof(ZkBooCommit) * s);
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
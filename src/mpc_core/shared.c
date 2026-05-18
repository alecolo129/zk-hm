#include "shared.h"
#include "omp.h"
#include "openssl/sha.h"
#include <openssl/evp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <strings.h>

// void H2(unsigned char k[16], View2 v, unsigned char r[4],
//         unsigned char hash[SHA256_DIGEST_LENGTH]) {
//   EVP_MD_CTX *ctx = setupSHA256();
//   EVP_DigestUpdate(ctx, k, 16);
//   EVP_DigestUpdate(ctx, &v, sizeof(v));
//   EVP_DigestUpdate(ctx, r, 4);
//   uint32_t outlen = 0;
//   EVP_DigestFinal_ex(ctx, hash, &outlen);
//   EVP_MD_CTX_free(ctx);
// }

// void H3_2(uint32_t y[8], a2 *as, int s, int *es) {

//   unsigned char hash[SHA256_DIGEST_LENGTH];
//   EVP_MD_CTX *ctx = setupSHA256();
//   EVP_DigestUpdate(ctx, y, 32);
//   EVP_DigestUpdate(ctx, as, sizeof(a2) * s);
//   uint32_t outlen = 0;
//   EVP_DigestFinal_ex(ctx, hash, &outlen);

//   // Pick bits from hash
//   int i = 0;
//   int bitTracker = 0;
//   while (i < s) {
//     if (bitTracker >=
//         SHA256_DIGEST_LENGTH * 8) { // Generate new hash as we have run out of
//                                     // bits in the previous hash
//       EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
//       EVP_DigestUpdate(ctx, hash, sizeof(hash));
//       EVP_DigestFinal_ex(ctx, hash, &outlen);
//       bitTracker = 0;
//     }

//     int b1 = GETBIT(hash[bitTracker / 8], bitTracker % 8);
//     int b2 = GETBIT(hash[(bitTracker + 1) / 8], (bitTracker + 1) % 8);
//     if (b1 == 0) {
//       if (b2 == 0) {
//         es[i] = 0;
//         bitTracker += 2;
//         i++;
//       } else {
//         es[i] = 1;
//         bitTracker += 2;
//         i++;
//       }
//     } else {
//       if (b2 == 0) {
//         es[i] = 2;
//         bitTracker += 2;
//         i++;
//       } else {
//         bitTracker += 2;
//       }
//     }
//   }
//   EVP_MD_CTX_free(ctx);
// }
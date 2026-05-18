#ifndef __CRYPTO_H__
#define __CRYPTO_H__

#include <openssl/evp.h>
#include <shared.h>


/*
##############
PRG functions
##############
*/

EVP_CIPHER_CTX *setupAES(const unsigned char key[16]);
void getAllRandomness(unsigned char key[16],
                      unsigned char randomness[RAND_BYTES]);
void expand_A(uint32_t A[A_WORDS], const uint8_t keyA[16]);
uint32_t getRandom32(unsigned char randomness[RAND_BYTES], int randCount);

/*
##############
Hash functions
##############
*/

EVP_MD_CTX *setupSHA256();

void MD(const unsigned char *r, uint32_t r_len,
        unsigned char hash[SHA256_DIGEST_LENGTH]);

void H(unsigned char k[16], View *v, unsigned char r[4],
       unsigned char hash[SHA256_DIGEST_LENGTH]);

void HH(EVP_MD_CTX *ctx, unsigned char k[16], View *v, unsigned char r[4],
        unsigned char hash[SHA256_DIGEST_LENGTH]);

void H3(EVP_MD_CTX *ctx, uint32_t y[8], a *as, int s, int *es);

#endif

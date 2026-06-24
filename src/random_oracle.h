#pragma once
#include <openssl/evp.h>
#include <shared.h>

EVP_MD_CTX *setupSHA256();

void H(unsigned char k[16], View *v, unsigned char r[4],
       unsigned char hash[SHA256_DIGEST_LENGTH]);

void HH(EVP_MD_CTX *ctx, unsigned char k[16], View *v, unsigned char r[4],
        unsigned char hash[SHA256_DIGEST_LENGTH]);

void H3(EVP_MD_CTX *ctx, uint32_t y[8], ZkBooCommit *as, int s, int *es);

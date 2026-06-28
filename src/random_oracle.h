#pragma once
#include <openssl/evp.h>
#include <shared.h>

EVP_MD_CTX *setupSHA256();

void H(const unsigned char k[16], const View *v, const unsigned char r[4],
        unsigned char hash[SHA256_DIGEST_LENGTH]);

void HH(EVP_MD_CTX *ctx, const unsigned char k[16], const View *v, const unsigned char r[4],
        unsigned char hash[SHA256_DIGEST_LENGTH]);

void H3(EVP_MD_CTX *ctx, const uint32_t y[8], const ZkBooCommit *as, int s, int *es);

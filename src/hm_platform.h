#pragma once
#include <stdio.h>

#if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) &&             \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "Big-endian machines are currently not supported"
#endif

#ifdef VERBOSE
#define LOG_ERRF(fmt, ...)                                                     \
  do {                                                                         \
    flockfile(stderr);                                                         \
    fprintf(stderr, "%s:%d:%s(): " fmt "\n", __FILE_NAME__, __LINE__,          \
            __func__, ##__VA_ARGS__);                                          \
    fflush(stderr);                                                            \
    funlockfile(stderr);                                                       \
  } while (0)
#else
#define LOG_ERRF(fmt, ...)
#endif

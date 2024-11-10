#pragma once
#ifdef __cplusplus
extern "C" {
#endif
#include <stdint.h>
#include <stddef.h>


typedef enum {
	RNDCPPTYPE_NONE,
	RNDCPPTYPE_MINSTD,
	RNDCPPTYPE_MT19937,
	RNDCPPTYPE_RANLUX,
	RNDCPPTYPE_KNUTHB
} rnd_cpp_t;

size_t rnd_cpp_ctx_size (void);
size_t rnd_cpp_seed_size (void *ctx);
void rnd_cpp (void *ctx, uint8_t *buf, size_t len);
bool rnd_cpp_setopt (void *ctx, const void *opt);
void rnd_cpp_seed (void *ctx, const uint8_t *seed);
void rnd_cpp_deseed (void *ctx);

#ifdef __cplusplus
}
#endif

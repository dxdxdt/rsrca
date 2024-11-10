// The Well Equidistributed Long-period Linear PRNG 512a variant
// http://web.archive.org/web/20240118022029/http://www.iro.umontreal.ca/~panneton/well/WELL512a.c
#pragma once
#include <stdint.h>
#include <stddef.h>


typedef struct {
	uint32_t state[16];
	size_t index;
} rnd_well512_t;

size_t rnd_well512_ctx_size (void);
size_t rnd_well512_seed_size (rnd_well512_t *ctx);
void rnd_well512 (rnd_well512_t *ctx, uint8_t *buf, size_t len);
void rnd_well512_seed (rnd_well512_t *ctx, const uint8_t *seed);

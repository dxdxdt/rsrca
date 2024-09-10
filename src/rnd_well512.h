// The Well Equidistributed Long-period Linear PRNG 512a variant
// http://web.archive.org/web/20240118022029/http://www.iro.umontreal.ca/~panneton/well/WELL512a.c
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>


typedef struct {
	uint32_t state[16];
	size_t index;
} rnd_well512_t;

void rnd_well512 (rnd_well512_t *ctx, uint8_t *buf, size_t len);
void rnd_well512_seed (rnd_well512_t *ctx, const uint8_t *seed);

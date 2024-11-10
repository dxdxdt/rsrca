#pragma once
#include <stdint.h>
#include <stddef.h>

typedef struct {
	// empty, for now.
} rnd_rdrnd_t;

size_t rnd_rdrnd_ctx_size (void);
void rnd_rdrnd (rnd_rdrnd_t *ctx, uint8_t *buf, size_t len);

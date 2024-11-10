#include "rnd_well512.h"
#include <string.h>


static uint32_t rnd_well512_pull (rnd_well512_t *ctx) {
	uint32_t a, b, c, d;

	a = ctx->state[ctx->index];
	c = ctx->state[(ctx->index + 13) & 15];
	b = a ^ c ^ (a << 16) ^ (c << 15);
	c = ctx->state[(ctx->index + 9) & 15];
	c ^= (c >> 11);
	a = ctx->state[ctx->index] = b ^ c;
	d = a ^ ((a << 5) & 0xDA442D24UL);
	ctx->index = (ctx->index + 15) & 15;
	a = ctx->state[ctx->index];
	ctx->state[ctx->index] = a ^ b ^ d ^ (a << 2) ^ (b << 18) ^ (c << 28);

	return ctx->state[ctx->index];
}

size_t rnd_well512_ctx_size (void) {
	return sizeof(uint32_t[16]);
}

size_t rnd_well512_seed_size (rnd_well512_t *ctx) {
	return sizeof(ctx->state);
}

void rnd_well512 (rnd_well512_t *ctx, uint8_t *buf, size_t len) {
	size_t consume;
	uint32_t n;

	if ((uintptr_t)buf % sizeof(uint32_t) == 0) { // if aligned
		while (len >= sizeof(uint32_t) * 2) {
			*((uint32_t*)buf) = rnd_well512_pull(ctx);
			*((uint32_t*)buf + 1) = rnd_well512_pull(ctx);
			buf += sizeof(uint32_t) * 2;
			len -= sizeof(uint32_t) * 2;
		}
		if (len >= sizeof(uint32_t)) {
			*((uint32_t*)buf) = rnd_well512_pull(ctx);
			buf += sizeof(uint32_t);
			len -= sizeof(uint32_t);
		}
	}

	while (len > 0) {
		n = rnd_well512_pull(ctx);
		consume = len > sizeof(n) ? sizeof(n) : len;
		memcpy(buf, &n, consume);
		buf += consume;
		len -= consume;
	}
}

void rnd_well512_seed (rnd_well512_t *ctx, const uint8_t *seed) {
	memcpy(ctx->state, seed, sizeof(ctx->state));
}

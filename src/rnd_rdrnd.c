#include "rnd_rdrnd.h"
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <immintrin.h>

// https://stackoverflow.com/questions/29372893/rdrand-and-rdseed-intrinsics-on-various-compilers/72265912#72265912
// https://www.phoronix.com/news/RdRand-3-Percent
// https://arstechnica.com/gadgets/2019/10/how-a-months-old-amd-microcode-bug-destroyed-my-weekend/

size_t rnd_rdrnd_ctx_size (void) {
	return 0;
}

void rnd_rdrnd (rnd_rdrnd_t *ctx, uint8_t *buf, size_t len) {
	size_t consume;
	uint64_t n;
	int fr;

	while (len > 0) {
		fr = _rdrand64_step((unsigned long long*)&n);
		if (fr == 0) {
			abort();
		}

		consume = len > sizeof(n) ? sizeof(n) : len;
		memcpy(buf, &n, consume); // this can be avoided if buf is aligned
		buf += consume;
		len -= consume;
	}
}

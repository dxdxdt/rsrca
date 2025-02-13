#include <string.h>
#include <errno.h>

#include "dns-utils.h"


bool dns_foreach_label (
		const char *in_rname,
		void *uc,
		bool(*cb)(char *label, uint8_t len, void *uc))
{
	char rname[257];
	char *p, *dot;
	uint8_t len;

	if (stpncpy(rname, in_rname, sizeof(rname) - 1) - rname >= 256) {
		errno = ENAMETOOLONG;
		return false;
	}

	p = rname;
	do {
		dot = strchr(p, '.');

		if (dot != NULL) {
			*dot = 0;
		}
		len = (uint8_t)strlen(p);
		if (len > 0) {
			if (!cb(p, len, uc)) {
				return true;
			}
		}
		p = dot + 1;
	} while (dot != NULL);

	cb(NULL, 0, uc);
	return true;
}

struct lblz_ctx {
	uint8_t *out;
	size_t len;
	size_t osize;
};

static bool dns_label_rname (char *label, uint8_t len, void *in_uc) {
	struct lblz_ctx *ctx = (struct lblz_ctx*)in_uc;
	const size_t nlen = ctx->len + len + 1;

	if (nlen > ctx->osize) {
		errno = EMSGSIZE;
		return false;
	}

	ctx->out[ctx->len] = len;
	memcpy(ctx->out + ctx->len + 1, label, len);
	ctx->len += len + 1;

	return true;
}

size_t dns_labelize (const char *str, void *out, const size_t olen) {
	struct lblz_ctx ctx;

	ctx.len = 0;
	ctx.out = out;
	ctx.osize = olen;
	if (dns_foreach_label(str, &ctx, dns_label_rname)) {
		return ctx.len;
	}
	return 0;
}

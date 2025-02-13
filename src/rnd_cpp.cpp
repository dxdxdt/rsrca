#include "rnd_cpp.h"
#include <string.h>
#include <errno.h>
#include <random>
#include <climits>
#include <typeinfo>


class rnd_engine_base {
public:
	virtual ~rnd_engine_base () {}

	virtual size_t result_size () const = 0;
	virtual void seed (const void *v) = 0;
	virtual void gen (uint8_t *out, size_t len) = 0;
};

template <class T>
class rnd_engine : public rnd_engine_base {
protected:
	T *engine;

	virtual void gen_unaligned (const size_t &rs, uint8_t *&buf, size_t &len) {
		size_t consume;
		typename T::result_type n;

		while (len > 0) {
			n = (*this->engine)();
			consume = len > rs ? rs : len;
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
			memcpy(buf, &n, consume);
#else
			#error FIXME!
#endif
			buf += consume;
			len -= consume;
		}
	}

	virtual void gen_aligned (const size_t &rs, uint8_t *&buf, size_t &len) {
		while (len >= rs * 2) {
			switch (rs) {
			case 4:
				*((uint32_t*)buf) = (*this->engine)();
				*((uint32_t*)buf + 1) = (*this->engine)();
				break;
			case 8:
				*((uint64_t*)buf) = (*this->engine)();
				*((uint64_t*)buf + 1) = (*this->engine)();
				break;
			}
			buf += rs * 2;
			len -= rs * 2;
		}
		if (len >= rs) {
			switch (rs) {
			case 4:
				*((uint32_t*)buf) = (*this->engine)();
				break;
			case 8:
				*((uint64_t*)buf) = (*this->engine)();
				break;
			}
			buf += rs;
			len -= rs;
		}
	}

public:
	rnd_engine (T *engine) : engine(engine) {}
	virtual ~rnd_engine () {
		delete this->engine;
	}

	virtual size_t result_size () const {
		if (typeid(typename T::result_type) == typeid(uint_fast32_t)) {
			return 4;
		}
		else if (typeid(typename T::result_type) == typeid(uint_fast64_t)) {
			return 8;
		}
		else {
			abort();
		}
	}

	virtual void seed (const void *v) {
		typename T::result_type n;

		memcpy(&n, v, sizeof(typename T::result_type));
		this->engine->seed(n);
	}

	virtual void gen (uint8_t *buf, size_t len) {
		const size_t rs = this->result_size();

		if ((uintptr_t)buf % sizeof(uint32_t) == 0) { // if aligned
			this->gen_aligned(rs, buf, len);
		}
		this->gen_unaligned(rs, buf, len);
	}
};

typedef struct {
	rnd_engine_base *engine;
	rnd_cpp_t t;
} rnd_cpp_ctx_t;

static rnd_engine_base *alloc_from_enum (const rnd_cpp_t t_in) {
	switch (t_in) {
	case RNDCPPTYPE_NONE: return new rnd_engine(new std::default_random_engine());
	case RNDCPPTYPE_MINSTD: return new rnd_engine(new std::minstd_rand());
	case RNDCPPTYPE_MT19937: return new rnd_engine(new std::mt19937_64());
	case RNDCPPTYPE_RANLUX: return new rnd_engine(new std::ranlux48());
	case RNDCPPTYPE_KNUTHB: return new rnd_engine(new std::knuth_b());
	}

	throw std::bad_cast();
}

size_t rnd_cpp_ctx_size (void) {
	return sizeof(rnd_cpp_ctx_t);
}

size_t rnd_cpp_seed_size (void *ctx_in) {
	rnd_cpp_ctx_t *ctx = (rnd_cpp_ctx_t*)ctx_in;
	return ctx->engine->result_size();
}

void rnd_cpp (void *ctx_in, void *buf, size_t len) {
	rnd_cpp_ctx_t *ctx = (rnd_cpp_ctx_t*)ctx_in;
	return ctx->engine->gen((uint8_t*)buf, len);
}

bool rnd_cpp_setopt (void *ctx_in, const void *opt) {
	rnd_cpp_ctx_t *ctx = (rnd_cpp_ctx_t*)ctx_in;
	auto t = *((const rnd_cpp_t*)opt);

	try {
		auto engine = alloc_from_enum(t);

		delete ctx->engine;
		ctx->engine = engine;
		ctx->t = t;
	}
	catch (std::bad_alloc&) {
		return false;
	}
	catch (std::bad_cast&) {
		errno = EINVAL;
		return false;
	}

	return true;
}

void rnd_cpp_seed (void *ctx_in, const void *seed) {
	rnd_cpp_ctx_t *ctx = (rnd_cpp_ctx_t*)ctx_in;
	ctx->engine->seed(seed);
}

void rnd_cpp_deseed (void *ctx_in) {
	rnd_cpp_ctx_t *ctx = (rnd_cpp_ctx_t*)ctx_in;

	if (ctx == NULL) {
		return;
	}

	delete ctx->engine;
	ctx->engine = nullptr;
}

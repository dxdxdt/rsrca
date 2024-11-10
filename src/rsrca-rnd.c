#include <stdio.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include <signal.h>
#include <getopt.h>
#include <unistd.h>
#include <fcntl.h>

#include "rnd_well512.h"
#include "rnd_rdrnd.h"
#include "rnd_cpp.h"

#define ARGV0 "rsrca-rnd"
#define DEFAULT_RND "well512"


struct rnd {
	const char *name;
	size_t c_size;
	void (*gen)(void *ctx, void *buf, size_t len);
	void (*seed)(void *ctx, const uint8_t *seed);
	size_t (*seed_size)(void *ctx);
	void (*deseed)(void *ctx);
	bool (*setopt)(void *ctx, const void *opt);
	const void *rnd_opts;
};
typedef struct rnd rnt_t;

static struct {
	ssize_t n;
	rnt_t rnd;
	unsigned int timeout;
	union {
		struct {
			unsigned int bout:1;
			unsigned int help:1;
		};
	};
} opts;

static struct {
	void *ctx;
	size_t pagesize;
	size_t pipesize;
	uint8_t *cache;
	size_t cache_size;
} g;

static void print_help (void) {
#define HELP_STR "Usage: "ARGV0" [-hb] [-t TYPE] [-n COUNT] [-s TIMEOUT]\n"

	printf(HELP_STR);
#undef HELP_STR
}

static bool getrndbyname (const char *name, rnt_t *out) {
	static rnd_cpp_t cpp_type;
	rnt_t ret = { 0, };
	bool found = false;

	if (strcmp(name, "well512") == 0) {
		ret.name = "well512";
		ret.c_size = rnd_well512_ctx_size();
		ret.gen = (void (*)(void *ctx, void *buf, size_t len))rnd_well512;
		ret.seed = (void (*)(void *ctx, const uint8_t *seed))rnd_well512_seed;
		ret.seed_size = (size_t (*)(void *ctx))rnd_well512_seed_size;

		found = true;
	}
	else if (strcmp(name, "rdrnd") == 0) {
		ret.name = "rdrnd";
		ret.c_size = rnd_rdrnd_ctx_size();
		ret.gen = (void (*)(void *ctx, void *buf, size_t len))rnd_rdrnd;

		found = true;
	}
	else {
		if (strcmp(name, "cpp") == 0) {
			ret.name = "cpp";
			cpp_type = RNDCPPTYPE_NONE;
			found = true;
		}
		if (strcmp(name, "cpp_minstd") == 0) {
			ret.name = "cpp_minstd";
			cpp_type = RNDCPPTYPE_MINSTD;
			found = true;
		}
		if (strcmp(name, "cpp_mt") == 0) {
			ret.name = "cpp_mt";
			cpp_type = RNDCPPTYPE_MT19937;
			found = true;
		}
		if (strcmp(name, "cpp_ranlux") == 0) {
			ret.name = "cpp_ranlux";
			cpp_type = RNDCPPTYPE_RANLUX;
			found = true;
		}
		if (strcmp(name, "cpp_knuthb") == 0) {
			ret.name = "cpp_knuthb";
			cpp_type = RNDCPPTYPE_KNUTHB;
			found = true;
		}
		if (found) {
			ret.c_size = rnd_cpp_ctx_size();
			ret.gen = (void (*)(void *ctx, void *buf, size_t len))rnd_cpp;
			ret.seed = (void (*)(void *ctx, const uint8_t *seed))rnd_cpp_seed;
			ret.seed_size = (size_t (*)(void *ctx))rnd_cpp_seed_size;
			ret.deseed = (void (*)(void *ctx))rnd_cpp_deseed;
			ret.setopt = (bool (*)(void *ctx, const void *opt))rnd_cpp_setopt;
			ret.rnd_opts = &cpp_type;
		}
	}

	if (found && out != NULL) {
		*out = ret;
	}

	return found;
}

static bool parse_opts (const int argc, const char **argv) {
	int fr;
	bool has_rnd = false;

	while (true) {
		fr = getopt(argc, (char*const*)argv, "ht:n:bs:");
		if (fr == -1) {
			break;
		}

		switch (fr) {
		case 'h': opts.help = true; return true;
		case 'n':
			opts.n = 0;
			fr = sscanf(optarg, "%zd", &opts.n);
			if (fr != 1 || opts.n == 0) {
				fprintf(stderr, ARGV0": invalid option -n: %s\n", optarg);
				return false;
			}
			break;
		case 't':
			if (!getrndbyname(optarg, &opts.rnd)) {
				fprintf(stderr, ARGV0": invalid option -t: %s\n", optarg);
				return false;
			}
			has_rnd = true;
			break;
		case 'b': opts.bout = true; break;
		case 's':
			fr = sscanf(optarg, "%u", &opts.timeout);
			if (fr != 1) {
				fprintf(stderr, ARGV0": invalid option -s: %s\n", optarg);
				return false;
			}
			break;
		case '?': return false;
		}
	}

	if (!has_rnd) {
		if (!getrndbyname(DEFAULT_RND, &opts.rnd)) {
			abort();
		}
	}

	if (opts.bout && isatty(STDOUT_FILENO)) {
		fprintf(stderr, ARGV0": refusing to write binary to terminal\n");
		return false;
	}

	return true;
}

static bool seed (void) {
	bool ret = false;
	uint8_t *buf = NULL;
	int fd = -1;
	ssize_t iofr;
	size_t s_size;

	if (opts.rnd.seed == NULL) {
		return true;
	}

	if (opts.rnd.seed_size == NULL) {
		s_size = 0;
	}
	else {
		s_size = opts.rnd.seed_size(g.ctx);
	}

	fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0) {
		perror(ARGV0": /dev/urandom");
		goto END;
	}

	if (s_size > 0) {
		buf = malloc(s_size);
		if (buf == NULL) {
			perror(ARGV0": malloc()");
			goto END;
		}

		iofr = read(fd, buf, s_size);
		if (iofr < 0) {
			perror(ARGV0": reading /dev/urandom");
			goto END;
		}
		else if (s_size != (size_t)iofr) {
			perror(ARGV0": unexpected EOF whilst reading /dev/urandom");
			goto END;
		}
	}

	opts.rnd.seed(g.ctx, buf);
	ret = true;

END:
	free(buf);
	if (fd >= 0) {
		close(fd);
	}
	return ret;
}

static bool setopt (void) {
	if (opts.rnd.setopt != NULL && opts.rnd.rnd_opts != NULL) {
		return opts.rnd.setopt(g.ctx, opts.rnd.rnd_opts);
	}
	return true;
}

static void init_opts (void) {
	opts.n = -1;
}

static void init_g (void) {
	int fr;

	fr = getpagesize();
	if (fr <= 0) {
		abort();
	}
	g.pagesize = (size_t)fr;

	fr = fcntl(STDOUT_FILENO, F_GETPIPE_SZ);
	if (fr > 0) {
		g.pipesize = (size_t)fr;
	}
	else {
		g.pipesize = g.pagesize;
	}
}

static bool alloc_g (void) {
	void *nm;

	nm = realloc(g.ctx, opts.rnd.c_size);
	if (opts.rnd.c_size > 0 && nm == NULL) {
		perror(ARGV0);
		return false;
	}
	g.ctx = nm;

	g.cache_size = (g.pipesize / sizeof(uint64_t)) * sizeof(uint64_t);
	if (g.cache_size == 0) {
		abort();
	}
	g.cache = malloc(g.cache_size);
	if (g.cache == NULL) {
		perror(ARGV0);
		return false;
	}

	return setopt() && seed();
}

static void dealloc_g (void) {
	if (opts.rnd.deseed != NULL) {
		opts.rnd.deseed(g.ctx);
	}
	free(g.ctx);
	g.ctx = NULL;
	free(g.cache);
	g.cache = NULL;
}

static void do_bout (void) {
	const ssize_t step = g.cache_size / sizeof(uint64_t);
	size_t consume;

	for (ssize_t i = 0; opts.n < 0 || i < opts.n; i += step) {
		if (opts.n > 0 && i + step >= opts.n) {
			consume = (opts.n - i) * sizeof(uint64_t);
		}
		else {
			consume = g.cache_size;
		}

		opts.rnd.gen(g.ctx, g.cache, consume);
		write(STDOUT_FILENO, g.cache, consume);
	}
}

static void do_printf (void) {
	uint64_t num;

	for (ssize_t i = 0; opts.n < 0 || i < opts.n; i += 1) {
		opts.rnd.gen(g.ctx, &num, sizeof(num));
		printf("%"PRIu64"\n", num);
	}
}

static void handle_alarm (int) {
	exit(0);
}

int main (const int argc, const char **argv) {
	int ec = 0;

	init_opts();

	if (!parse_opts(argc, argv)) {
		ec = 2;
		goto END;
	}

	if (opts.help) {
		print_help();
		goto END;
	}

	init_g();
	if (!alloc_g()) {
		ec = 1;
		goto END;
	}

	if (opts.timeout > 0) {
		signal(SIGALRM, handle_alarm);
		alarm(opts.timeout);
	}
	if (opts.bout) {
		do_bout();
	}
	else {
		do_printf();
	}

END:
	dealloc_g();
	return ec;
}

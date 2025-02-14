#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <inttypes.h>
#include <limits.h>
#include <assert.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <bsd/sys/time.h>

#include "dns-utils.h"
#include "rnd_cpp.h"

#define ARGV0 "rsrca-ns"

static_assert(EAGAIN == EWOULDBLOCK);


struct tcp_ctx {
	struct tcp_ctx *prev;
	struct tcp_ctx *next;
	const struct pollfd *pfd;
	struct timespec last_op;
	struct {
		size_t len;
		uint8_t m[65536];
	} in;
	struct {
		size_t len;
		uint8_t m[65536];
	} out;
	union {
		struct sockaddr_storage ss;
		struct sockaddr sa;
	} addr;
	int fd;
};


struct {
	const char *addr;
	const char *port;
	int af;
	unsigned int backlog;
	size_t maxconn;
	uint_fast32_t vl;
	unsigned long nchild;
	struct {
		bool help;
		bool udp;
		bool tcp;
	} flags;
	struct timespec timeout;
} params;

struct {
	void *rnd;
	struct {
		union {
			struct sockaddr_storage _;
			struct sockaddr sa;
			struct sockaddr_in sin;
			struct sockaddr_in6 sin6;
		} addr;
		int fd;
	} s_udp;
	struct {
		union {
			struct sockaddr_storage _;
			struct sockaddr sa;
			struct sockaddr_in sin;
			struct sockaddr_in6 sin6;
		} addr;
		int fd;
	} s_tcp;
	struct {
		size_t size;
		struct pollfd *pfd;
		struct pollfd *pfd_base;
		struct tcp_ctx *list;
		size_t list_len;
	} cctx;
	pid_t pid;
	socklen_t addr_sl;
	struct timespec tick_start;
} g;

static void init_params (void) {
	params.backlog = 4096;
	params.maxconn = 1000;
	params.port = "53";
	params.vl = 2;
	params.nchild = (unsigned long)sysconf(_SC_NPROCESSORS_ONLN);
	params.timeout.tv_sec = 15;
}

static void init_g (void) {
	g.pid = getpid();
	g.s_udp.fd = -1;
	g.s_tcp.fd = -1;
}

static bool alloc_cctx (void) {
	free(g.cctx.pfd);

	g.cctx.size = 2 + params.maxconn;
	g.cctx.pfd = calloc(g.cctx.size, sizeof(struct pollfd));

	if (g.cctx.pfd != NULL) {
		g.cctx.size = params.maxconn;
		g.cctx.pfd_base = g.cctx.pfd + 2;
		// for (size_t i = 0; i < g.cctx.size; i += 1) {
		// 	g.cctx.pfd[i].fd = -1;
		// }
	}
	else {
		free(g.cctx.pfd);
		g.cctx.size = 0;
		g.cctx.pfd = NULL;

		perror(ARGV0": alloc_cctx()");
		return false;
	}

	return true;
}

static void seed_rnd (void *ctx, const size_t ss) {
	uint8_t buf[ss];
	const int fd = open("/dev/urandom", O_RDONLY);
	const ssize_t rsize = read(fd, buf, ss);

	close(fd);

	if (rsize < 0 || (size_t)rsize != ss) {
		const long n = (long)getpid() * (long)time(NULL);

		memset(buf, 0, ss);
		memcpy(buf, &n, sizeof(n) > ss ? ss : sizeof(n));
	}

	rnd_cpp_seed(ctx, buf);
}

static void alloc_rnd (void) {
	const rnd_cpp_t rt = RNDCPPTYPE_NONE;
	size_t ss;
	bool fr;

	if (g.rnd != NULL) {
		rnd_cpp_deseed(g.rnd);
		free(g.rnd);
	}

	g.rnd = malloc(rnd_cpp_ctx_size());
	fr = rnd_cpp_setopt(g.rnd, &rt);
	assert(fr);
	(void)fr;
	ss = rnd_cpp_seed_size(g.rnd);

	seed_rnd(g.rnd, ss);
}

static void deinit_g (void) {
	rnd_cpp_deseed(g.rnd);
	free(g.rnd);
	g.rnd = NULL;

	close(g.s_udp.fd);
	close(g.s_tcp.fd);
	g.s_udp.fd = -1;
	g.s_tcp.fd = -1;
}

static void print_help (void) {
	fprintf(
		stdout,
		"Usage: "ARGV0" [-hvq46ut] [-H ADDR] [-p PORT] [-T PROCS] [-M MAX_CONN]\n"
		"\t[-X TIMEOUT]\n");
}

static bool parse_args (const int argc, const char **argv) {
	int fr;
	long tmpl;
	size_t tmps;

	while (true) {
		fr = getopt(argc, (char*const*)argv, "hH:p:vqT:46tuM:X:");
		if (fr < 0) {
			break;
		}

		switch (fr) {
		case 'h': params.flags.help = true; break;
		case 'H': params.addr = optarg; break;
		case 'p': params.port = optarg; break;
		case 'v': params.vl += 1; break;
		case 'q': params.vl = 0; break;
		case 'T':
			tmpl = -1;
			if (sscanf(optarg, "%ld", &tmpl) != 1 || tmpl < 0) {
				errno = EINVAL;
				fprintf(stderr, ARGV0": -T %s: ", optarg);
				perror(NULL);

				return false;
			}
			if (tmpl != 0) {
				params.nchild = (unsigned long)tmpl;
			}
			else {
				params.nchild = (unsigned long)sysconf(_SC_NPROCESSORS_ONLN);
			}
			break;
		case '4': params.af = AF_INET; break;
		case '6': params.af = AF_INET6; break;
		case 'u': params.flags.udp = true; break;
		case 't': params.flags.tcp = true; break;
		case 'M':
			tmps = 0;
			if (sscanf(optarg, "%zu", &tmps) != 1 || tmps == 0) {
				errno = EINVAL;
				fprintf(stderr, ARGV0": -M %s: ", optarg);
				perror(NULL);

				return false;
			}
			params.maxconn = tmps;
			break;
		case 'X':
			tmpl = 0;
			if (sscanf(optarg, "%ld", &tmpl) != 1) {
				errno = EINVAL;
				fprintf(stderr, ARGV0": -M %s: ", optarg);
				perror(NULL);

				return false;
			}
			params.timeout.tv_sec = tmpl;
			break;
		default:
			return false;
		}
	}

	if (params.flags.udp && params.flags.tcp) {
		fprintf(stderr, ARGV0": -t and -u options are mutually exclusive\n");
		return false;
	}

	return true;
}

static void print_child_header (FILE *f) {
	fprintf(f, ARGV0" %zu: ", (size_t)g.pid);
}

static void print_sin (const struct sockaddr *sa_in, FILE *f) {
	const char *fr;
	char str_addr[INET6_ADDRSTRLEN];
	union {
		const struct sockaddr *sa;
		const struct sockaddr_in *sin;
		const struct sockaddr_in6 *sin6;
	} addr;

	str_addr[0] = 0;
	addr.sa = sa_in;
	assert(addr.sa->sa_family == AF_INET || addr.sa->sa_family == AF_INET6);

	if (addr.sa->sa_family == AF_INET) {
		fr = inet_ntop(AF_INET, &addr.sin->sin_addr, str_addr, sizeof(str_addr));
		assert(fr != NULL);

		fprintf(f, "%s:%"PRIu16, str_addr, addr.sin->sin_port);
	}
	else {
		fr = inet_ntop(AF_INET6, &addr.sin6->sin6_addr, str_addr, sizeof(str_addr));
		assert(fr != NULL);

		if (addr.sin6->sin6_scope_id == 0) {
			fprintf(f, "[%s]:%"PRIu16, str_addr, addr.sin6->sin6_port);
		}
		else {
			fprintf(
				f,
				"[%s%%%"PRIu32"]:%"PRIu16,
				str_addr,
				addr.sin6->sin6_scope_id,
				addr.sin6->sin6_port);
		}
	}

	(void)fr;
}

static bool setup_socket_udp (const struct addrinfo *target) {
	int fr;

	close(g.s_udp.fd);
	g.s_udp.fd = socket(target->ai_family, SOCK_DGRAM, IPPROTO_UDP);
	if (g.s_udp.fd < 0) {
		perror(ARGV0": socket()");
		return false;
	}

	fr = bind(g.s_udp.fd, target->ai_addr, target->ai_addrlen);
	if (fr != 0) {
		perror(ARGV0": failed to bind UDP socket");
		return false;
	}

	g.addr_sl = sizeof(g.s_udp.addr);
	fr = getsockname(g.s_udp.fd, &g.s_udp.addr.sa, &g.addr_sl);
	assert(fr == 0);
	assert(
		g.s_udp.addr.sa.sa_family == AF_INET ||
		g.s_udp.addr.sa.sa_family == AF_INET6);

	fr = fcntl(g.s_udp.fd, F_SETFL, O_NONBLOCK);
	assert(fr == 0);

	return true;
}

static bool setup_socket_tcp (const struct addrinfo *target) {
	int fr;
	int ov;

	close(g.s_tcp.fd);
	g.s_tcp.fd = socket(target->ai_family, SOCK_STREAM, IPPROTO_TCP);
	if (g.s_tcp.fd < 0) {
		perror(ARGV0": socket()");
		return false;
	}

	ov = 1;
	setsockopt(g.s_tcp.fd, SOL_SOCKET, SO_REUSEADDR, &ov, sizeof(ov));

	fr = bind(g.s_tcp.fd, target->ai_addr, target->ai_addrlen);
	if (fr != 0) {
		perror(ARGV0": failed to bind TCP socket");
		return false;
	}

	fr = listen(g.s_tcp.fd, params.backlog);
	if (fr != 0) {
		perror(ARGV0": listen()");
		return false;
	}

	g.addr_sl = sizeof(g.s_tcp.addr);
	fr = getsockname(g.s_tcp.fd, &g.s_tcp.addr.sa, &g.addr_sl);
	assert(fr == 0);
	assert(
		g.s_tcp.addr.sa.sa_family == AF_INET ||
		g.s_tcp.addr.sa.sa_family == AF_INET6);

	fr = fcntl(g.s_tcp.fd, F_SETFL, O_NONBLOCK);
	assert(fr == 0);

	return true;
}

static bool setup_socket (void) {
	int fr;
	struct addrinfo hints = { 0, }, *res, *target, *p;
	bool ret;

	hints.ai_family = params.af;
	hints.ai_flags = AI_PASSIVE;
	fr = getaddrinfo(params.addr, params.port, &hints, &res);

	if (fr != 0) {
		if (params.addr == NULL) {
			params.addr = "";
		}
		fprintf(
			stderr,
			ARGV0": %s %s: %s\n",
			params.addr,
			params.port,
			gai_strerror(fr));

		return false;
	}

	target = res;
	if (params.af == 0) {
		for (p = res; p != NULL; p = p->ai_next) {
			if (p->ai_family == AF_INET6) {
				target = p;
				break;
			}
		}
	}

	if (params.flags.udp) {
		ret = setup_socket_udp(target);

		if (params.vl > 2) {
			fprintf(stderr, ARGV0": UDP socket bound to ");
			print_sin(&g.s_udp.addr.sa, stderr);
			fprintf(stderr, "\n");
		}
	}
	else if (params.flags.tcp) {
		ret = setup_socket_tcp(target);

		if (params.vl > 2) {
			fprintf(stderr, ARGV0": TCP socket bound to ");
			print_sin(&g.s_tcp.addr.sa, stderr);
			fprintf(stderr, "\n");
		}
	}
	else {
		ret = setup_socket_udp(target) && setup_socket_tcp(target);
	}

	freeaddrinfo(res);
	return ret;
}

static void report_dgram (
	const struct sockaddr *sa,
	const uint8_t *buf,
	const size_t len)
{
	print_child_header(stderr);
	fprintf(stderr, "received %zu bytes from ", len);
	print_sin(sa, stderr);

	if (params.vl > 4) {
		fprintf(stderr, " =");
		for (size_t i = 0; i < len; i += 1) {
			fprintf(stderr, " %02x", buf[i]);
		}
	}

	fprintf(stderr, "\n");
}

struct child_udp_send_ctx {
	struct sockaddr *sa;
	socklen_t sl;
	int fd;
};

static bool parse_dns_msg (
	const uint8_t *buf,
	const size_t len,
	struct dns_header *dh,
	struct dns_query *q,
	const size_t q_size,
	const size_t lblpool_size)
{
	uint16_t lblpool[lblpool_size];
	size_t i, j, offset, lblpool_ptr = 0, qno, qno_l, qno_newlen;

	if (len < 12 || len > 65535) {
		errno = EPROTO;
		return false;
	}
	memcpy(dh, buf, 12);

	dh->id = ntohs(dh->id);
	dh->q_count = ntohs(dh->q_count);
	dh->ans_count = ntohs(dh->ans_count);
	dh->auth_count = ntohs(dh->auth_count);
	dh->add_count = ntohs(dh->add_count);

	offset = 12;
	for (i = 0; i < dh->q_count && i < q_size; i += 1) {
		if (offset > len) {
			errno = EBADMSG;
			return false;
		}

		qno = offset;

		// index and check qname labels

		while (buf[offset] != 0) {
			if ((buf[offset] & 0xc0) == 0xc0) { // pointer
				uint16_t lp;
				bool found;

				if (offset + 1 >= len) {
					errno = EBADMSG;
					return false;
				}

				lp = (((uint16_t)buf[offset] & 0x3f) << 8) | buf[offset + 1];
				offset += 2;

				found = false;
				for (j = 0; j < lblpool_ptr; j += 1) {
					if (lblpool[j] == lp) {
						found = true;
						break;
					}
				}

				if (found) {
					break;
				}
				else {
					errno = EBADMSG;
					return false;
				}
			}
			else if (buf[offset] > 63) {
				errno = EBADMSG;
				return false;
			}
			else {
				if (lblpool_ptr >= lblpool_size) {
					errno = E2BIG;
					return false;
				}
				lblpool[lblpool_ptr++] = offset;
				offset += buf[offset] + 1;
			}
		}
		offset += 1;

		// stringify qname

		qno_l = 0;
		while (buf[qno] != 0) {
			if (buf[qno] & 0xc0) {
				// follow pointer
				qno = (((uint16_t)buf[qno] & 0x3f) << 8) | buf[qno + 1];
			}

			qno_newlen = qno_l + buf[qno] + 1;
			if (qno_newlen > 255) {
				errno = EBADMSG;
				return false;
			}

			memcpy(q[i].name + qno_l, buf + qno + 1, buf[qno]);
			q[i].name[qno_l + buf[qno]] = '.';
			qno += buf[qno] + 1;
			qno_l = qno_newlen;
		}
		q[i].name[qno_l] = 0;

		// parse question

		if (offset + 4 > len) {
			errno = EBADMSG;
			return false;
		}
		static_assert(sizeof(struct dns_qd) == 4);
		memcpy(&q[i].desc, buf + offset, 4);
		offset += 4;

		q[i].desc.qtype = ntohs(q[i].desc.qtype);
		q[i].desc.qclass = ntohs(q[i].desc.qclass);
	}

	return true;
}

static void report_dns_msg (
	FILE *f,
	const struct dns_header *dh,
	const struct dns_query *q,
	const size_t q_size)
{
	size_t i;

	fprintf(
		f,
		";; opcode: %"PRIu16", status: %"PRIu16", id: %"PRIu16"\n",
		dh->opcode,
		dh->rcode,
		dh->id);
	fprintf(
		f,
		";; flags: %s%s%s%s%s%s%s%s; QUERY: %"PRIu16", ANSWER: %"PRIu16", "
			"AUTHORITY: %"PRIu16", ADDITIONAL: %"PRIu16"\n",
		dh->rd ? "rd" : "",
		dh->tc ? "tc" : "",
		dh->aa ? "aa" : "",
		dh->qr ? "qr" : "",
		dh->cd ? "cd" : "",
		dh->ad ? "ad" : "",
		dh->z ? "z" : "",
		dh->ra ? "ra" : "",
		dh->q_count,
		dh->ans_count,
		dh->auth_count,
		dh->add_count);

	fprintf(f, ";; QUESTION SECTION:\n");
	for (i = 0; i < dh->q_count && i < q_size; i += 1) {
		fprintf(
			f,
			"; %s	%"PRIu16"	%"PRIu16"\n",
			q[i].name,
			q[i].desc.qclass,
			q[i].desc.qtype);
	}
}

static bool bufsink (
		void *buf,
		const void *src,
		const size_t datalen,
		size_t *buflen,
		const size_t bufsize)
{
	if (*buflen + datalen > bufsize) {
		errno = EOVERFLOW;
		return false;
	}

	memcpy(buf + *buflen, src, datalen);
	*buflen += datalen;

	return true;
}

typedef bool(*child_send_ft)(void *, const void *, const size_t);

static bool child_respond (
		child_send_ft sendf,
		void *sctx,
		uint8_t *buf,
		const size_t bufsize,
		struct dns_header *dh,
		struct dns_query *q,
		const size_t q_size)
{
	const struct dns_header org_dh = *dh;
	const uint16_t qtype = q[0].desc.qtype;
	const uint16_t qclass = q[0].desc.qclass;
	char rdata[256];
	size_t offset = 0, l;
	bool bfr;
	struct dns_rdata rr = { 0, };
	uint16_t lptr;
	uint8_t txtlen;

	l = dns_labelize(q[0].name, rdata, sizeof(rdata));
	assert(l > 0);
	q[0].desc.qclass = htons(q[0].desc.qclass);
	q[0].desc.qtype = htons(q[0].desc.qtype);

	memset(dh, 0, sizeof(struct dns_header));
	dh->id = htons(org_dh.id);
	dh->aa = org_dh.rd ? false : true;
	dh->qr = true;
	dh->ra = true;
	dh->q_count = htons(1);

	switch (qtype) {
	case 1:
	case 28:
	case 16:
		dh->ans_count = htons(1);
		break;
	default:
		dh->rcode = 3;
	}

	bfr =
		bufsink(buf, dh, sizeof(struct dns_header), &offset, bufsize) &&
		bufsink(buf, rdata, l, &offset, bufsize) &&
		bufsink(buf, &q[0].desc, sizeof(q[0].desc), &offset, bufsize);
	if (!bfr) {
		goto TRUNC;
	}

	if (dh->rcode != 0) {
		goto SEND;
	}

	// ANSWERS

	lptr = htons(0xc000 | 12);
	if (!bufsink(buf, &lptr, 2, &offset, bufsize)) {
		goto TRUNC;
	}

	switch (qtype) {
	case 1:
		rnd_cpp(g.rnd, rdata, 4);
		rr.type = htons(1);
		rr.class = htons(1);
		rr.ttl = htonl(86400);
		rr.data_len = htons(4);

		bfr =
			bufsink(buf, &rr, sizeof(rr), &offset, bufsize) &&
			bufsink(buf, rdata, 4, &offset, bufsize);
		break;
	case 28:
		rnd_cpp(g.rnd, rdata, 16);
		rr.type = htons(28);
		rr.class = htons(1);
		rr.ttl = htonl(86400);
		rr.data_len = htons(16);

		bfr =
			bufsink(buf, &rr, sizeof(rr), &offset, bufsize) &&
			bufsink(buf, rdata, 16, &offset, bufsize);
		break;
	case 16:
		if (qclass == 3) {
			static const char chaos_str[] =
				"David Timber <dxdt@dev.snart.me>, rsrca project, 2025";
			static_assert(sizeof(chaos_str) < 256);

			txtlen = sizeof(chaos_str) - 1;
			memcpy(rdata, chaos_str, sizeof(chaos_str));
		}
		else {
			rnd_cpp(g.rnd, &txtlen, sizeof(txtlen));
			rnd_cpp(g.rnd, rdata, txtlen);
			for (size_t i = 0; i < txtlen; i += 1) {
				rdata[i] = (char)(((uint_fast8_t)rdata[i] % 95) + 32); // 32 ~ 126 (inc)
			}
		}
		rr.type = htons(16);
		rr.class = htons(qclass);
		rr.ttl = htonl(86400);
		rr.data_len = htons((uint16_t)txtlen + 1);

		bfr =
			bufsink(buf, &rr, sizeof(rr), &offset, bufsize) &&
			bufsink(buf, &txtlen, 1, &offset, bufsize) &&
			bufsink(buf, rdata, txtlen, &offset, bufsize);
		break;
	default:
		return false;
	}

	if (!bfr) {
		goto TRUNC;
	}

SEND:
	return sendf(sctx, buf, offset);
TRUNC:
	// TODO: no need for now
	return false;
}

static void child_respond_fmterr (
		child_send_ft sendf,
		void *sctx,
		struct dns_header *dh)
{
	const uint16_t qid = htons(dh->id);

	memset(dh, 0, sizeof(struct dns_header));
	dh->id = qid;
	dh->opcode = 2;
	dh->qr = true;
	dh->rcode = 1;

	sendf(sctx, dh, sizeof(struct dns_header));
}

static bool child_serve_tail (
		child_send_ft sendf,
		void *sctx,
		uint8_t *buf,
		const size_t bufsize,
		const size_t msglen,
		struct dns_header *dh,
		struct dns_query *q,
		const size_t q_size)
{
	const bool parse_ret = parse_dns_msg(buf, msglen, dh, q, q_size, 127);

	if (!parse_ret) {
		if (params.vl > 3) {
			print_child_header(stderr);
			perror("parse_dns_msg()");
		}

		if (errno == EBADMSG) {
			child_respond_fmterr(sendf, sctx, dh);
		}
		return false;
	}
	if (params.vl > 4) {
		print_child_header(stderr);
		report_dns_msg(stderr, dh, q, q_size);
	}

	if (dh->q_count > q_size) {
		if (params.vl > 3) {
			print_child_header(stderr);
			fprintf(
				stderr,
				"too many questions (%zu > %zu)\n",
				(size_t)dh->q_count,
				(size_t)q_size);
		}
		return false;
	}
	if (dh->qr || dh->opcode != 0 || dh->q_count == 0) {
		if (params.vl > 4) {
			print_child_header(stderr);
			fprintf(stderr, "dropping irrelevant query\n");
		}
		return false;
	}

	return child_respond(sendf, sctx, buf, bufsize, dh, q, q_size);
}

static bool child_udp_send (void *ctx_in, const void *buf, const size_t len) {
	struct child_udp_send_ctx *ctx = ctx_in;

	sendto(ctx->fd, buf, len, MSG_NOSIGNAL, ctx->sa, ctx->sl);

	return true;
}

static void child_serve_udp (
		struct sockaddr *sa,
		socklen_t *sl,
		uint8_t *buf,
		const size_t bufsize,
		struct dns_header *dh,
		struct dns_query *q,
		const size_t q_size)
{
	ssize_t fr;
	struct child_udp_send_ctx sctx;

	assert(bufsize > 0);

	fr = recvfrom(g.s_udp.fd, buf, bufsize, 0, sa, sl);
	if (fr < 0) {
		switch (errno) {
		case EAGAIN:
		case ECONNREFUSED:
			return;
		}
		print_child_header(stderr);
		perror("recvfrom()");
		abort();
	}

	if (params.vl > 3) {
		report_dgram(sa, buf, (size_t)fr);
	}

	sctx.fd = g.s_udp.fd;
	sctx.sa = sa;
	sctx.sl = *sl;
	(void)child_serve_tail(
		child_udp_send,
		&sctx,
		buf,
		bufsize, 
		(size_t)fr, 
		dh, 
		q, 
		q_size);
}

static void child_accept_tcp (struct sockaddr *sa, socklen_t *sl) {
	struct tcp_ctx *tc;
	const int ret = accept(g.s_tcp.fd, sa, sl);

	if (ret < 0) {
		switch (errno) {
		case EAGAIN:
		case ECONNABORTED:
		case EINTR:
		case EPROTO:
			return;
		}
		print_child_header(stderr);
		perror("accept()");
		abort();
	}

	assert(g.cctx.size > g.cctx.list_len);
	assert(*sl <= sizeof(struct sockaddr_storage));

	tc = calloc(1, sizeof(struct tcp_ctx));
	if (tc == NULL) {
		print_child_header(stderr);
		perror("child_accept_tcp()");

		close(ret);
		return;
	}

	if (g.cctx.list == NULL) {
		g.cctx.list = tc;
	}
	else {
		tc->next = g.cctx.list;
		g.cctx.list->prev = tc;
		g.cctx.list = tc;
	}

	tc->last_op = g.tick_start;
	tc->fd = ret;
	memcpy(&tc->addr, sa, *sl);

	g.cctx.list_len += 1;

	if (params.vl > 3) {
		print_child_header(stderr);
		fprintf(stderr, "accepted TCP conn(fd=%d) from ", ret);
		print_sin(sa, stderr);
		fprintf(stderr, "\n");
	}
}

static void child_teardown_tcp (struct tcp_ctx *tc) {
	assert(g.cctx.list_len > 0);

	if (params.vl > 3) {
		print_child_header(stderr);
		fprintf(stderr, "tearing down TCP conn(fd=%d) ", tc->fd);
		print_sin(&tc->addr.sa, stderr);
		fprintf(stderr, "\n");
	}

	if (g.cctx.list == tc) {
		g.cctx.list = g.cctx.list->next;
	}
	else {
		tc->prev->next = tc->next;
		if (tc->next != NULL) {
			tc->next->prev = tc->prev;
		}
	}

	close(tc->fd);
	free(tc);
	g.cctx.list_len -= 1;
}

static int child_rebuild_pfd (void) {
	size_t i;
	struct tcp_ctx *tc, *d = NULL;
	int ret = -1;
	struct timespec dur;
	struct timespec ttl;
	unsigned long ttl_ms;

	for (i = 0, tc = g.cctx.list; tc != NULL; i += 1) {
		timespecsub(&g.tick_start, &tc->last_op, &dur);

		if (params.timeout.tv_sec >= 0 && timespeccmp(&dur, &params.timeout, >)) {
			// remove the timed out connection
			d = tc;
			tc = tc->next;
		}
		else {
			timespecsub(&params.timeout, &dur, &ttl);
			ttl_ms = ttl.tv_sec * 1000 + ttl.tv_nsec / 1000000;
			if (ttl_ms > INT_MAX) {
				// overflow. this shouldn't really happen.
				ttl_ms = INT_MAX;
			}
			if (ret < 0 || ttl_ms < (unsigned long)ret) {
				// find the connection with least ttl value
				ret = ttl_ms;
			}

			tc->pfd = g.cctx.pfd_base + i;
			g.cctx.pfd_base[i].fd = tc->fd;
			if (tc->out.len > 0) {
				g.cctx.pfd_base[i].events = POLLOUT;
			}
			else {
				g.cctx.pfd_base[i].events = POLLIN;
			}

			tc = tc->next;
		}

		if (d != NULL) {
			child_teardown_tcp(d);
			d = NULL;
		}
	}
	for (; i < g.cctx.size; i += 1) {
		g.cctx.pfd_base[i].fd = -1;
	}

	return ret;
}

static bool child_tcp_send (void *ctx_in, const void *buf, const size_t len) {
	struct tcp_ctx *ctx = ctx_in;
	const uint16_t msglen = htons((uint16_t)len);
	ssize_t wfr;

	assert(0 < len);
	if (len + 2 > sizeof(ctx->out.m)) {
		errno = E2BIG;
		return false;
	}

	memcpy(ctx->out.m, &msglen, 2);
	memcpy(ctx->out.m + 2, buf, len);
	ctx->out.len = 2 + len;

	wfr = send(ctx->fd, ctx->out.m, ctx->out.len, MSG_NOSIGNAL);
	// wfr = write(ctx->fd, buf, len);
	if (wfr < 0) {
		return false;
	}

	ctx->out.len -= wfr;
	memcpy(ctx->out.m, (const uint8_t*)buf + wfr, ctx->out.len);

	return true;
}

static bool child_consume_tcp (
		struct tcp_ctx *tc,
		uint8_t *buf,
		const size_t bufsize,
		struct dns_header *dh,
		struct dns_query *q,
		const size_t q_size)
{
	uint16_t msglen;
	bool fr;
	size_t consumed;

	while (tc->in.len >= 2) {
		msglen = ntohs(*(uint16_t*)tc->in.m);
		if (msglen > tc->in.len - 2) {
			break;
		}

		memcpy(buf, tc->in.m + 2, msglen);

		consumed = 2 + msglen;
		memmove(tc->in.m, tc->in.m + consumed, tc->in.len - consumed);
		tc->in.len -= consumed;

		if (params.vl > 3) {
			report_dgram(&tc->addr.sa, buf, msglen);
		}

		fr = child_serve_tail(child_tcp_send, tc, buf, bufsize, msglen, dh, q, q_size);
		if (!fr) {
			return false;
		}
		tc->last_op = g.tick_start;
	}

	return true;
}

static void child_serve_tcp (
		uint8_t *buf,
		const size_t bufsize,
		struct dns_header *dh,
		struct dns_query *q,
		const size_t q_size)
{
	struct tcp_ctx *tc = g.cctx.list, *d;
	ssize_t fr;
	size_t rem;

	assert(sizeof(tc->in.m) > 514);

	while (tc != NULL) {
		if (tc->pfd != NULL && tc->pfd->revents) {
			if (tc->out.len > 0) {
				fr = write(tc->fd, tc->out.m, tc->out.len);
				assert(fr != 0);
				if (fr < 0) {
					// TODO: report error
					goto DROP;
				}

				rem = tc->out.len - fr;
				tc->out.len = rem;
				memmove(tc->out.m, tc->out.m + fr, rem);
			}
			else {
				rem = sizeof(tc->in.m) - tc->in.len;
				fr = read(tc->fd, tc->in.m + tc->in.len, rem);
				if (fr < 0) {
					// TODO: report error
					goto DROP;
				}
				else if (fr == 0) {
					shutdown(tc->fd, SHUT_RDWR);
					goto DROP;
				}
				else {
					tc->in.len += fr;
					if (!child_consume_tcp(tc, buf, bufsize, dh, q, q_size)) {
						// TODO: report error
						goto DROP;
					}
				}
			}
		}

		tc = tc->next;
		continue;
DROP:
		d = tc;
		tc = tc->next;
		child_teardown_tcp(d);
	}
}

static int child_main (void) {
#define Q_SIZE (1)
	static uint8_t msgbuf[65535];
	static struct dns_header dh;
	static struct dns_query q[Q_SIZE];

	int fr;
	struct pollfd *pfd_udp = g.cctx.pfd + 0;
	struct pollfd *pfd_tcp = g.cctx.pfd + 1;
	int poll_timeout;

	union {
		struct sockaddr_storage _;
		struct sockaddr sa;
	} addr;
	socklen_t sl;

	pfd_udp->fd = g.s_udp.fd;
	pfd_udp->events = POLLIN;
	pfd_tcp->events = POLLIN;

	assert(pfd_udp->fd >= 0 || pfd_tcp->fd >= 0);

	while (true) {
		clock_gettime(CLOCK_MONOTONIC, &g.tick_start);

		if (g.cctx.list_len < g.cctx.size) {
			pfd_tcp->fd = g.s_tcp.fd;
		}
		else {
			pfd_tcp->fd = -1;
		}
		poll_timeout = child_rebuild_pfd();

		fr = poll(g.cctx.pfd, (nfds_t)g.cctx.size + 2, poll_timeout);
		clock_gettime(CLOCK_MONOTONIC, &g.tick_start);
		if (fr < 0) {
			print_child_header(stderr);
			switch (errno) {
			case EINTR: continue;
			case EINVAL:
				fprintf(stderr, "poll() returned EINVAL! Check RLIMIT_NOFILE(ulimit -n)\n");
				break;
			default:
				perror("poll()");
			}

			abort();
		}

		if (pfd_udp->revents) {
			sl = sizeof(addr);
			child_serve_udp(&addr.sa, &sl, msgbuf, sizeof(msgbuf), &dh, q, Q_SIZE);
		}

		if (pfd_tcp->revents) {
			sl = sizeof(addr);
			child_accept_tcp(&addr.sa, &sl);
		}

		child_serve_tcp(msgbuf, sizeof(msgbuf), &dh, q, Q_SIZE);
	}
}

static void reap_procs (
		pid_t *arr,
		const size_t size,
		const int term_sig,
		const pid_t excl)
{
	for (size_t i = 0; i < size; i += 1) {
		if (arr[i] > 0 || arr[i] == excl) {
			continue;
		}
		kill(arr[i], term_sig);
		waitpid(arr[i], NULL, 0);
	}
	memset(arr, 0, sizeof(pid_t) * size);
}

static int do_service (void) {
	pid_t arr[params.nchild];
	int ec;
	pid_t dead_child;
	struct sigaction sa = { 0, };

	sa.sa_handler = SIG_IGN;
	sa.sa_flags = SA_RESETHAND;

	memset(arr, 0, sizeof(pid_t) * params.nchild);

	for (unsigned long i = 0; i < params.nchild; i += 1) {
		arr[i] = fork();
		if (arr[i] < 0) {
			perror(ARGV0": fork()");
			reap_procs(arr, params.nchild, SIGKILL, -1);
			return 1;
		}
		else if (arr[i] == 0) {
			memset(&sa, 0, sizeof(sa));
			sa.sa_handler = SIG_IGN;
			sigaction(SIGPIPE, &sa, NULL);

			g.pid = getpid();
			alloc_rnd();

			ec = child_main();
			exit(ec);
		}
	}

	close(g.s_udp.fd);
	close(g.s_tcp.fd);
	g.s_udp.fd = -1;
	g.s_tcp.fd = -1;

	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);

	dead_child = wait(NULL);
	reap_procs(arr, params.nchild, SIGHUP, dead_child);

	if (dead_child > 0) {
		return 1;
	}
	return 0;
}

int main (const int argc, const char **argv) {
	static int ec = 0;

	init_params();
	init_g();

	if (!parse_args(argc, argv)) {
		ec = 2;
		goto END;
	}

	if (params.flags.help) {
		print_help();
		goto END;
	}

	if (!alloc_cctx()) {
		ec = 1;
		goto END;
	}

	if (!setup_socket()) {
		ec = 1;
		goto END;
	}

	ec = do_service();
END:
	deinit_g();
	return ec;
}

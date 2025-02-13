#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <inttypes.h>
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

#include "dns-utils.h"
#include "rnd_cpp.h"

#define ARGV0 "rsrca-ns"

static_assert(EAGAIN == EWOULDBLOCK);


struct tcp_ctx {
	struct timespec last_op;
	size_t expected;
	size_t len;
	uint8_t buf[512];
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
		size_t nb_conn;
		struct pollfd *pfd;
		struct tcp_ctx *pb;
	} cctx;
	pid_t pid;
	socklen_t addr_sl;
} g;

static void init_params (void) {
	params.backlog = 4096;
	params.maxconn = 2048;
	params.port = "53";
	params.vl = 2;
	params.nchild = (unsigned long)sysconf(_SC_NPROCESSORS_ONLN);
}

static void init_g (void) {
	g.pid = getpid();
	g.s_udp.fd = -1;
	g.s_tcp.fd = -1;
}

static bool alloc_cctx (void) {
	bool ret;

	g.cctx.nb_conn = 0;
	free(g.cctx.pfd);
	free(g.cctx.pb);

	g.cctx.pb = calloc(params.maxconn, sizeof(struct tcp_ctx));
	g.cctx.pfd = calloc(2 + params.maxconn, sizeof(struct pollfd));

	ret = g.cctx.pfd != NULL && g.cctx.pb != NULL;
	if (ret) {
		for (size_t i = 0; i < 2 + params.maxconn; i += 1) {
			g.cctx.pfd[i].fd = -1;
		}
	}
	else {
		perror(ARGV0": alloc_cctx()");
	}

	return ret;
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
	// TODO
}

static bool parse_args (const int argc, const char **argv) {
	int fr;
	long tmp;

	while (true) {
		fr = getopt(argc, (char*const*)argv, "hH:p:vT:46tu");
		if (fr < 0) {
			break;
		}

		switch (fr) {
		case 'h': params.flags.help = true; break;
		case 'H': params.addr = optarg; break;
		case 'p': params.port = optarg; break;
		case 'v': params.vl += 1; break;
		case 'T':
			tmp = -1;
			if (sscanf(optarg, "%ld", &tmp) != 1 || tmp < 0) {
				errno = EINVAL;
				fprintf(stderr, ARGV0": %s: ", optarg);
				perror(NULL);

				return false;
			}
			if (tmp != 0) {
				params.nchild = (unsigned long)tmp;
			}
			break;
		case '4': params.af = AF_INET; break;
		case '6': params.af = AF_INET6; break;
		case 'u': params.flags.udp = true; break;
		case 't': params.flags.tcp = true; break;
		default: return false;
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
		if (false) {
			ret = setup_socket_udp(target) && setup_socket_tcp(target);
		}
		else {
			ret = setup_socket_udp(target);
		}
	}

	freeaddrinfo(res);
	return ret;
}

static void report_udp_dgram (
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
		if (offset >= len) {
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

		if (offset + 4 >= len) {
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
	const struct dns_query *q)
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
	for (i = 0; i < dh->q_count; i += 1) {
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

static void child_respond (
		const int fd,
		struct sockaddr *sa,
		const socklen_t sl,
		uint8_t *buf,
		const size_t bufsize,
		struct dns_header *dh,
		struct dns_query *q,
		const size_t q_size)
{
	const uint16_t qid = dh->id;
	char rdata[256];
	size_t offset = 0, l;
	bool bfr;
	struct dns_rdata rr = { 0, };
	uint16_t lptr;
	uint8_t txtlen;

	memset(dh, 0, sizeof(struct dns_header));
		dh->id = htons(qid);
	dh->aa = true;
	// dh->opcode = 0;
	dh->qr = true;
	// dh->rcode = 0;

	dh->q_count = htons(1);
	dh->ans_count = htons(1);

	if (!bufsink(buf, dh, sizeof(struct dns_header), &offset, bufsize)) {
		goto TRUNC;
	}

	// QUESTIONS

	l = dns_labelize(q[0].name, rdata, sizeof(rdata));
	assert(l > 0);
	q[0].desc.qclass = htons(q[0].desc.qclass);
	q[0].desc.qtype = htons(q[0].desc.qtype);

	bfr =
		bufsink(buf, rdata, l, &offset, bufsize) &&
		bufsink(buf, &q[0].desc, sizeof(q[0].desc), &offset, bufsize);
	if (!bfr) {
		goto TRUNC;
	}

	// ANSWERS

	lptr = htons(0xc000 | 12);
	if (!bufsink(buf, &lptr, 2, &offset, bufsize)) {
		goto TRUNC;
	}

	rnd_cpp(g.rnd, &txtlen, sizeof(txtlen));
	rnd_cpp(g.rnd, rdata, txtlen);
	for (size_t i = 0; i < txtlen; i += 1) {
		rdata[i] = (char)(((uint_fast8_t)rdata[i] % 95) + 32); // 32 ~ 126 (inc)
	}

	rr.type = htons(16);
	rr.class = htons(1);
	rr.ttl = htonl(86400);
	rr.data_len = htons((uint16_t)txtlen + 1);

	bfr =
		bufsink(buf, &rr, sizeof(rr), &offset, bufsize) &&
		bufsink(buf, &txtlen, 1, &offset, bufsize) &&
		bufsink(buf, rdata, txtlen, &offset, bufsize);
	if (!bfr) {
		goto TRUNC;
	}

	sendto(fd, buf, offset, MSG_NOSIGNAL, sa, sl);

	return;
TRUNC:
	// TODO
	return;
}

static void child_respond_fmterr (
		const int fd,
		struct sockaddr *sa,
		const socklen_t sl,
		struct dns_header *dh)
{
	const uint16_t qid = htons(dh->id);

	memset(dh, 0, sizeof(struct dns_header));
	dh->id = qid;
	dh->opcode = 2;
	dh->qr = true;
	dh->rcode = 1;

	sendto(fd, dh, sizeof(struct dns_header), MSG_NOSIGNAL, sa, sl);
}

static bool child_serve_tail (
		const int fd,
		struct sockaddr *sa,
		socklen_t sl,
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
			child_respond_fmterr(fd, sa, sl, dh);
		}
		return false;
	}
	if (params.vl > 4) {
		print_child_header(stderr);
		report_dns_msg(stderr, dh, q);
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
	if (dh->qr || dh->opcode != 0 || dh->q_count == 0 || q[0].desc.qtype != 16) {
		if (params.vl > 4) {
			print_child_header(stderr);
			fprintf(stderr, "dropping irrelevant query\n");
		}
		return false;
	}

	child_respond(fd, sa, sl, buf, bufsize, dh, q, q_size);

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

	assert(bufsize > 0);

	fr = recvfrom(g.s_udp.fd, buf, bufsize, 0, sa, sl);
	if (fr < 0) {
		switch (errno) {
		case EAGAIN:
		case ECONNREFUSED:
		case EINTR:
			return;
		}
		print_child_header(stderr);
		perror("recvfrom()");
		abort();
	}

	if (params.vl > 3) {
		report_udp_dgram(sa, buf, (size_t)fr);
	}

	if (fr > 512 && false) {
		// truncated (larger than 512 bytes)
		if (params.vl > 3) {
			print_child_header(stderr);
			fprintf(stderr, "ignoring large message\n");
		}
		return;
	}

	child_serve_tail(g.s_udp.fd, sa, *sl, buf, bufsize, (size_t)fr, dh, q, q_size);
}

static int child_accept_tcp (struct sockaddr *sa, socklen_t *sl) {
	int ret = accept(g.s_tcp.fd, sa, sl);
	if (ret < 0) {
		switch (errno) {
		case EAGAIN:
		case ECONNABORTED:
		case EINTR:
		case EPROTO:
			return -1;
		}
		print_child_header(stderr);
		perror("accept()");
		abort();
	}

	if (params.vl > 3) {
		print_child_header(stderr);
		fprintf(stderr, "accepted TCP connection from ");
		print_sin(sa, stderr);
		fprintf(stderr, "\n");
	}

	if (true) { // FIXME
		shutdown(ret, SHUT_RDWR);
		close(ret);
		return -1;
	}

	return ret;
}

static int child_main (void) {
#define Q_SIZE (1)
	static uint8_t udpbuf[65535];
	static struct dns_header dh;
	static struct dns_query q[Q_SIZE];

	int fr;
	struct pollfd *pfd_udp = g.cctx.pfd + 0;
	struct pollfd *pfd_tcp_main = g.cctx.pfd + 1;
	struct pollfd *pfd_tcp_pool = g.cctx.pfd + 2;
	int poll_timeout = -1;

	union {
		struct sockaddr_storage _;
		struct sockaddr sa;
	} addr;
	socklen_t sl;

	pfd_udp->fd = g.s_udp.fd;
	pfd_udp->events = POLLIN;
	pfd_tcp_main->fd = g.s_tcp.fd;
	pfd_tcp_main->events = POLL_IN;

	assert(pfd_udp->fd >= 0 || pfd_tcp_main->fd >= 0);

	while (true) {
		// TODO: calculate poll_timeout to implement TCP timeout

		fr = poll(g.cctx.pfd, 2 + (nfds_t)g.cctx.nb_conn, poll_timeout);
		if (fr < 0) {
			if (errno == EINTR) {
				continue;
			}
			print_child_header(stderr);
			perror("poll()");
			abort();
		}

		if (pfd_udp->fd >= 0 && pfd_udp->revents) {
			sl = sizeof(addr);
			child_serve_udp(&addr.sa, &sl, udpbuf, sizeof(udpbuf), &dh, q, Q_SIZE);
		}

		if (pfd_tcp_main->fd >= 0 && pfd_tcp_main->revents) {
			sl = sizeof(addr);
			fr = child_accept_tcp(&addr.sa, &sl);
			if (fr >= 0) {
				// TODO
			}
		}

		// TODO: iterate over tcp connections
	}
}

static void reap_procs (pid_t *arr, const size_t size, const int term_sig) {
	for (size_t i = 0; i < size; i += 1) {
		if (arr[i] <= 0) {
			continue;
		}
		kill(arr[i], term_sig);
	}

	for (size_t i = 0; i < size; i += 1) {
		if (arr[i] <= 0) {
			continue;
		}
		waitpid(arr[i], NULL, 0);
		arr[i] = 0;
	}
}

static int do_service (void) {
	pid_t arr[params.nchild];
	int ec;
	int caught;

	memset(arr, 0, sizeof(pid_t) * params.nchild);

	for (unsigned long i = 0; i < params.nchild; i += 1) {
		arr[i] = fork();
		if (arr[i] < 0) {
			perror(ARGV0": fork()");
			reap_procs(arr, params.nchild, SIGKILL);
			return 1;
		}
		else if (arr[i] == 0) {
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

	pause();

	reap_procs(arr, params.nchild, SIGHUP);
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

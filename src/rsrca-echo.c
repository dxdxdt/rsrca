#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <pthread.h>
#include <sys/types.h>
#ifdef WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#else
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netdb.h>
#include <unistd.h>
#endif
#define ARGV0 "rsrca-echo"


struct {
	const char *addr;
	const char *port;
	size_t maxlen;
	unsigned long nproc;
	int verbose;
	int af;
	int pmtud;
	struct {
		bool help;
		bool nosend;
	} flags;
} params;

struct {
#ifdef WIN32
	SOCKET fd;
#else
	int fd;
#endif
	pthread_mutex_t stdio_l;
} g;

#ifdef WIN32
#define ISSOCKVALID(x) ((x) != INVALID_SOCKET)
#define psockerr(x) fprintf(stderr, "%s%sWSA error %d\n", (x) == NULL ? "" : (x), (x) == NULL ? "" : ": ", WSAGetLastError())
#else
#define ISSOCKVALID(x) ((x) >= 0)
#define psockerr(x) perror(x)
#endif

static bool ismemzero (const void *m, const size_t len) {
	const uint8_t *p = m;

	for (size_t i = 0; i < len; i += 1) {
		if (p[i] != 0) {
			return false;
		}
	}
	return true;
}

static void init_params (void) {
	params.port = "2007";
	params.verbose = 1;
	params.pmtud = -1;
}

static void init_g (void) {
#ifdef WIN32
	g.fd = INVALID_SOCKET;
#else
	g.fd = -1;
#endif
	pthread_mutex_init(&g.stdio_l, NULL);
}

static bool parse_args (const int argc, const char **argv) {
	int fr;

	while (true) {
		fr = getopt(argc, (char*const*)argv, "vhT:Nl:");
		if (fr < 0) {
			break;
		}

		switch (fr) {
		case 'v': params.verbose += 1; break;
		case 'h': params.flags.help = true; break;
		case 'T':
			if (sscanf(optarg, "%lu", &params.nproc) != 1) {
				fprintf(stderr, ARGV0": -T %s: ", optarg);
				errno = EINVAL;
				perror(NULL);
				return false;
			}
			break;
		case 'N': params.flags.nosend = true; break;
		case 'l':
			if (sscanf(optarg, "%zu", &params.maxlen) != 1) {
				fprintf(stderr, ARGV0": -l %s: ", optarg);
				errno = EINVAL;
				perror(NULL);
				return false;
			}
			break;
		default:
			return false;
		}
	}

	if (optind + 1 < argc) {
		params.addr = argv[optind];
		params.port = argv[optind + 1];
	}
	else if (optind < argc) {
		params.port = argv[optind];
	}

	return true;
}

static bool parse_env (void) {
	static const char KEY[] = "RSRCA_PMTUDISC=";
	const char **p, *env, *val_src;
	char val[12];
	size_t i;

	for (p = (const char **)environ; *p != NULL; p += 1) {
		env = *p;
		if (strstr(env, KEY) == env) {
			val_src = env + (sizeof(KEY) - 1);
		}
		else {
			continue;
		}

		for (i = 0; i < 11 && val_src[i] != 0; i += 1) {
			if ('a' <= val_src[i] && val_src[i] <= 'z') {
				val[i] = val_src[i] - ('a' - 'A');
			}
			else {
				val[i] = val_src[i];
			}
		}
		val[i] = 0;

#ifdef IPV6_PMTUDISC_DONT
		static_assert(IPV6_PMTUDISC_DONT == IP_PMTUDISC_DONT);
#endif
#ifdef IPV6_PMTUDISC_DO
		static_assert(IPV6_PMTUDISC_DO == IP_PMTUDISC_DO);
#endif
#ifdef IPV6_PMTUDISC_PROBE
		static_assert(IPV6_PMTUDISC_PROBE == IP_PMTUDISC_PROBE);
#endif

		if (*val == 0) {
			params.pmtud = -1;
		}
		else if (strcmp(val, "WANT") == 0) {
#ifdef IP_PMTUDISC_WANT
			static_assert(IPV6_PMTUDISC_WANT == IP_PMTUDISC_WANT);
			params.pmtud = IP_PMTUDISC_WANT;
#else
			errno = ENOTSUP;
			fprintf(stderr, ARGV0": %s: ", env);
			perror(NULL);
			return false;
#endif
		}
		else if (strcmp(val, "DONT") == 0) {
			params.pmtud = IP_PMTUDISC_DONT;
		}
		else if (strcmp(val, "DO") == 0) {
			params.pmtud = IP_PMTUDISC_DO;
		}
		else if (strcmp(val, "PROBE") == 0) {
			params.pmtud = IP_PMTUDISC_PROBE;
		}
		else if (sscanf(val, "%d", &params.pmtud) != 1) {
			fprintf(stderr, ARGV0": %s: ", env);
			errno = EINVAL;
			perror(NULL);
			return false;
		}
	}

	return true;
}

static void print_help (void) {
	printf(
		"Usage: "ARGV0" [-vhN] [-T THREADS] [-l MAXLEN]\n"
		"ENV: RSRCA_PMTUDISC=WANT|DONT|DO|PROBE\n"
	);
}

static void th_lock_stdio (void) {
	pthread_mutex_lock(&g.stdio_l);
}

static void th_unlock_stdio (void) {
	pthread_mutex_unlock(&g.stdio_l);
}

static void th_print_header (FILE *f) {
#ifdef WIN32
	const pthread_t th = pthread_self();

	fprintf(f, "%"PRIxPTR":\t", (uintptr_t)th);
#else
	fprintf(f, "%ld:\t", (long)gettid());
#endif
}

static void print_sin (FILE *f, const struct sockaddr *sa_in, const int v6only) {
	union {
		const struct sockaddr *sa;
		const struct sockaddr_in *sin;
		const struct sockaddr_in6 *sin6;
	} addr;
	char addrstr[INET6_ADDRSTRLEN] = { 0, };
	const void *addr_loc;
	uint16_t port;
	const char *pfmt;
	const char *fr;

	addr.sa = sa_in;

	static_assert(INET6_ADDRSTRLEN > INET_ADDRSTRLEN);
	assert(addr.sa->sa_family == AF_INET || addr.sa->sa_family == AF_INET6);

	switch (addr.sa->sa_family) {
	case AF_INET:
		addr_loc = &addr.sin->sin_addr;
		port = ntohs(addr.sin->sin_port);
		pfmt = "%s:%"PRIu16;
		break;
	case AF_INET6:
		addr_loc = &addr.sin6->sin6_addr;
		port = ntohs(addr.sin6->sin6_port);
		if (addr.sin6->sin6_scope_id == 0) {
			if (ismemzero(&addr.sin6->sin6_addr, sizeof(addr.sin6->sin6_addr)) &&
					v6only == 0)
			{
				addrstr[0] = '*';
				pfmt = "%s:%"PRIu16;
			}
			else {
				pfmt = "[%s]:%"PRIu16;
			}
		}
		else {
			pfmt = "[%s%%%"PRIu32"]:%"PRIu16;
		}
		break;
	default:
		abort();
	}

	if (addrstr[0] == 0) {
		fr = inet_ntop(addr.sa->sa_family, addr_loc, addrstr, sizeof(addrstr));
		assert(fr != NULL);
		(void)fr;
	}

	if (addr.sa->sa_family == AF_INET6 && addr.sin6->sin6_scope_id == 0) {
		fprintf(f, pfmt, addrstr, port);
	}
	else {
		fprintf(f, pfmt, addrstr, addr.sin6->sin6_scope_id, port);
	}
}

static void th_reply (
		const struct sockaddr *sa,
		const socklen_t sl,
		const void *buf,
		size_t len)
{
	ssize_t fr;
	int flags;

	assert(sl >= (socklen_t)sizeof(struct sockaddr_in) && sa != NULL);

	if (params.maxlen > 0 && params.maxlen < len) {
		len = params.maxlen;
	}

	flags = 0;
#ifdef MSG_NOSIGNAL
	flags |= MSG_NOSIGNAL;
#endif
#ifdef MSG_DONTWAIT
	// caveat: without this flag, if the destination is a neighbour node,
	// sendto() could block until NDISC is completed. There's no WSA equivalent.

	// TODO: find out whether the Windows kernel exhibits the same behaviour.
	flags |= MSG_DONTWAIT;
#endif

	fr = sendto(g.fd, buf, len, flags, sa, sl);
	if (params.verbose > 1) {
#ifdef WIN32
		// FIXME: useless statement unless the socket is in nonblocking mode
		if (WSAGetLastError() == WSAEWOULDBLOCK) {
			return;
		}
#else
		switch (errno) {
		case EAGAIN:
#if EAGAIN != EWOULDBLOCK
		case EWOULDBLOCK:
#endif
			return;
		}
#endif
		if (fr < 0) {
			th_lock_stdio();
			th_print_header(stderr);
			psockerr(ARGV0": sendto()");
			th_unlock_stdio();
		}
		else {
			th_lock_stdio();
			th_print_header(stdout);
			printf("sent %zu to ", (size_t)fr);
			print_sin(stdout, sa, -1);
			printf("\n");
			th_unlock_stdio();
		}
	}
}

static void *th_main (void*) {
	union {
		struct sockaddr_storage ss;
		struct sockaddr sa;
	} addr = { 0, };
	socklen_t sl;
	ssize_t rlen;
	uint8_t msgbuf[65535];

	while (true) {
		sl = sizeof(addr);
		rlen = recvfrom(g.fd, (char*)msgbuf, sizeof(msgbuf), 0, &addr.sa, &sl);
		if (rlen < 0) {
#ifdef WIN32
			switch (WSAGetLastError()) {
			case WSAENETRESET:
			case WSAECONNRESET:
				goto tail;
			}
#else
			switch (errno) {
			case ECONNREFUSED:
			case EINTR:
				goto tail;
			}
#endif
			th_lock_stdio();
			psockerr(ARGV0": recvfrom()");
			abort();
tail:
			if (params.verbose > 1) {
				th_lock_stdio();
				th_print_header(stderr);
				psockerr(ARGV0": recvfrom()");
				th_unlock_stdio();
				continue;
			}
		}

		if (params.verbose > 1) {
			th_lock_stdio();
			th_print_header(stdout);
			printf("received %zu from ", (size_t)rlen);
			print_sin(stdout, &addr.sa, -1);
			printf("\n");
			th_unlock_stdio();
		}

		if (!params.flags.nosend) {
			th_reply(&addr.sa, sl, msgbuf, (size_t)rlen);
		}
	}

	abort();
}

static void report_sockname (void) {
	union {
		struct sockaddr sa;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	} addr;
	socklen_t sl = sizeof(addr);
	int v6only = -1;

	memset(&addr, 0, sizeof(addr));
	getsockname(g.fd, &addr.sa, &sl);

#ifdef IPV6_V6ONLY
	if (addr.sa.sa_family == AF_INET6) {
		socklen_t sl = sizeof(v6only);
		getsockopt(g.fd, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&v6only, &sl);
	}
#endif

	fprintf(stderr, ARGV0": bound on ");
	print_sin(stderr, &addr.sa, v6only);
	fprintf(stderr, "\n");
}

static bool setup_socket (void) {
	bool ret = false;
	struct addrinfo hints = { 0, };
	struct addrinfo *ai = NULL;
	struct addrinfo *p, *target;
	int fr, slevel, sopt;

	hints.ai_flags = AI_PASSIVE;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	fr = getaddrinfo(params.addr, params.port, &hints, &ai);
	if (fr != 0) {
		fprintf(stderr, ARGV0": getaddrinfo(): %s\n", gai_strerror(fr));
		goto END;
	}

	target = ai;
	if (params.af == 0) {
		// if no AF option is specified, prefer IPv6 to serve v4 and v6 with one
		// socket
		for (p = ai; p != NULL; p = p->ai_next) {
			if (p->ai_family == AF_INET6) {
				target = p;
				break;
			}
		}
	}

#ifdef WIN32
	closesocket(g.fd);
#else
	close(g.fd);
#endif
	g.fd = socket(target->ai_family, target->ai_socktype, target->ai_protocol);
	if (!ISSOCKVALID(g.fd)) {
		psockerr(ARGV0": socket()");
		goto END;
	}

#ifdef IPV6_V6ONLY
	if (target->ai_family == AF_INET6 && params.af == 0) {
		const int ov = 0;
		setsockopt(g.fd, IPPROTO_IPV6, IPV6_V6ONLY, (const char*)&ov, sizeof(ov));
	}
#endif

	if (params.pmtud >= 0) {
		assert(target->ai_family == AF_INET || target->ai_family == AF_INET6);
		switch (target->ai_family) {
		case AF_INET:
			slevel = IPPROTO_IP;
			sopt = IP_MTU_DISCOVER;
			fprintf(stderr, ARGV0": setting IP_MTU_DISCOVER to %d\n", params.pmtud);
			break;
		case AF_INET6:
			slevel = IPPROTO_IPV6;
			sopt = IPV6_MTU_DISCOVER;
			fprintf(stderr, ARGV0": setting IPV6_MTU_DISCOVER to %d\n", params.pmtud);
			break;
		default:
			abort();
		}
		fr = setsockopt(
			g.fd,
			slevel,
			sopt,
			(const char*)&params.pmtud,
			sizeof(params.pmtud));
		if (fr != 0) {
			fprintf(
				stderr,
				ARGV0": setsockopt(..., %d, %d, ...):",
				sopt,
				params.pmtud);
			psockerr(NULL);
			goto END;
		}
	}

	fr = bind(g.fd, target->ai_addr, target->ai_addrlen);
	if (fr != 0) {
		psockerr(ARGV0": bind()");
		goto END;
	}

	report_sockname();

	ret = true;
END:
	freeaddrinfo(ai);
	return ret;
}

static unsigned long get_nproc (void) {
	long ret;
#ifdef WIN32
	SYSTEM_INFO si = { 0, };

	GetSystemInfo(&si);
	// technically, this is not the same as _SC_NPROCESSORS_ONLN but who cares?
	ret = (unsigned long)si.dwNumberOfProcessors;
#else
	ret = sysconf(_SC_NPROCESSORS_ONLN);
#endif
	assert(ret > 0);
	return (unsigned long)ret;
}

#ifdef WIN32
static void start_wsa (void) {
	int fr;
	WSADATA wsaData = {0};

	fr = WSAStartup(MAKEWORD(2, 2), &wsaData);
	assert(fr == 0);
	(void)fr;
}
#endif

int main (const int argc, const char **argv) {
	unsigned long nchild;
	unsigned long i;
	int fr;
	pthread_t th;

	init_params();
	init_g();

	if (!parse_args(argc, argv) || !parse_env()) {
		return 2;
	}

	if (params.flags.help) {
		print_help();
		return 0;
	}

#ifdef WIN32
	start_wsa();
#endif

	if (!setup_socket()) {
		return 1;
	}

	nchild = params.nproc == 0 ? get_nproc() : params.nproc;
	for (i = 0; i < nchild; i += 1) {
		fr = pthread_create(&th, NULL, th_main, NULL);
		if (fr != 0) {
			perror(ARGV0": pthread_create()");
			abort();
		}
	}

	pthread_join(th, NULL); // should never return
	abort();
}

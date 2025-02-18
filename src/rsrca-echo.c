#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
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
	pthread_spinlock_t stdio_l;
} g;

#ifdef WIN32
#define ISSOCKVALID(x) ((x) != INVALID_SOCKET)
#define psockerr(x) fprintf(stderr, "%s%sWSA error %d\n", (x) == NULL ? "" : (x), (x) == NULL ? "" : ": ", WSAGetLastError())
#else
#define ISSOCKVALID(x) ((x) >= 0)
#define psockerr(x) perror(x)
#endif

static void init_params (void) {
	params.port = "2007";
	params.verbose = 1;
}

static void init_g (void) {
#ifdef WIN32
	g.fd = INVALID_SOCKET;
#else
	g.fd = -1;
#endif
	pthread_spin_init(&g.stdio_l, true);
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
				perror(NULL);
				return false;
			}
			break;
		case 'N': params.flags.nosend = true; break;
		case 'l':
			if (sscanf(optarg, "%zu", &params.maxlen) != 1) {
				fprintf(stderr, ARGV0": -l %s: ", optarg);
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

static void print_help (void) {
	// TODO
}

static void th_lock_stdio (void) {
	pthread_spin_lock(&g.stdio_l);
}

static void th_unlock_stdio (void) {
	pthread_spin_unlock(&g.stdio_l);
}

static void th_print_header (FILE *f) {
#ifdef WIN32
	const pthread_t th = pthread_self();

	fprintf(f, "%"PRIxPTR":\t", (uintptr_t)th);
#else
	fprintf(f, "%ld:\t", (long)gettid());
#endif
}

static void print_sin (FILE *f, const struct sockaddr *sa_in) {
	union {
		const struct sockaddr *sa;
		const struct sockaddr_in *sin;
		const struct sockaddr_in6 *sin6;
	} addr;
	char addrstr[INET6_ADDRSTRLEN];
	const void *addr_loc;
	uint16_t port;
	const char *pfmt;
	const char *fr;

	addr.sa = sa_in;
	addrstr[0] = 0;

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
		pfmt = "[%s]:%"PRIu16;
		break;
	default:
		abort();
	}

	fr = inet_ntop(addr.sa->sa_family, addr_loc, addrstr, sizeof(addrstr));
	assert(fr != NULL);
	(void)fr;

	fprintf(f, pfmt, addrstr, port);
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

	fr = sendto(g.fd, buf, len, flags, sa, sl);
	if (params.verbose > 1) {
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
			print_sin(stdout, sa);
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
			print_sin(stdout, &addr.sa);
			printf("\n");
			th_unlock_stdio();
		}

		if (!params.flags.nosend) {
			th_reply(&addr.sa, sl, msgbuf, (size_t)rlen);
		}
	}

	abort();
}

static bool setup_socket (void) {
	bool ret = false;
	struct addrinfo hints = { 0, };
	struct addrinfo *ai = NULL;
	struct addrinfo *p, *target;
	int fr;

	hints.ai_flags = AI_PASSIVE;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	fr = getaddrinfo(params.addr, params.port, &hints, &ai);
	if (fr != 0) {
		fprintf(stderr, ARGV0": getaddrinfo(): %s\n", gai_strerror(fr));
		goto END;
	}

	target = ai;
	// prefer IPv6 to serve v4 and v6 with one socket
	for (p = ai; p != NULL; p = p->ai_next) {
		if (p->ai_family == AF_INET6) {
			target = p;
			break;
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

	fr = bind(g.fd, target->ai_addr, target->ai_addrlen);
	if (fr != 0) {
		psockerr(ARGV0": bind()");
		goto END;
	}

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

	if (!parse_args(argc, argv)) {
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

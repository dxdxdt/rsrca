#include <stdint.h>
#include <stddef.h>

struct ip6_hdr;

uint16_t calc_chksum6 (
	const struct ip6_hdr *ih,
	const void *nh,
	size_t n_len,
	const void *data,
	size_t data_len);
uint16_t calc_chksum6_udp (
	const struct ip6_hdr *ih,
	const void *nh,
	size_t n_len,
	const void *data,
	size_t data_len);

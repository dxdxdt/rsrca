#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <assert.h>


struct dns_header {
	uint16_t id; // identification number

	bool rd :1; // recursion desired
	bool tc :1; // truncated message
	bool aa :1; // authoritive answer
	uint8_t opcode :4; // purpose of message
	bool qr :1; // query/response flag

	uint8_t rcode :4; // response code
	bool cd :1; // checking disabled
	bool ad :1; // authenticated data
	bool z :1; // its z! reserved
	bool ra :1; // recursion available

	uint16_t q_count; // number of question entries
	uint16_t ans_count; // number of answer entries
	uint16_t auth_count; // number of authority entries
	uint16_t add_count; // number of resource entries
};
static_assert(sizeof(struct dns_header) == 12);

struct dns_qd {
	uint16_t qtype;
	uint16_t qclass;
};
static_assert(sizeof(struct dns_qd) == 4);

#pragma pack(push, 1)
struct dns_rdata {
	uint16_t type;
	uint16_t class;
	uint32_t ttl;
	uint16_t data_len;
};
#pragma pack(pop)
static_assert(sizeof(struct dns_rdata) == 10);

struct dns_query {
	char name[256];
	struct dns_qd desc;
};


bool dns_foreach_label (
		const char *in_rname,
		void *uc,
		bool(*cb)(char *label, uint8_t len, void *uc));
size_t dns_labelize (const char *str, void *out, const size_t olen);

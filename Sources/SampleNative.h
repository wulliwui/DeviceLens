#include <stddef.h>

// Returns zero on success, including when the resolver has no IPv4 servers.
int sample_dns_servers(char *output, size_t capacity);

// Reads the pdp_ip0 transmit counter using NET_RT_IFLIST2.
int sample_cell_transmitted_bytes(unsigned long long *output);

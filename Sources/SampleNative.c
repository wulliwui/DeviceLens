#include "SampleNative.h"
#include <arpa/inet.h>
#include <net/if.h>
#include <resolv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>

// RTM_IFINFO2 from Darwin; iOS exposes if_msghdr2 in net/if.h.
enum { sample_route_ifinfo2 = 0x12 };

int sample_dns_servers(char *output, size_t capacity) {
    if (capacity == 0) return -1;
    output[0] = '\0';
    struct __res_state state = {0};
    if (res_ninit(&state) != 0) return -1;
    size_t used = 0;
    int result = 0;
    for (int i = 0; i < state.nscount && i < MAXNS; i++) {
        char address[INET_ADDRSTRLEN];
        if (!inet_ntop(AF_INET, &state.nsaddr_list[i].sin_addr, address, sizeof(address))) continue;
        int written = snprintf(output + used, capacity - used, "%s%s", used ? "," : "", address);
        if (written < 0 || (size_t)written >= capacity - used) {
            result = -1;
            break;
        }
        used += (size_t)written;
    }
    res_ndestroy(&state);
    return result;
}

int sample_cell_transmitted_bytes(unsigned long long *output) {
    int mib[] = {CTL_NET, PF_ROUTE, 0, 0, NET_RT_IFLIST2, 0};
    size_t length = 0;
    *output = 0;
    if (sysctl(mib, 6, NULL, &length, NULL, 0) != 0 || length == 0) return -1;
    char *messages = malloc(length);
    if (!messages) return -1;
    if (sysctl(mib, 6, messages, &length, NULL, 0) != 0) {
        free(messages);
        return -1;
    }
    for (size_t offset = 0; length - offset >= 4;) {
        unsigned short messageLength;
        memcpy(&messageLength, messages + offset, sizeof(messageLength));
        if (messageLength < 4 || messageLength > length - offset) break;
        if (messages[offset + 3] == sample_route_ifinfo2 && messageLength >= sizeof(struct if_msghdr2)) {
            struct if_msghdr2 message;
            memcpy(&message, messages + offset, sizeof(message));
            char name[IF_NAMESIZE] = {0};
            if (if_indextoname(message.ifm_index, name) && strcmp(name, "pdp_ip0") == 0)
                *output += message.ifm_data.ifi_obytes;
        }
        offset += messageLength;
    }
    free(messages);
    return 0;
}

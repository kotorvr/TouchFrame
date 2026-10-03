// Host test helper: prints the hop sequence for (netaddr, map, start, n) so test.py can compare it
// with an independent Python implementation. Also checks beacon parsing round-trips.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/pulsar_hop.h"

int main(int argc, char** argv) {
    if (argc == 2 && !strcmp(argv[1], "parse")) {
        // beacon bytes on stdin as hex pairs -> "map unmapped" or "reject"
        unsigned b[64];
        int n = 0;
        while (n < 64 && scanf("%2x", &b[n]) == 1) n++;
        uint8_t p[64];
        for (int i = 0; i < n; i++) p[i] = (uint8_t)b[i];
        uint64_t map;
        uint8_t un;
        if (pulsar_parse_beacon(p, (uint8_t)n, &map, &un)) printf("%llx %u\n", (unsigned long long)map, un);
        else printf("reject\n");
        return 0;
    }
    if (argc != 5) return 2;
    pulsar_hop_t h;
    h.hop = pulsar_hop_increment((uint32_t)strtoul(argv[1], 0, 0));
    h.map = strtoull(argv[2], 0, 0);
    h.unmapped = (uint8_t)atoi(argv[3]);
    int count = atoi(argv[4]);
    for (int i = 0; i < count; i++) printf("%u ", pulsar_channel_mhz(pulsar_hop_next(&h)));
    printf("\n");
    return 0;
}

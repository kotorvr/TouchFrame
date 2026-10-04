// Host helper for test_ll.py: builds the byte formats the firmware transmits so Python can check
// them against independent models (the sniffer's beacon parser, tools/pulsar_host.py).
//   ll_test beacon <map> <unmapped> <dm_in> <session> <ts> <cl_mask> <ack>  -> 16 bytes hex
//   ll_test pairdata <shared 64 hex> <netaddr> <key 32 hex> <iv 16 hex>     -> 32 bytes hex
//   ll_test unpair <shared 64 hex> <payload 64 hex>                         -> "netaddr key" or "fail"
//   ll_test advert <device_id>                                              -> 32 bytes hex
//   ll_test dm <netaddr> <periods>                                          -> announce per period
//   ll_test legacy <session> <beacon_ts>                                    -> 13-byte nonce hex
//   ll_test steady <counter> <iv 16 hex>                                    -> 13-byte nonce hex
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/pulsar_ll.h"
#include "../src/pulsar_pair.h"

static void unhex(const char* s, uint8_t* out, size_t n) {
    for (size_t i = 0; i < n; i++) {
        unsigned v = 0;
        sscanf(s + 2 * i, "%2x", &v);
        out[i] = (uint8_t)v;
    }
}

static void hex(const uint8_t* b, size_t n) {
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
    printf("\n");
}

int main(int argc, char** argv) {
    if (argc == 9 && !strcmp(argv[1], "beacon")) {
        pulsar_beacon_t b = {strtoull(argv[2], 0, 0), (uint8_t)atoi(argv[3]), (uint8_t)atoi(argv[4]),
                             (uint16_t)strtoul(argv[5], 0, 0), strtoull(argv[6], 0, 0),
                             (uint8_t)strtoul(argv[7], 0, 0), (uint8_t)strtoul(argv[8], 0, 0)};
        uint8_t out[PULSAR_BEACON_HDR_LEN];
        pulsar_beacon_build(&b, out);
        pulsar_beacon_t back;
        if (!pulsar_beacon_parse(out, sizeof out, &back) || back.map != b.map || back.unmapped != b.unmapped ||
            back.dm_in != b.dm_in || back.session_nonce != b.session_nonce ||
            back.timestamp_us != (b.timestamp_us & 0xFFFFFFFFFFFFull) || back.cl_slot_mask != b.cl_slot_mask ||
            back.ack_mask != b.ack_mask) {
            printf("roundtrip-fail\n");
            return 1;
        }
        hex(out, sizeof out);
        return 0;
    }
    if (argc == 6 && !strcmp(argv[1], "pairdata")) {
        uint8_t shared[32], key[16], iv[8], out[PAIR_DATA_LEN];
        unhex(argv[2], shared, 32);
        unhex(argv[4], key, 16);
        unhex(argv[5], iv, 8);
        pair_data_build(shared, (uint32_t)strtoul(argv[3], 0, 0), key, iv, out);
        hex(out, sizeof out);
        return 0;
    }
    if (argc == 4 && !strcmp(argv[1], "unpair")) {
        uint8_t shared[32], in[PAIR_DATA_LEN], key[16];
        uint32_t netaddr;
        unhex(argv[2], shared, 32);
        unhex(argv[3], in, PAIR_DATA_LEN);
        if (!pair_data_parse(shared, in, &netaddr, key)) {
            printf("fail\n");
            return 0;
        }
        printf("%08x ", netaddr);
        hex(key, 16);
        return 0;
    }
    if (argc == 3 && !strcmp(argv[1], "advert")) {
        uint8_t out[PAIR_ADVERT_LEN];
        pair_advert_build(strtoull(argv[2], 0, 0), 0x0301, out);
        pair_advert_t a;
        if (!pair_advert_parse(out, sizeof out, &a) || a.device_id != strtoull(argv[2], 0, 0) ||
            a.pulsar_version != PULSAR_VERSION) {
            printf("roundtrip-fail\n");
            return 1;
        }
        hex(out, sizeof out);
        return 0;
    }
    if (argc == 4 && !strcmp(argv[1], "dm")) {
        pulsar_dm_t dm;
        pulsar_dm_init(&dm, (uint32_t)strtoul(argv[2], 0, 0));
        for (int i = 0; i < atoi(argv[3]); i++) {
            uint8_t ann;
            bool is_dm = pulsar_dm_next(&dm, &ann);
            printf("%s ", is_dm ? "D" : (char[2]){(char)('0' + ann), 0});
        }
        printf("\n");
        return 0;
    }
    if (argc == 4 && !strcmp(argv[1], "legacy")) {
        uint8_t n[13];
        pulsar_nonce_legacy((uint16_t)strtoul(argv[2], 0, 0), strtoull(argv[3], 0, 0), n);
        hex(n, 13);
        return 0;
    }
    if (argc == 4 && !strcmp(argv[1], "steady")) {
        uint8_t n[13], iv[8];
        unhex(argv[3], iv, 8);
        pulsar_nonce_steady((uint32_t)strtoul(argv[2], 0, 0), iv, n);
        hex(n, 13);
        return 0;
    }
    return 2;
}

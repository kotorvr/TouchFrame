// Host helper for test_ll.py: builds the byte formats the firmware transmits so Python can check
// them against independent models (the sniffer's beacon parser, tools/pulsar_host.py).
//   ll_test beacon <map> <unmapped> <dm_in> <session> <ts> <cl_mask> <ack>  -> 16 bytes hex
//   ll_test pairdata <shared 64 hex> <netaddr> <key 32 hex> <iv 16 hex>     -> 32 bytes hex
//   ll_test unpair <shared 64 hex> <payload 64 hex>                         -> "netaddr key" or "fail"
//   ll_test advert <device_id>                                              -> 32 bytes hex
//   ll_test dm <netaddr> <periods>                                          -> announce per period
//   ll_test legacy <session> <beacon_ts>                                    -> 13-byte nonce hex
//   ll_test steady <counter> <iv 16 hex>                                    -> 13-byte nonce hex
//   ll_test conn <device_id> <slot> <iv 16 hex>                             -> cl_real accept hex
//   ll_test req <device_id> <iv 16 hex>                                     -> cl_real request hex
//   ll_test tl <reg> <seq> <read> <payload hex or ->                        -> cl_real TL request hex
//   ll_test led <mode> <period> <on> <phase>                                -> cl_real TL packet hex (seq 0)
//   ll_test haptic <mode> <amplitude> <freq>                                -> cl_real TL packet hex (seq 0)
//   ll_test tlup <plaintext hex>                                            -> "slot reg flags datahex" or "none"
//   ll_test ntf <payload hex> ...                                           -> "type:hex" per chunk, one
//                                                                              unpacker over all payloads
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/pulsar_cl.h"
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

static void print_chunk(void* user, uint8_t type, const uint8_t* d, uint8_t n) {
    (void)user;
    printf("%u:", type);
    for (uint8_t i = 0; i < n; i++) printf("%02x", d[i]);
    printf(" ");
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
    if (argc == 5 && !strcmp(argv[1], "conn")) {
        cl_msg_t m, back;
        memset(&m, 0, sizeof m);
        m.type = CL_CONN_ACCEPT;
        m.u.conn.device_id = strtoull(argv[2], 0, 0);
        m.u.conn.slot = (uint8_t)atoi(argv[3]);
        m.u.conn.version = PULSAR_VERSION;
        m.u.conn.fmt = 2;
        unhex(argv[4], m.u.conn.iv, 8);
        uint8_t out[CL_DOWN_MAX];
        int n = cl_real.encode(&m, out, sizeof out);
        if (n < 0) {
            printf("refused\n");
            return 0;
        }
        if (!cl_real.decode(out, n, CL_DIR_DOWN, &back) || back.type != CL_CONN_ACCEPT ||
            back.u.conn.device_id != m.u.conn.device_id || back.u.conn.slot != m.u.conn.slot) {
            printf("roundtrip-fail\n");
            return 1;
        }
        hex(out, (size_t)n);
        return 0;
    }
    if (argc == 6 && !strcmp(argv[1], "tl")) {
        cl_msg_t m;
        memset(&m, 0, sizeof m);
        bool read = atoi(argv[4]);
        m.type = read ? CL_REG_READ : CL_REG_WRITE;
        m.seq = (uint8_t)atoi(argv[3]);
        m.u.reg.reg = (uint8_t)strtoul(argv[2], 0, 0);
        uint8_t n = strcmp(argv[5], "-") ? (uint8_t)(strlen(argv[5]) / 2) : 0;
        unhex(argv[5], m.u.reg.data, n);
        if (read) m.u.reg.n = n;
        else m.u.reg.len = n;
        uint8_t out[CL_DOWN_MAX];
        int k = cl_real.encode(&m, out, sizeof out);
        if (k < 0) {
            printf("refused\n");
            return 0;
        }
        hex(out, (size_t)k);
        return 0;
    }
    if ((argc == 6 && !strcmp(argv[1], "led")) || (argc == 5 && !strcmp(argv[1], "haptic"))) {
        cl_msg_t m;
        memset(&m, 0, sizeof m);
        if (argc == 6) {
            m.type = CL_LED;
            m.u.led.mode = (uint8_t)atoi(argv[2]);
            m.u.led.period_us = (uint32_t)strtoul(argv[3], 0, 0);
            m.u.led.on_us = (uint32_t)strtoul(argv[4], 0, 0);
            m.u.led.phase_us = (int32_t)strtol(argv[5], 0, 0);
        } else {
            m.type = CL_HAPTIC;
            m.u.haptic.mode = (uint8_t)atoi(argv[2]);
            m.u.haptic.amplitude = (uint8_t)atoi(argv[3]);
            m.u.haptic.freq_hz = (uint16_t)atoi(argv[4]);
        }
        uint8_t out[CL_DOWN_MAX];
        int k = cl_real.encode(&m, out, sizeof out);
        if (k < 0) {
            printf(k == CL_PENDING_RE ? "pending\n" : "refused\n");
            return 0;
        }
        hex(out, (size_t)k);
        return 0;
    }
    if (argc == 3 && !strcmp(argv[1], "tlup")) {
        uint8_t in[CL_UP_MAX];
        size_t n = strlen(argv[2]) / 2;
        unhex(argv[2], in, n);
        cl_msg_t m;
        if (!cl_real.decode(in, (int)n, CL_DIR_UP, &m) || m.type != CL_TL_UP) {
            printf("none\n");
            return 0;
        }
        printf("%u %u %u ", m.u.tl.slot, m.u.tl.reg, m.u.tl.flags);
        hex(m.u.tl.data, m.u.tl.n);
        return 0;
    }
    if (argc >= 3 && !strcmp(argv[1], "ntf")) {
        cl_ntf_t st;
        memset(&st, 0, sizeof st);
        for (int i = 2; i < argc; i++) {
            uint8_t in[CL_UP_MAX];
            size_t n = strcmp(argv[i], "-") ? strlen(argv[i]) / 2 : 0;
            unhex(argv[i], in, n);
            cl_ntf_unpack(&st, in, (int)n, print_chunk, NULL);
        }
        printf("\n");
        return 0;
    }
    if (argc == 4 && !strcmp(argv[1], "req")) {
        cl_msg_t m, back;
        memset(&m, 0, sizeof m);
        m.type = CL_CONN_REQ;
        m.u.conn.device_id = strtoull(argv[2], 0, 0);
        m.u.conn.version = PULSAR_VERSION;
        unhex(argv[3], m.u.conn.iv, 8);
        uint8_t out[CL_UP_MAX];
        int n = cl_real.encode(&m, out, sizeof out);
        if (n < 0 || !cl_real.decode(out, n, CL_DIR_UP, &back) || back.u.conn.device_id != m.u.conn.device_id ||
            memcmp(back.u.conn.iv, m.u.conn.iv, 8)) {
            printf("roundtrip-fail\n");
            return 1;
        }
        hex(out, (size_t)n);
        return 0;
    }
    return 2;
}

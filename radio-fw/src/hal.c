#include "hal.h"

#include <string.h>

#include "crypto.h"
#include "nrf.h"

// CCM data structure (nRF52840 PS "CCM"): KEY[16], PKTCTR (39 bits in 8 bytes), DIRECTION, IV[8]
typedef struct __attribute__((packed)) {
    uint8_t key[16];
    uint8_t pktctr[8];
    uint8_t direction;
    uint8_t iv[8];
} ccm_cnf_t;

static ccm_cnf_t cnf;
static uint8_t ccm_in[3 + 256], ccm_out[3 + 256];
static uint8_t scratch[16 + 256] __attribute__((aligned(4)));

bool hal_ccm(bool encrypt, const uint8_t key[16], const uint8_t nonce[13], const uint8_t* in, uint8_t len,
             uint8_t* out) {
    if (len == 0 || (!encrypt && len <= PULSAR_MIC_LEN) || (encrypt && len > 251 - PULSAR_MIC_LEN)) {
        if (encrypt) {
            pulsar_ccm_encrypt(key, nonce, 0, in, len, out);
            return true;
        }
        return pulsar_ccm_decrypt(key, nonce, 0, in, len, out);
    }
    memcpy(cnf.key, key, 16);
    memset(cnf.pktctr, 0, sizeof cnf.pktctr);
    memcpy(cnf.pktctr, nonce, 5);
    cnf.pktctr[4] &= 0x7F;
    cnf.direction = nonce[4] >> 7;
    memcpy(cnf.iv, nonce + 5, 8);
    // packet in RAM: [header][length][RFU][payload]; header 0 -> AAD 0x00 (masked with 0xE3)
    ccm_in[0] = 0;
    ccm_in[1] = len;
    ccm_in[2] = 0;
    memcpy(ccm_in + 3, in, len);

    NRF_CCM->ENABLE = CCM_ENABLE_ENABLE_Enabled;
    NRF_CCM->MODE = (encrypt ? CCM_MODE_MODE_Encryption : CCM_MODE_MODE_Decryption) << CCM_MODE_MODE_Pos |
                    CCM_MODE_DATARATE_2Mbit << CCM_MODE_DATARATE_Pos | CCM_MODE_LENGTH_Extended << CCM_MODE_LENGTH_Pos;
    NRF_CCM->MAXPACKETSIZE = 251;
    NRF_CCM->CNFPTR = (uint32_t)&cnf;
    NRF_CCM->INPTR = (uint32_t)ccm_in;
    NRF_CCM->OUTPTR = (uint32_t)ccm_out;
    NRF_CCM->SCRATCHPTR = (uint32_t)scratch;
    NRF_CCM->SHORTS = CCM_SHORTS_ENDKSGEN_CRYPT_Msk;
    NRF_CCM->EVENTS_ENDKSGEN = 0;
    NRF_CCM->EVENTS_ENDCRYPT = 0;
    NRF_CCM->EVENTS_ERROR = 0;
    NRF_CCM->TASKS_KSGEN = 1;
    while (!NRF_CCM->EVENTS_ENDCRYPT && !NRF_CCM->EVENTS_ERROR) {}
    bool ok = NRF_CCM->EVENTS_ENDCRYPT && !NRF_CCM->EVENTS_ERROR;
    if (!encrypt) ok = ok && NRF_CCM->MICSTATUS;
    NRF_CCM->ENABLE = CCM_ENABLE_ENABLE_Disabled;
    uint8_t n = encrypt ? (uint8_t)(len + PULSAR_MIC_LEN) : (uint8_t)(len - PULSAR_MIC_LEN);
    if (ok) memcpy(out, ccm_out + 3, n);
    else if (!encrypt) memset(out, 0, n);
    memset(&cnf, 0, sizeof cnf);
    return ok;
}

void hal_random(uint8_t* out, size_t n) {
    NRF_RNG->CONFIG = RNG_CONFIG_DERCEN_Enabled;  // bias correction
    NRF_RNG->EVENTS_VALRDY = 0;
    NRF_RNG->TASKS_START = 1;
    for (size_t i = 0; i < n; i++) {
        while (!NRF_RNG->EVENTS_VALRDY) {}
        NRF_RNG->EVENTS_VALRDY = 0;
        out[i] = (uint8_t)NRF_RNG->VALUE;
    }
    NRF_RNG->TASKS_STOP = 1;
}

uint64_t hal_device_id(void) { return (uint64_t)NRF_FICR->DEVICEID[1] << 32 | NRF_FICR->DEVICEID[0]; }

// Composite: CDC-ACM (interfaces 0-1) + vendor HID (interface 2), the same link stream on both
// (link.h "Framing"). VID/PID 1209:0001 is the pid.codes test ID (private use only).
#include <string.h>

#include "nrf.h"
#include "tusb.h"

#define USB_VID 0x1209
#define USB_PID 0x0001

static const tusb_desc_device_t desc_device = {
    .bLength = sizeof(tusb_desc_device_t),
    .bDescriptorType = TUSB_DESC_DEVICE,
    .bcdUSB = 0x0200,
    .bDeviceClass = TUSB_CLASS_MISC,
    .bDeviceSubClass = MISC_SUBCLASS_COMMON,
    .bDeviceProtocol = MISC_PROTOCOL_IAD,
    .bMaxPacketSize0 = CFG_TUD_ENDPOINT0_SIZE,
    .idVendor = USB_VID,
    .idProduct = USB_PID,
    .bcdDevice = 0x0100,
    .iManufacturer = 1,
    .iProduct = 2,
    .iSerialNumber = 3,
    .bNumConfigurations = 1,
};

const uint8_t* tud_descriptor_device_cb(void) { return (const uint8_t*)&desc_device; }

enum { ITF_NUM_CDC = 0, ITF_NUM_CDC_DATA, ITF_NUM_HID, ITF_NUM_TOTAL };

#define CONFIG_TOTAL_LEN (TUD_CONFIG_DESC_LEN + TUD_CDC_DESC_LEN + TUD_HID_INOUT_DESC_LEN)
// vendor page 0xFF00, 64-byte IN and OUT reports, no report IDs
static const uint8_t hid_report_desc[] = {TUD_HID_REPORT_DESC_GENERIC_INOUT(64)};

const uint8_t* tud_hid_descriptor_report_cb(uint8_t instance) {
    (void)instance;
    return hid_report_desc;
}

static const uint8_t desc_configuration[] = {
    TUD_CONFIG_DESCRIPTOR(1, ITF_NUM_TOTAL, 0, CONFIG_TOTAL_LEN, 0x00, 100),
    TUD_CDC_DESCRIPTOR(ITF_NUM_CDC, 4, 0x81, 16, 0x02, 0x82, 64),
    TUD_HID_INOUT_DESCRIPTOR(ITF_NUM_HID, 5, HID_ITF_PROTOCOL_NONE, sizeof hid_report_desc, 0x03, 0x83, 64, 1),
};

const uint8_t* tud_descriptor_configuration_cb(uint8_t index) {
    (void)index;
    return desc_configuration;
}

static const char* const strings[] = {
    NULL,                // 0: language (handled below)
    "TouchFrame",        // 1: manufacturer
    "TouchFrame radio",  // 2: product
    NULL,                // 3: serial from FICR.DEVICEID
    "TouchFrame radio",  // 4: CDC interface
    "TouchFrame radio HID",  // 5: HID interface
};

static uint16_t desc_str[33];

const uint16_t* tud_descriptor_string_cb(uint8_t index, uint16_t langid) {
    (void)langid;
    size_t n;
    if (index == 0) {
        desc_str[1] = 0x0409;
        n = 1;
    } else if (index == 3) {
        static const char hex[] = "0123456789ABCDEF";
        uint32_t id[2] = {NRF_FICR->DEVICEID[1], NRF_FICR->DEVICEID[0]};
        n = 16;
        for (size_t i = 0; i < n; i++) desc_str[1 + i] = hex[(id[i / 8] >> (28 - 4 * (i % 8))) & 0xF];
    } else if (index < sizeof(strings) / sizeof(strings[0])) {
        const char* s = strings[index];
        n = strlen(s);
        if (n > 32) n = 32;
        for (size_t i = 0; i < n; i++) desc_str[1 + i] = (uint8_t)s[i];
    } else {
        return NULL;
    }
    desc_str[0] = (uint16_t)((TUSB_DESC_STRING << 8) | (2 * n + 2));
    return desc_str;
}

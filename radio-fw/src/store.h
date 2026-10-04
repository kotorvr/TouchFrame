// Flash store for the host identity and pairings (LINK_HOST_STORED). Portable: flash goes through
// store_flash_t, so the same code runs on the dongle (NVMC, main.c) and on a RAM image in the tests.
//
// Layout: two pages used in turn. Each is a log of 32-byte records; slot 0 is the page header
// {generation}, written LAST when a page is (re)built, so a page only counts once it is complete.
// Records are replayed in order: IDENT {netaddr, key} (netaddr 0 = cleared) resets the pairings,
// PAIR {id, slot, hand} adds or updates one, FORGET {id} / FORGET_ALL remove. Each record ends with
// a checksum written last, so a write cut by power loss is ignored. When the page is full the live
// state is copied to the other (already erased) page and the old one is erased in the background.
//
// Timing on the nRF52840 (the reason for the shape): a word write stalls the CPU ~41 us, a full
// page erase ~85 ms, which would cost every connected controller ~42 beacons. So records are
// written a word at a time (interrupts run in between) and erases are done as partial-erase slices
// (store_step, one slice per call, paced by the caller). The only synchronous erase is at boot
// (store_init) and when a page fills while the spare is still being erased, which needs > 100 writes
// in a few seconds.
#pragma once
#include <stdbool.h>
#include <stdint.h>

#define STORE_PAGE_BYTES 4096
#define STORE_REC_WORDS 8
#define STORE_RECS (STORE_PAGE_BYTES / 4 / STORE_REC_WORDS)  // per page, including the header
#define STORE_MAX_PAIRS 8

typedef struct {
    uint32_t* page[2];  // memory-mapped, STORE_PAGE_BYTES each, erased = all 0xFF
    void* user;
    void (*write_word)(void* user, uint32_t* addr, uint32_t value);  // only clears bits
    void (*erase_slice)(void* user, uint32_t* page);                 // one partial-erase slice
    uint16_t erase_slices;  // slices that add up to a full erase
} store_flash_t;

typedef struct {
    uint64_t device_id;
    uint8_t slot, hand;
} store_pair_t;

typedef struct {
    store_flash_t f;
    bool ok;               // a valid page is in use
    uint8_t active;        // page index
    uint32_t gen;
    uint16_t used;         // records used in the active page, header included
    uint16_t erase_left[2];// slices still needed to erase each page (0 = erased or in use)
    // the replayed state
    uint32_t netaddr;      // 0 = no identity yet
    uint8_t key[16];
    uint8_t npairs;
    store_pair_t pair[STORE_MAX_PAIRS];  // oldest first
} store_t;

void store_init(store_t* s, const store_flash_t* f);
bool store_set_identity(store_t* s, uint32_t netaddr, const uint8_t key[16]);  // also clears pairings
bool store_add_pair(store_t* s, uint64_t device_id, uint8_t slot, uint8_t hand);  // evicts the oldest if full
int store_forget(store_t* s, uint64_t device_id);  // pairings removed (0 or 1); -1 on a flash error
int store_forget_all(store_t* s);
const store_pair_t* store_find(const store_t* s, uint64_t device_id);
bool store_step(store_t* s);  // one background erase slice if one is pending; true if it did one
bool store_busy(const store_t* s);  // a background erase is pending
uint16_t store_writes_left(const store_t* s);

#include "store.h"

#include <string.h>

#define MAGIC 0x54460000u  // "TF" in the top half of word 0, the record type in the bottom
#define ERASED 0xFFFFFFFFu
#define STORE_EARLY_COMPACT 4  // compact this many records before the page is full, if the spare is ready

enum { REC_HEADER = 1, REC_IDENT = 2, REC_PAIR = 3, REC_FORGET = 4, REC_FORGET_ALL = 5 };

static uint32_t checksum(const uint32_t* w) {
    uint32_t h = 2166136261u;  // FNV-1a over words 0..6
    for (int i = 0; i < STORE_REC_WORDS - 1; i++) {
        h ^= w[i];
        h *= 16777619u;
    }
    return h == ERASED ? 0 : h;
}

static uint32_t* rec_at(const store_t* s, uint8_t page, uint16_t i) { return s->f.page[page] + i * STORE_REC_WORDS; }

static bool rec_blank(const uint32_t* w) {
    for (int i = 0; i < STORE_REC_WORDS; i++)
        if (w[i] != ERASED) return false;
    return true;
}

static bool rec_valid(const uint32_t* w) {
    return (w[0] & 0xFFFF0000u) == MAGIC && w[STORE_REC_WORDS - 1] == checksum(w);
}

static bool page_blank(const store_t* s, uint8_t page) {
    for (uint16_t i = 0; i < STORE_RECS; i++)
        if (!rec_blank(rec_at(s, page, i))) return false;
    return true;
}

static void erase_now(store_t* s, uint8_t page) {
    uint16_t n = s->erase_left[page] ? s->erase_left[page] : s->f.erase_slices;
    for (uint16_t i = 0; i < n; i++) s->f.erase_slice(s->f.user, s->f.page[page]);
    s->erase_left[page] = 0;
}

// Word by word, checksum last; then read back.
static bool rec_write(store_t* s, uint8_t page, uint16_t i, uint32_t type, const uint32_t data[6]) {
    uint32_t w[STORE_REC_WORDS];
    w[0] = MAGIC | type;
    memcpy(w + 1, data, 6 * sizeof(uint32_t));
    w[STORE_REC_WORDS - 1] = checksum(w);
    uint32_t* dst = rec_at(s, page, i);
    for (int k = 0; k < STORE_REC_WORDS; k++)
        if (w[k] != ERASED) s->f.write_word(s->f.user, dst + k, w[k]);
    return memcmp(dst, w, sizeof w) == 0;
}

//------------------------------------------------------------------ the replayed state

static void apply_forget(store_t* s, uint64_t id) {
    for (uint8_t i = 0; i < s->npairs; i++) {
        if (s->pair[i].device_id != id) continue;
        memmove(&s->pair[i], &s->pair[i + 1], (size_t)(s->npairs - i - 1) * sizeof s->pair[0]);
        s->npairs--;
        return;
    }
}

static void apply_pair(store_t* s, uint64_t id, uint8_t slot, uint8_t hand) {
    apply_forget(s, id);  // re-pairing makes it the newest
    if (s->npairs == STORE_MAX_PAIRS) apply_forget(s, s->pair[0].device_id);
    s->pair[s->npairs++] = (store_pair_t){id, slot, hand};
}

static void apply(store_t* s, const uint32_t* w) {
    uint64_t id = (uint64_t)w[1] | (uint64_t)w[2] << 32;
    switch (w[0] & 0xFF) {
    case REC_IDENT:
        s->netaddr = w[1];
        memcpy(s->key, w + 2, 16);
        s->npairs = 0;
        break;
    case REC_PAIR:
        apply_pair(s, id, (uint8_t)w[3], (uint8_t)(w[3] >> 8));
        break;
    case REC_FORGET:
        apply_forget(s, id);
        break;
    case REC_FORGET_ALL:
        s->npairs = 0;
        break;
    default:
        break;
    }
}

//------------------------------------------------------------------ page management

static bool header(const store_t* s, uint8_t page, uint32_t* gen) {
    const uint32_t* w = rec_at(s, page, 0);
    if (!rec_valid(w) || (w[0] & 0xFF) != REC_HEADER) return false;
    *gen = w[1];
    return true;
}

static void replay(store_t* s) {
    s->netaddr = 0;
    memset(s->key, 0, sizeof s->key);
    s->npairs = 0;
    s->used = 1;
    for (uint16_t i = 1; i < STORE_RECS; i++) {
        const uint32_t* w = rec_at(s, s->active, i);
        if (rec_blank(w)) continue;
        s->used = (uint16_t)(i + 1);  // a torn record still takes its place
        if (rec_valid(w)) apply(s, w);
    }
}

static void put_id(uint32_t d[6], uint64_t id) {
    d[0] = (uint32_t)id;
    d[1] = (uint32_t)(id >> 32);
}

// Rebuild the live state on the other page, header last, then retire this one.
static bool spare_ready(const store_t* s) {
    uint8_t to = (uint8_t)(1 - s->active);
    return !s->erase_left[to] && page_blank(s, to);
}

static bool compact(store_t* s) {
    uint8_t to = (uint8_t)(1 - s->active);
    if (!spare_ready(s)) {
        if (s->no_sync_erase) return false;  // R9: never stall a connected link; retried later
        if (s->erase_left[to]) erase_now(s, to);  // still being erased in the background: finish now
        if (!page_blank(s, to)) erase_now(s, to);
    }
    uint16_t i = 1;
    uint32_t d[6];
    if (s->netaddr) {
        memset(d, 0xFF, sizeof d);
        d[0] = s->netaddr;
        memcpy(d + 1, s->key, 16);
        if (!rec_write(s, to, i++, REC_IDENT, d)) return false;
    }
    for (uint8_t k = 0; k < s->npairs; k++) {
        memset(d, 0xFF, sizeof d);
        put_id(d, s->pair[k].device_id);
        d[2] = 0xFFFF0000u | (uint32_t)s->pair[k].hand << 8 | s->pair[k].slot;
        if (!rec_write(s, to, i++, REC_PAIR, d)) return false;
    }
    memset(d, 0xFF, sizeof d);
    d[0] = s->gen + 1;
    if (!rec_write(s, to, 0, REC_HEADER, d)) return false;
    s->erase_left[s->active] = s->f.erase_slices;
    s->active = to;
    s->gen++;
    s->used = i;
    return true;
}

static bool append(store_t* s, uint32_t type, const uint32_t d[6]) {
    if (!s->ok) return false;
    // compact early while the spare is ready, so a full page rarely meets a spare still being erased
    if (s->used >= STORE_RECS - STORE_EARLY_COMPACT && s->used < STORE_RECS && spare_ready(s)) compact(s);
    if (s->used >= STORE_RECS && !compact(s)) return false;
    uint16_t i = s->used++;
    if (!rec_write(s, s->active, i, type, d)) return false;
    apply(s, rec_at(s, s->active, i));
    return true;
}

void store_init(store_t* s, const store_flash_t* f) {
    memset(s, 0, sizeof(*s));
    s->f = *f;
    uint32_t g[2];
    bool v0 = header(s, 0, &g[0]), v1 = header(s, 1, &g[1]);
    if (!v0 && !v1) {
        s->active = 0;
        s->gen = 1;
        if (!page_blank(s, 0)) erase_now(s, 0);
        uint32_t d[6];
        memset(d, 0xFF, sizeof d);
        d[0] = s->gen;
        if (!rec_write(s, 0, 0, REC_HEADER, d)) return;
    } else {
        s->active = (uint8_t)(v1 && (!v0 || g[1] > g[0]));
        s->gen = g[s->active];
    }
    uint8_t other = (uint8_t)(1 - s->active);
    if (!page_blank(s, other)) erase_now(s, other);  // boot: the radio is idle, a full erase is fine
    replay(s);
    s->ok = true;
}

bool store_set_identity(store_t* s, uint32_t netaddr, const uint8_t key[16]) {
    uint32_t d[6];
    memset(d, 0xFF, sizeof d);
    d[0] = netaddr;
    if (key) memcpy(d + 1, key, 16);
    else memset(d + 1, 0, 16);
    return append(s, REC_IDENT, d);
}

bool store_add_pair(store_t* s, uint64_t device_id, uint8_t slot, uint8_t hand) {
    const store_pair_t* p = store_find(s, device_id);
    if (p && p->slot == slot && p->hand == hand && p == &s->pair[s->npairs - 1]) return true;  // unchanged
    uint32_t d[6];
    memset(d, 0xFF, sizeof d);
    put_id(d, device_id);
    d[2] = 0xFFFF0000u | (uint32_t)hand << 8 | slot;
    return append(s, REC_PAIR, d);
}

int store_forget(store_t* s, uint64_t device_id) {
    if (!store_find(s, device_id)) return 0;
    uint32_t d[6];
    memset(d, 0xFF, sizeof d);
    put_id(d, device_id);
    return append(s, REC_FORGET, d) ? 1 : -1;
}

int store_forget_all(store_t* s) {
    int n = s->npairs;
    if (!n) return 0;
    uint32_t d[6];
    memset(d, 0xFF, sizeof d);
    return append(s, REC_FORGET_ALL, d) ? n : -1;
}

const store_pair_t* store_find(const store_t* s, uint64_t device_id) {
    for (uint8_t i = 0; i < s->npairs; i++)
        if (s->pair[i].device_id == device_id) return &s->pair[i];
    return NULL;
}

bool store_step(store_t* s) {
    for (uint8_t p = 0; p < 2; p++) {
        if (!s->erase_left[p]) continue;
        s->f.erase_slice(s->f.user, s->f.page[p]);
        s->erase_left[p]--;
        return true;
    }
    return false;
}

bool store_busy(const store_t* s) { return s->erase_left[0] || s->erase_left[1]; }

uint16_t store_writes_left(const store_t* s) { return s->ok ? (uint16_t)(STORE_RECS - s->used) : 0; }

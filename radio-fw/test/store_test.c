// Flash store against an independent model, on a RAM flash that behaves like NOR (writes only clear
// bits, a partly erased page reads as garbage) and that can lose power after any word.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/store.h"

#define SLICES 85

static uint32_t flash[2][STORE_PAGE_BYTES / 4];
static int slices_done[2];
static long budget = -1;  // word writes left before "power loss"; -1 = unlimited
static long writes, erases;

static int page_of(uint32_t* p) { return p >= flash[1]; }

static void w_word(void* u, uint32_t* a, uint32_t v) {
    (void)u;
    if (budget == 0) return;
    if (budget > 0) budget--;
    *a &= v;
    slices_done[page_of(a)] = 0;  // a later erase needs the full time again
    writes++;
}

static void w_erase(void* u, uint32_t* page) {
    (void)u;
    if (budget == 0) return;
    int p = page_of(page);
    if (++slices_done[p] >= SLICES) {  // erased; more slices keep it erased
        memset(flash[p], 0xFF, sizeof flash[p]);
        erases += slices_done[p] == SLICES;
    } else {
        memset(flash[p], 0xA5, sizeof flash[p]);  // half erased: neither old data nor blank
    }
}

static const store_flash_t F = {{flash[0], flash[1]}, NULL, w_word, w_erase, SLICES};

// independent model
typedef struct {
    uint32_t netaddr;
    uint8_t key[16];
    int n;
    store_pair_t p[STORE_MAX_PAIRS];
} model_t;

static void m_forget(model_t* m, uint64_t id) {
    for (int i = 0; i < m->n; i++)
        if (m->p[i].device_id == id) {
            for (int j = i; j < m->n - 1; j++) m->p[j] = m->p[j + 1];
            m->n--;
            return;
        }
}

static int same(const store_t* s, const model_t* m) {
    if (s->netaddr != m->netaddr || s->npairs != m->n) return 0;
    if (m->netaddr && memcmp(s->key, m->key, 16)) return 0;
    for (int i = 0; i < m->n; i++)
        if (memcmp(&s->pair[i], &m->p[i], sizeof m->p[i])) return 0;
    return 1;
}

static uint64_t ids[12];

// One random operation on both; returns 0 if the store reported a failure.
static int op(store_t* s, model_t* m, int r) {
    int k = r % 10;
    uint64_t id = ids[(r / 10) % 12];
    if (k < 5) {
        uint8_t slot = (uint8_t)(r % 5), hand = (uint8_t)(r % 3);
        if (!store_add_pair(s, id, slot, hand)) return 0;
        m_forget(m, id);
        if (m->n == STORE_MAX_PAIRS) m_forget(m, m->p[0].device_id);
        m->p[m->n++] = (store_pair_t){id, slot, hand};
    } else if (k < 8) {
        if (store_forget(s, id) < 0) return 0;
        m_forget(m, id);
    } else if (k == 8) {
        if (store_forget_all(s) < 0) return 0;
        m->n = 0;
    } else {
        uint8_t key[16];
        uint32_t x = (uint32_t)r * 2654435761u;  // from r only: the power-cut test replays ops
        for (int i = 0; i < 16; i++) key[i] = (uint8_t)((x = x * 1664525u + 1013904223u) >> 24);
        uint32_t na = (r & 0x100) ? 0 : x | 1;
        if (!store_set_identity(s, na, key)) return 0;
        m->netaddr = na;
        memcpy(m->key, key, 16);
        if (!na) memset(m->key, 0, 16);
        m->n = 0;
    }
    return 1;
}

int main(void) {
    srand(7);
    for (int i = 0; i < 12; i++) ids[i] = ((uint64_t)rand() << 40) ^ ((uint64_t)rand() << 16) ^ (uint64_t)rand();
    store_t s;
    model_t m;
    memset(&m, 0, sizeof m);

    // boot on garbage: formats
    for (size_t i = 0; i < sizeof flash / 4; i++) ((uint32_t*)flash)[i] = (uint32_t)rand() * 2654435761u;
    store_init(&s, &F);
    if (!s.ok || !same(&s, &m)) { printf("FAIL: init on garbage\n"); return 1; }

    // random operations, background erase steps, reboots
    long compactions = 0;
    for (int i = 0; i < 20000; i++) {
        uint32_t gen = s.gen;
        if (!op(&s, &m, rand())) { printf("FAIL: op %d reported failure\n", i); return 1; }
        compactions += s.gen != gen;
        if (!same(&s, &m)) { printf("FAIL: op %d: state differs from the model\n", i); return 1; }
        for (int k = rand() % 4; k > 0; k--) store_step(&s);
        if (rand() % 50 == 0) {
            store_init(&s, &F);
            if (!s.ok || !same(&s, &m)) { printf("FAIL: reboot after op %d\n", i); return 1; }
        }
    }
    printf("store: 20000 random ops match the model; %ld compactions, %ld page erases, reboots keep state\n",
           compactions, erases);

    // power loss after every possible word of an operation: the state after reboot is the one before
    // or the one after, never anything else
    int cases = 0;
    for (int i = 0; i < 3000; i++) {
        int r = rand();
        static uint32_t saved[2][STORE_PAGE_BYTES / 4];
        memcpy(saved, flash, sizeof flash);
        int saved_slices[2] = {slices_done[0], slices_done[1]};
        store_t s0 = s;
        model_t before = m, after = m;
        store_t probe = s;
        long w0 = writes;
        op(&probe, &after, r);
        long words = writes - w0;
        memcpy(flash, saved, sizeof flash);
        slices_done[0] = saved_slices[0], slices_done[1] = saved_slices[1];
        long cut = words ? rand() % (words + 1) : 0;
        s = s0;
        model_t dummy = before;
        budget = cut;
        op(&s, &dummy, r);
        budget = -1;
        store_init(&s, &F);
        if (!s.ok || (!same(&s, &before) && !same(&s, &after))) {
            printf("FAIL: power cut after %ld of %ld words (case %d)\n", cut, words, i);
            return 1;
        }
        m = same(&s, &after) ? after : before;
        cases++;
    }
    printf("store: %d power cuts mid-write: always the old or the new state\n", cases);
    return 0;
}

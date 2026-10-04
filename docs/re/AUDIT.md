# AUDIT-1: adversarial re-check of PROTOCOL.md (and FRAME-TRACKER §8)

Written 2026-10-04 by AUDIT-1 against the committed baseline `3f813df`. Every claim below was
re-derived from the binaries in `artifacts/work/` (`syncboss.bin`, `elk-app-ruby_prq.bin`,
`elk-spl-ruby_prq.bin`), with `tools/ghidra/{disasm,getfn,xref,scan}.py`, the `*.decomp.c` dumps,
and small capstone and Python scans. Nothing here copies Meta bytes. It gives addresses,
instructions and our own descriptions only. Static only, no device access.

Severity scale (as the planner asked):
- **BLOCKS** host mode: a dongle host built on the current text would fail.
- **HARMLESS**: wrong, but host mode still works. Where it breaks something else (sniff and
  decode, an offline tool), that is said in the entry.
- **WORDING**: a misleading label, a wrong citation, or a tag that should be upgraded or downgraded.

Address conventions follow PROTOCOL.md: syncboss base 0, elk-app base 0x14000, elk-spl base 0x2000.
"LL" below means the host Pulsar LL state struct at RAM `0x200156d0` (syncboss `DAT_0001e5a4`).

---

## Summary

| # | Finding | Severity |
|---|---|---|
| A1 | §3.1.4 settled: `FUN_00047604` is **only** the pairing wrap (`ecdh_pairing.c`). It is not connected-link negotiation. | BLOCKS (the Q3 nonce story rests on it) |
| A2 | The "legacy" negotiation nonce is **IV = session_nonce<<48 \| beacon_ts48, counter 0**. It is not a random IV sent in the clear. | **BLOCKS** |
| A3 | The steady-state IV is 8 bytes the **controller** sends in its connection request (CL bytes 0x0f..0x16). The counter is per slot and starts at 0. | **BLOCKS** |
| A4 | Connected-link CCM is **uplink only**. The host never encrypts and the controller never decrypts: beacons and downlink CL are plaintext. | **BLOCKS** |
| A5 | SPL command byte = `(number<<1) \| read`. `pulsar_host.py` puts 0x12/0x11 on air as raw bytes. | **BLOCKS** |
| A6 | `pulsar_input.decode_hreg(0x17)` reads analogs C and D from the wrong bits (they sit at bits 28 and 40). | **BLOCKS** (2 of 4 analogs wrong) |
| A7 | The real host pairs with **0x1d (per-device key = ECDH secret)** first and uses 0x11 only as a fallback. | HARMLESS for host mode; **breaks HARDWARE-DAY §5 decode** |
| A8 | `pulsar_crypto.py` nonce model, `scan` header strip and counter range are all wrong. | HARMLESS for host TX; **breaks §5 decode** |
| A9 | CRC-24 values are right, but the tool's address handling is wrong (bit-reversed base LSByte-first, then prefix). | HARMLESS for TX; breaks offline netaddr check |
| A10 | "No other software crypt call" is false: `FUN_0001b29c` / `FUN_0001b3cc` are the per-packet RX decrypts. | WORDING (it hid A2/A3) |
| A11 | CRC "literal" citations point at CRC lookup-table entries, not register writes. | WORDING |
| A12 | The flag remap isn't contested: reg 4 = `out2=in.3, out3=in.0`. The prose has it backwards; the tool is right. | WORDING |
| A13 | "Exactly four 12-bit analogs" is too strong: regs 3 and 0x17 pack **six** 12-bit fields. | WORDING |
| A14 | Q6: `0x23bc4` builds the controller's connection **request** (uplink), not a "response". | WORDING |
| A15 | Q2: the "0/1 flag to `FUN_000093c0`" is a decompiler artifact. The 0x11/0x1d difference is `FUN_000038e8`'s 2nd argument. | WORDING |
| A16 | PairingData base address is a little-endian u32. Neither the doc nor the tool says so. | HARMLESS (specify it) |
| A17 | CCM direction: the doc describes the config-struct bit, not the nonce bit. No image ever writes it (it stays 0). | WORDING |
| A18 | Beacon byte 14 can be upgraded to CONFIRMED; the deerfly checksum can be upgraded to CONFIRMED CRC-32. | WORDING (upgrade) |
| A19 | Q4 reg 0x16 = "IMU" is not supported by `FUN_00014c38`. | WORDING |
| A20 | Open for RE-1: which key the host uses to decrypt a seeking controller's negotiation on slot 0. | open question |
| A21 | Smaller tool issues: `radio.py` presets, `--with-adverts`, `pulsar_analyze` default, stale comments, weak selftests. | HARMLESS / WORDING |
| F1–F4 | FRAME-TRACKER §8 spot-check: no wrong claims found. Two new risks (event-queue rate; re-connect with a known deviceId). | HARMLESS / risk |

Docs that repeat the wrong A2–A4/A7 narrative: PROTOCOL Q1 (beacon bytes 6..7), Q2 ("Host mirror"
parenthetical), Q3 (the whole "Connection-negotiation nonce" and "Steady-state link" paragraphs
and the open-contradiction box), open items 4 and 8, MASTER-PLAN §3.1.3–§3.1.4, HARDWARE-DAY §5,
`tools/pulsar_crypto.py` docstring and `candidate_nonces`, and `tools/pulsar_host.py` header.

---

## A1. `syncboss FUN_00047604` is the ECDH pairing wrap, nothing else (§3.1.4 settled)

**Claim (Q2/Q3):** this function is both the PairingData wrap and the connected-link "legacy nonce /
connection negotiation" crypt. It saves the random IV at `+0x99` "for the session".

**Evidence:**
- Literal pool `0x47764..0x47788`:
  - `__FILE__` = `"ecdh_pairing.c"` (0x5dda8);
  - log tag `"ECDH"`;
  - `"Calculated shared secret"`;
  - `"Secure pairing failed. Status %d"`;
  - the assert `"m_session.pairing_state == PAIRING_STATE_SENDING_KEY"`.
- The session struct is RAM `0x2001ad38` (`m_session`). It is referenced only from `0x47310..0x47984`,
  the `ecdh_pairing.c` state machine.
- `FUN_00025eb4(+0x01, +0x41, +0x61)` is X25519. The private key is at +0x01, the controller
  public key at +0x41 (copied in by `FUN_00047834` from the 0x12 reply, state 2→3), and the
  shared secret is written to +0x61.
- `FUN_0001b0a4(+0x61)` loads the first 16 bytes of the secret as the CCM key.
- RNG fills 8 bytes at +0x88. `FUN_0001b1a4` encrypts `[netaddr u32][16-byte key]` (20 B) to `+0xa1`.
- The `+0x88 → +0x99` copy is **packet assembly, not a saved session IV**. `+0x99..+0xa0` (IV)
  and `+0xa1..+0xb8` (ciphertext + MIC) make one contiguous 32-byte payload. `FUN_00047548` sends
  exactly `0x2001add1` (= `+0x99`), length `0x20`, through `FUN_0004531c`. Its log string is
  `"Sending encrypted pairing info"`.
- After the send, `FUN_00047310` / `FUN_0004739c` zero the whole struct (`memset(+0, 0, 0xc0)`).
  Nothing survives into the connected link.

**Severity: BLOCKS.** Hypothesis (a) in Q3 has no basis, and HARDWARE-DAY §5's advice ("take the IV
from the 0x11 payload") gives an IV that is never used on the connected link.

**Fix:** Q2: drop the "(this is the legacy nonce / connection negotiation crypt …)" parenthetical.
Q3: delete the "Connection-negotiation nonce (CONFIRMED, `FUN_00047604`)" paragraph, the
open-contradiction box and hypothesis (a). Replace them with A2/A3.

## A2. The negotiation ("legacy") nonce is derived from the beacon. There is no IV on air.

**Claim:** "negotiation nonce is an 8-byte random IV … with counter 0, sent in the clear" (Q3, open
item 4). Open item 4 also says the `session_nonce<<48|timestamp` lead "was wrong". Q1 beacon bytes
6..7 say the session nonce goes in "the top 16 bits of its 64-bit CCM **packet counter**".

**Evidence, host:**
- `FUN_0001aba8 @ 0x1aba8` is `cmp r1,#0x10000; add.w r1, r1, r2, lsl #16; bx lr`, with the
  assert string `"timestamp < (1ULL << LL_BITS_IN_BEACON_TIMESTAMP"` (`pulsar_ll_common.c`).
  It returns the 64-bit value `ts48 | session_nonce << 48`.
- Its two callers are the uplink-RX decrypt arms `FUN_0001da8c` case 1 (→ `FUN_0001b3cc`) and
  `FUN_0001e2dc` case 1 (→ `FUN_0001b29c`). Both take a branch "if the per-slot IV
  (`LL+0xf10+slot*8`) is 0". In that branch they pass `FUN_0001aba8(LL+0xf08, LL+0xf0c, LL+0x54)`
  as **param_5/6 = IV** and `0,0` as param_7/8 = packet counter.
- `LL+0xf08` is the current 48-bit beacon timestamp. `LL+0x54` is the 16-bit session nonce from
  `pulsar_host_init`.
- In `FUN_0001b29c` / `FUN_0001b3cc` / `FUN_0001b1a4`, param_5/6 are stored to config `+0x129/+0x12d`
  (IV) and param_7/8 to `+0x120/+0x124` (PKTCTR).

**Evidence, controller (elk-app):**
- `0x24092..0x240d6`: if the stored IV `LL+0x1e8` is 0, then `ts = LL+0x290 (beacon ts) +
  LL+0x280 * 2000`.
- `0x240cc add.w r3, r3, r4, lsl #16` with `r4 = ldrh [LL+0x298]` (the session nonce the beacon
  parser stores from payload bytes 6..7, `FUN_00024164`). `r2/r3` is the IV. The counter
  `[sp] = 0,0`.
- Then `bl 0x239fc`, whose body stores `r2,r3 → cfg+0x129/+0x12d` (IV) and the stack pair →
  `cfg+0x120` (PKTCTR). CCM `MODE = 0x01010000` = encrypt, 2 Mbit, extended length.
- The 0x2409c "beacon scheduler" objection in open item 4 was about a different function; the
  `<<48` packing is real.

**Result (CONFIRMED both sides):**
- legacy nonce = `PKTCTR = 0`, direction 0;
- `IV (u64, little-endian in the nonce) = session_nonce << 48 | beacon_timestamp48`, where the
  timestamp is that of the beacon starting the period in which the packet is sent;
- the 13-byte nonce = `00 00 00 00 00 ‖ ts[0..5] LE ‖ session_nonce LE`.

Everything comes from the beacon, so a sniffer with the key can decrypt negotiation uplinks
without seeing any IV.

**Severity: BLOCKS.** A host must use this to decrypt the controller's first uplink.

**Fix:** Q1 bytes 6..7: "…the device puts it in the top 16 bits of the 64-bit CCM **IV**". Q3:
replace the negotiation paragraph with the above. Open item 4: strike "The earlier
`session_nonce<<48|timestamp` lead was wrong".

## A3. The steady-state IV comes from the controller's connection request; the counter is per slot

**Evidence: the controller's connection request (uplink).** The CL payload is built at elk-app
`0x23bc4..0x23c22`, LENGTH `0x19` (25). The connection record is `0x20004ec0`.

| CL byte | content |
|---|---|
| 0 | 0 (the host's `FUN_0001d038` takes this path only when it is 0) |
| 1 | `0x11`. The host reads `[1] >> 3` (=2) as a format version; non-zero means bytes 0x0e..0x18 are present |
| 2..9 | 64-bit controller ID (record +0/+4) |
| 10..13 | record +8 word: the `0x1701` version (bytes 10..11 = `01 17`) + record +0xa/+0xb |
| 14 | record +0x71 (or 1 if record +0x70 == 0) |
| **15..22** | **8-byte IV, u64 LE from record +0x68** |
| 23 | RADIO `+0x50c` read + a global byte (UNKNOWN) |
| 24 | a global byte at `0x200000b0` (UNKNOWN) |

**Evidence: the host.**
- `FUN_0001d038` (`pulsar_cl_host.c`, `"Unable to allocate endpoint, ignoring request from
  %08lx%08lx"`) parses the request. It reads `iVar4 = *(u32*)(p+0xf)` and `iVar10 = *(u32*)(p+0x13)`
  (zeroed when `[1]>>3 == 1`).
- It gets the link key for that device from an upper-layer callback (`*(LL_CL+0xc)`) and calls
  `FUN_0001e90c(slot, {key16, iv64,…})`.
- `FUN_0001e90c` stores the per-slot **key** at `LL + 0xeb0 + slot*16` and the per-slot **IV** at
  `LL + 0xf10 + slot*8`.
- From then on, the RX arms use `IV = that per-slot IV` and `PKTCTR = (u32) LL[0x3c + slot*4], high
  byte 0`.
- The controller mirrors this. `FUN_00028ad0(slot, key*, iv_lo, iv_hi)` is called from
  `0x23c86` with `slot = record+0xc`, `key = record+0x58`, `IV = record+0x68`. It stores the IV at
  `LL+0x1e8` and **resets the TX counter `LL+0x1b8` to 0**.
- During seek (`0x23ae2`) it calls `FUN_00028ad0(0, 0x20004f08, 0, 0)`: slot 0 (TX prefix
  `0x01`), the stored key, IV 0. That is the legacy nonce of A2.

**Result:**
- steady-state nonce = `PKTCTR = per-slot u32 counter, starting at 0 after the accept` ‖ `IV =
  the 8 bytes the controller sent at CL bytes 15..22 of its connection request`.
- The request itself goes out under the A2 legacy nonce, so the IV is readable once the request is
  decrypted. It is not in the clear.
- Still UNKNOWN (RE-1): where the controller's record +0x68 IV comes from (RNG or stored), exactly
  when the counter increments (per TX attempt or per new packet; retransmits), and the request
  `[1]` low bits.

**Severity: BLOCKS.**

**Fix:** Q3 "Steady-state link": replace both hypotheses with this. Add the request layout to Q1/Q3
(or LINK.md). Move "steady-state packing" in open item 4 from "needs a live capture" to "pinned
statically; a live MIC check confirms it".

## A4. Connected-link CCM runs only on uplink. Host TX is plaintext.

**Claim:** "uplink and CL data are CCM-encrypted (Q3)". MASTER-PLAN §3.1.3: "A host must *produce*
valid MICs". BUILD-1's brief asks for "inline HW AES-CCM" on TX.

**Evidence:** a literal scan for CCM `MODE` values over all three images.
- **elk-app** has only `0x01010000` (MODE=Encryption) at `0x23a6c` (used by `0x239fc`, `str
  [CCM,#0x504]` at `0x23a54`) and `0x3013c`. There is **no** `0x01010001` (Decryption) literal.
  The other CCM-base uses are the init at `0x2546c` (CNFPTR), event clears at `0x24bd0..0x24c0a`,
  and disable at `0x25348`.
- **syncboss** has `0x01010001` (Decryption) in `FUN_0001b29c` (`0x1b37c`) and `FUN_0001b3cc`
  (`0x1b47c`), which are the uplink-RX arms. The only Encryption use is `0x1b28c` in
  `FUN_0001b1a4`, whose sole caller is `FUN_00047604` (pairing wrap).
- **elk-spl** has only Decryption (`0x9218`), for PairingData.
- Neither beacon path calls CCM: builder `FUN_0001dbf8` / CL `FUN_0001cf30` (host), parser
  `FUN_00024164` (controller). The parser takes CL data straight from `RX buffer + 0x11`.
- The controller TX path also has a **plaintext bypass**. At `0x24052`, `ldrb r0,[LL,#0x29c];
  cbz r0 → encrypt`, else it copies without CCM. What sets `LL+0x29c` is UNKNOWN (no direct store
  was found by a linear scan).

**Result:** beacons and downlink CL data travel **unencrypted and unauthenticated**. Only
controller→host packets carry CCM and a 4-byte MIC. A host needs HW-CCM **decrypt** on RX only. The
only host encrypt is the pairing wrap (software `FUN_0001b1a4` style).

**Severity: BLOCKS.** A host that CCM-encrypts its downlink sends ciphertext the controller parses
as plaintext, so every command is garbage. This also drops a large chunk of BUILD-1 work.

**Fix:** Q1 beacon note: "the beacon and all host→device CL data are plaintext (CONFIRMED: no
decrypt in elk-app). Uplink is CCM." MASTER-PLAN §3.1.3: "host must decrypt uplinks and produce
the pairing wrap. It does not encrypt on the connected link."

## A5. SPL command byte: tools send the command *number* as the raw byte

**Claim:** PROTOCOL Q2 gives command **numbers** under `switch((b & 0x7f) >> 1)`, correctly. But
`tools/pulsar_host.py:41-46` says "these are the confirmed on-wire byte values" and frames
`CMD_SETUP_X25519 = 0x12` and `CMD_PAIRING_DATA = 0x11` as the first payload byte.

**Evidence:**
- elk-spl `0x86a0..0x86d0`: on a DM-link RX the code tests `pkt[1] & 0x7e` (zero means an empty
  poll). It then calls the dispatcher as `FUN_0000822c(pkt+1, pkt[0])`, so `param_1[0]` is the
  first byte after LENGTH and `param_1[1]` is the seq.
- `FUN_0000822c`: `bit0 == 0` selects the write switch on `(b & 0x7f) >> 1` (0x11 → `FUN_00003abc`,
  0x1d → `FUN_00003ac6`). `bit0 == 1` selects the read switch (0x12 → `FUN_00003948`, reply length
  0x20).
- `FUN_00003948` copies **32 bytes from the request payload** (the host public key) into storage
  and returns the 32-byte controller public key. So the host pubkey rides in the 0x12 *read*
  request, which answers the helper's open question about where it travels.
- On air, the raw byte `0x12` is a write of command 9 (default case → no-op). The raw byte `0x11`
  is a read of command 8 (`FUN_000081a8`, a stub). Pairing as the tool frames it cannot work.

**Correct on-air bytes** (frame = `[LENGTH][cmd][seq][payload]`):

| command | byte |
|---|---|
| SetupX25519Keys read | **`0x25`** (payload = 32-byte host pubkey) |
| PairingData write | **`0x22`** |
| 0x1d write | **`0x3a`** |
| WriteAESKey | `0x28` |
| Reset | `0x2a` |

The format of the reply's command byte is UNKNOWN. `parse_setup_x25519_response` assumes `0x12`.
No SPL-level CRC appears in this dispatch path. The radio CRC-24 is the only check seen (INFERRED).

**Severity: BLOCKS** pairing.

**Fix:** PROTOCOL Q2: add a line "on-air byte = `(num << 1) | 1` for read, `num << 1` for write;
SetupX25519Keys = `0x25` carrying the host public key; PairingData = `0x22`". `pulsar_host.py`:
encode `(num<<1)|rw` in `frame_spl`, and make the selftest check the dispatcher decode
(`(b&0x7f)>>1`, `b&1`) rather than its own constant.

## A6. `pulsar_input.decode_hreg(0x17)`: wrong bit positions for analogs C and D

**Evidence:** elk-app `0x179fe..0x17a68` builds the 8-byte reg 0x17 on the stack at `sp+0x18`:
- `[0] = buf[0x2d]`, `[1] = buf[0x2e]`;
- `bfi …, s16@0x2f, #0, #12` fills bits 16..27;
- `C = u16@0x31` goes to `[3] hi-nibble` / `[4]`, i.e. bits 28..39;
- `D = u16@0x33` goes to `[5]` / `[6] lo-nibble`, i.e. bits 40..51;
- `bfi …, s16@0x35, #4, #12` fills bits 52..63.

As a little-endian u64:

| bits | field |
|---|---|
| 0..15 | `buf[0x2d..0x2e]` |
| 16..27 | `buf@0x2f & 0xfff` |
| **28..39** | **C** |
| **40..51** | **D** |
| 52..63 | `buf@0x35 & 0xfff` |

`pulsar_input.py:200-204` takes `word & 0xFFF` and `(word>>12) & 0xFFF` from the first 6 bytes, so
both analogs decode as garbage. Reg 3 is right: the same function packs `a | b<<12` into 3 bytes (decomp of
`FUN_000173bc`, the `FUN_0001f464(3, …)` call), matching `decode_hreg(3)`.

**Severity: BLOCKS** correct input for two of the four main analogs.

**Fix:** `decode_hreg(0x17)`: `v = int.from_bytes(raw[:8], 'little')`, `C = (v>>28)&0xfff`,
`D = (v>>40)&0xfff`, plus `aux0 = v&0xffff`, `aux1 = (v>>16)&0xfff`, `aux2 = (v>>52)&0xfff`. Add a
selftest built from a hand-packed vector that follows the instruction sequence above, not from
`pack_deerfly`.

## A7. Real host pairing: 0x1d (per-device key) first, 0x11 only as a fallback

**Claim:** Gate A and Q2 say "the 16-byte link AES key is host-chosen and sent encrypted". The Q2
host mirror says the host sends 0x11. "TouchFrame … can ignore `0x1d`."

**Evidence, syncboss `ecdh_pairing.c`:**
- `FUN_00047548` sets the command number `local_d = 0x1d`. It switches to `0x11` only
  `if (pairing_state == 5)`. `FUN_00047604` asserts state 4 (`PAIRING_STATE_SENDING_KEY`) before
  calling it, so the first send is **0x1d**.
- `FUN_00047834`, state 4, error reply: logs `"Bad response to ecdh_pairing_with_pdk request: %d;
  falling back to ecdh pairing without per…"`, moves to state 5 (assert
  `PAIRING_STATE_SENDING_KEY_NO_PDK`), and re-queues `FUN_00047548`, which now sends **0x11**.
- On success, `FUN_00047310` stores the device key via `FUN_00045c18(id_lo, key, id_hi)`. In
  state 4 the key = `m_session+0x61` (the **ECDH shared secret**). In state 5 the key =
  `FUN_000439bc()` (the global `pulsar_aes_key.bin`/default), logged as `"ECDH failed - falling
  back on global key"`.
- The controller side agrees: `FUN_000038e8(dec, shared)` (0x1d) stores
  `key = shared[:16]`; `FUN_000038e8(dec, 0)` (0x11) stores `dec+4`.
- The host LL keeps **per-slot keys** (`FUN_0001e8b0` / `FUN_0001e90c`, `LL+0xeb0+slot*16`).

**Result:**
- A Quest pairing a current controller ends with **link key = first 16 bytes of the X25519 secret,
  unique per pairing**. That key is never on disk as `pulsar_aes_key.bin` and can't be derived by a
  sniffer.
- For **our host** nothing breaks: both 0x11 and 0x1d are accepted. 0x1d is arguably better (no
  key to choose, and it matches Meta's normal path).
- HARDWARE-DAY §5's plan to decrypt a sniffed Quest session with `pulsar_aes_key.bin` only works if
  that controller was paired by the fallback.

**Severity: HARMLESS for host mode. Breaks HARDWARE-DAY §5 / HW-1 decode.**

**Fix:**
- Gate A / Q2: describe both modes, and say Meta's default is 0x1d (PDK).
- HARDWARE-DAY §5: the key is per device (find where libsyncboss persists `FUN_00045c18` keys, or
  pair the controller to *our* host and use our own key).
- MASTER-PLAN §3.1.10 (default key) loses most of its value.

## A8. `tools/pulsar_crypto.py` models the wrong nonce and strips the wrong header

Mostly confirms the tools helper's report, re-checked here:
- The docstring and `candidate_nonces` lead with the "random session IV" (A1). The right model is
  A2 (counter 0, IV from the beacon) for negotiation and A3 for steady state.
- The fallback `iv=sess<<48|ts LE` is the **correct** A2 layout. But it is fed `r["t_us"]` (the
  dongle capture time), not the beacon's 48-bit timestamp from payload bytes 8..13, and session
  defaults to 0.
- The `ctr=sess<<48|ts` candidate is masked to 39 bits in `nonce_from_fields`, so the session is
  silently dropped.
- `do_scan`: `payload = data[1:]` strips only one byte. With `radio.py sniff --connected` (s0len=1)
  `data` is `[S0][LEN][payload]`, so LENGTH stays inside the ciphertext and no MIC can verify.
  `--max-counter` defaults to 8.
- The AAD byte 0 is **correct**, but for a different reason than the docstring gives. nRF/BLE CCM
  uses `S0 & 0xE3` as AAD, and connected S0 = `0x04` masks to 0. The pairing wrap header byte is 0
  (`FUN_0001b1a4` writes `[0]=0, [1]=len, [2]=0`; elk-spl `FUN_00009198` likewise).
- The selftest's "keystream round-trip" ignores the MIC, and `nonce_from_fields` is not tested
  against anything independent. The helper verified the packing with a BLE Core-spec CCM sample
  from memory: direction = bit 39 is right.

**Severity: HARMLESS for host TX. Breaks §5 decode and would mislead a firmware RX port.**

**Fix:** rewrite the candidates as `legacy(session, beacon_ts)` and `steady(iv_from_request,
ctr)`. Parse S0 and LEN per capture mode. Pull the session nonce and timestamp from the preceding
beacon in the capture. Add a selftest that builds a packet with `cryptography`'s AESCCM under the
A2 nonce and checks that `scan` finds it.

## A9. CRC-24: values right, tool address handling wrong

**Re-verified (CONFIRMED):**
- Host PHY init `FUN_0001b61c` writes, at `0x1b74a` `mvn r0,#0xff000000` → `CRCINIT
  (+0x53c) = 0x00FFFFFF`; `0x1b752` `CRCCNF (+0x534) = 3` (LEN=3, SKIPADDR=0); `0x1b756`
  `CRCPOLY = 0x108421` (pool `0x1b958`). The controller does the same at `0x25694..0x256a4`.
- The controller's software re-check (elk-app `FUN_00024164`) uses `FUN_00022ab8`, an
  MSB-first table CRC-24, with its table at `0x316f8` = the MSB-first table for poly `0x108421`
  (all 256 entries checked). It also uses `FUN_00022780`, a bit-reverse through a nibble table at
  `0x31b1c`.
- Feed order: `bitrev(base & 0xff), bitrev(base>>8), bitrev(base>>16), bitrev(base>>24),
  bitrev(prefix)`, then S0 (if any), LENGTH and payload **unreversed**. The result is compared
  with `RXCRC`.
- `pulsar_host.crc24` matches the firmware on the S0/LENGTH/payload part (random vectors). The
  selftest's address input `0c b0 ce fa aa` (base LE + prefix, **not** bit-reversed) does **not**
  match the firmware. Bit-reversing each of those five bytes makes it match exactly.

**Severity: HARMLESS for TX** (the radio computes the CRC), but the PROTOCOL sniffer note
"any candidate address can be verified offline against a captured packet" can't be met with the
current code.

**Fix:** add `crc24_air(base, prefix, hdr, payload)` implementing the feed order above, plus a
selftest that reproduces the table-driven firmware algorithm. Note in Q1 that the on-air address
is LSbit-first, base LSByte first, prefix last (ENDIAN applies to S0/LEN/payload/CRC only). The
on-air CRC byte order (MSB first under ENDIAN=big) is INFERRED. The tool's `to_bytes(3,"little")`
trailer should be reconsidered against a capture.

## A10. "No other software crypt call" (Q3)

**False.** `pulsar_crypto.c` has four entry points:
- `FUN_0001b0a4` (init / KEY);
- `FUN_0001b1a4` (synchronous encrypt; pairing only);
- `FUN_0001b29c` (decrypt, start op 0/1/2, op 2 = armed for PPI from the radio; called by
  `FUN_0001e2dc`);
- `FUN_0001b3cc` (decrypt, KSGEN only, scratch = param_1; called by `FUN_0001da8c`).

The last two are where the per-packet nonce is set (A2/A3). **WORDING**, but it is the reason
the nonce looked unpinnable.

## A11. CRC "literal constants" citations point at lookup tables

PROTOCOL Q1 cites `syncboss 0x52034/0x520a8` and `elk-app 0x316fc/0x31770` as the poly/init
literals. Those addresses are entries **T[1] and T[30]** of the CRC-24 lookup tables at
`0x52030` / `0x316f8`. T[1] = poly, and T[30] happens to equal `0xFFFFFF`. The values are right.
The register writes are listed in A9. **WORDING.** Fix the citations.

## A12. Touch-flag remap is not contested

From the `FUN_000173bc` decomp, input `f = buf[0x04]`:
- `FUN_0001f748(v, 10)` low nibble = `f.1, f.2, f.0, f.3` (out0..3);
- `FUN_0001f464(4, …)` = `f.1, f.2, f.3, f.0`;
- reg 0x2b = `(f<<27)>>31` = `f.4`.

So reg 4 is `out2=in.3, out3=in.0`, and the other ordering belongs to the edge write. PROTOCOL Q4
has the attribution backwards ("the latter ordering may actually be the parallel 10-bit edge
write"). `pulsar_input.remap_flags_reg4` is **correct**, and its docstring is right about the
doc.

**WORDING.** Mark the reg-4 remap CONFIRMED; `touch_flags_edge10` can stay as an aside.

## A13. Analog fields: more than four 12-bit fields

Regs 3 and 0x17 together pack **six** 12-bit-masked fields, from `buf 0x23, 0x25, 0x2f, 0x31, 0x33,
0x35` (A6), plus 16 bits at `0x2d`. "Exactly the {trigger, grip, stickX, stickY} set" is
therefore an inference, not something the packing proves. Axis identity remains RE-2's deerfly job.

Hreg byte sources are reordered, and the table's ranges are loose:
- reg 8 (10 B) = `buf[7..10], [0xb..0xc], [5..6], [0xd..0xe]`;
- reg 0x21 (12 B) = `u16@0xf, u16@0x13, u16@0x11, u16@0x15, u32@0x17`;
- reg 0x20 (6 B) = `buf[0x1b], [0x1d], [0x1c], [0x1e], u16@0x1f`.

**WORDING.** `pulsar_input`'s raw slices (`s[5:15]`, …) are byte *sources*, not hreg layouts. Say
so in the docstrings.

## A14. Q6: `0x23bc4` builds the connection request, not a response

The block at `0x23bc4` (inside the handler Ghidra labels `FUN_00023aa8`) builds the controller →
host request of A3. The host handler that parses it logs "ignoring request from". The `0x1701`
version lands at request bytes 10..11. The accept handler's checks listed in Q6 (`[0]==1`, ID
at `[3..10]`, endpoint `[2]&7`, slot `[11]`) are for the host's *response* (downlink, plaintext per
A4).

**WORDING.** Q6's "Echoed outward in the connection-response builder" should say "the connection
request".

## A15. Q2: 0x11 vs 0x1d difference

`FUN_000093c0` takes three parameters (secret out, priv, pub). The "flag 0/1" in the decomp of
`FUN_00003abc`/`FUN_00003ac6` is a phantom argument. The real difference is
`FUN_000038e8(decrypted, 0)` versus `FUN_000038e8(decrypted, shared_secret)`, which the Q2 text
also states. Open item 1's "loose end" about that flag can be closed. **WORDING.**

## A16. PairingData base address byte order

The host fills plaintext[0..3] with `local_30 = FUN_00045a6c()`, a u32 stored natively, i.e.
**little-endian**. The controller stores the 20 bytes verbatim (`FUN_000038e8`) and later loads
the word as BASE. `pulsar_host.build_pairing_payload` takes 4 raw bytes, and its selftest uses
`deadbeef`, which shows no order.

**HARMLESS today, a trap later.** Specify "base address = `struct.pack('<I', netaddr)`" in Q2 and
take an int in the tool.

## A17. CCM direction bit

The nRF config struct has DIRECTION at `cfg+0x128` (bit 0). The hardware maps it to **bit 7 of
nonce byte 4** (BLE packing). That is what `nonce_from_fields` does, and the helper confirmed it
against a BLE spec sample. A capstone scan finds **no store to `cfg+0x128`** in any of the three
images, so direction stays at its reset value (0) for every crypt, both ways and in pairing.

**WORDING.** Q3 should say "direction = nonce bit 39, always 0 in Pulsar (never written)".

## A18. Upgrades (claims that are better than their tags)

- **Beacon byte 14: CONFIRMED.** Host `FUN_0001cf30` writes CL byte 0 (= beacon payload byte 14)
  as `1 << slot` when `FUN_0001d738` finds a device with pending downlink, else 0. CL length ≤ 0x22
  (+2 header). The negotiation variant sets length `'$'` = 36 and copies a 26-byte response
  struct. The controller parser hands the CL layer `payload+14`, length `LEN-14` (`local_2c = p+0x11`).
- **Deerfly checksum = standard CRC-32 (zlib): CONFIRMED.** `FUN_00029f4c` is a nibble-table
  reflected CRC-32 (table at `0x32b68`: `0, 0x1db71064, …`), init `~0`, final `~`. It matches
  `zlib.crc32` on random data and is compared with the u32 LE at `buf+0x39`. The tool was right;
  the doc's "CRC/sum INFERRED" can go.
- **Advertising interval**: the SPL advert setup at `0x7f9e` loads `0x186a0` = 100 000 (µs,
  INFERRED unit) before starting the timer, so expect adverts about every 100 ms. New, INFERRED.

## A19. Reg 0x16 is not obviously IMU

`FUN_00014c38` writes **reg 0** (a byte from `FUN_0001cf70`) and **reg 0x16** = a u16 global
(`DAT_00014c60`). Neither is sensor data visibly. Reg 0xb (12 B from `FUN_00014c1c`'s arg) fits 6×i16
accel+gyro. **WORDING.** Tag reg 0x16 as UNKNOWN, not IMU (RE-2).

## A20. Open question for RE-1 (not a doc error)

A seeking controller transmits on slot 0 (prefix `0x01`) with its stored link key (`0x20004f08`)
and the A2 nonce (`0x23ae2`). The host's slot-0 key is set once from `pulsar_host_init`'s
**global** key (`FUN_0001d300 → FUN_0001e8b0(0, key, 0, 0)`). With 0x1d pairing the controller's
key is per device. How does the host decrypt that controller's request? Possibly it reloads the
slot-0 key per candidate in `FUN_0001e2dc` case 2, or the upper layer reprograms it. Settle this
before writing the dongle's RX path. With **our** host using 0x11 and one global key it doesn't
matter.

## A21. Smaller tool and doc issues (HARMLESS / WORDING)

These come from the tools helper; I spot-checked the first two.
- `radio.py:59` "pairing" preset keeps base `0xFACEB00C`. The PROTOCOL recipe is base =
  `DEVICEID[0]` (advert bytes 5..8 LE; confirmed: SPL `FUN_000080c8` puts the ID at advert
  `[5..12]` and the same words at DM state `+0x28`).
- `radio.py sniff --connected --with-adverts` enables AP0 under the global `s0len=1`. Adverts and
  the DM beacon have no S0 (and are on 2402), so they are misparsed.
- `pulsar_analyze.py` defaults to `--hdr 1` (no S0), which is wrong for connected captures.
- Stale comments: `sniffer.h:164` says "hop = (base0 & 0xFF)" but the code (correctly) uses BASE1;
  `pulsar_hop.c:3` mentions only 2426 as skipped.
- `pulsar_input.py` docstrings still say deerfly is absent from the dumps.
- Weak selftests: `pulsar_input` checks 4 of 12 button bits individually, and its pack/parse share
  offsets (self-consistent only). `pulsar_crypto`'s round-trip ignores the MIC. The genuinely
  independent ones are RFC 7748 (X25519), RFC 3610 #1 (CCM M=8), and the radio-fw C-vs-Python
  hop/beacon models, which are independent code built from the same doc text.
- Selftests run by the helper: `pulsar_host`, `pulsar_crypto` and `pulsar_input` selftests PASS;
  radio-fw `test/test.py` with a scratch clang build PASS ("hop: 303 cases", "beacon parse: 200
  round-trips + 3 rejects"). `link.h` ↔ `radio.py` struct sizes (81/104/9) and IDs agree.

---

## Re-verified as correct (with evidence)

**Images:**
- elk-app base 0x14000 and git `edbf4671d29b`, elk-spl base 0x2000, syncboss base 0 (`images.json`).
- deerfly-app.bin: `dAeH`, header length 0x2e, kind `0x01020304`, SP `0x20007a60`, reset `0x10919`
  at file +0x100, 69 216 bytes. This confirms the MASTER-PLAN §3.1.7 correction.

**PHY / radio config (Q1 table):**
- host `0x1b6e0..0x1b756`: MODE=1, MODECNF0=1, SHORTS=0x113;
- PCNF0 = `8 | s0<<8 | (s0 ? S1INCL : 0)`, 8-bit preamble;
- PCNF1 = `maxlen | 0x01040000` (BALEN=4, ENDIAN=big, WHITEEN=0);
- CRC as in A9.
- Controller: `0x2565c..0x256ae` with struct `{8,1,…,maxlen 0x82, balen 4, big 1}`, BASE0=BASE1,
  AP1=`0xF0` (`0x25794`), CRC identical.

**Addresses:**
- discovery `0xFACEB00C`/`0xAA`, freq 2, advert LENGTH 0x20 (elk-spl `0x7f60..0x7f74`);
- advert layout `[0]=2, [1..4] info, [5..12] device ID, [13..16], [17..30] 14 B, [31]`
  (`FUN_000080c8`);
- DM base = ID low word (`+0x28`).
- Device TX = AP7 = `slot+1`, TXADDRESS=7 (`FUN_00028ad0` `0x28b04..0x28b12`).

**Channel table:** `syncboss 0x4fe70` = 37 × u32 `4,6,…,24,28,…,78` (2402 and 2426 excluded), used
by `FUN_0001ac24` (bounds `< 0x25`).

**Hop:**
- `hop = (u8)LL[0x50] % 11 + 5` (host `FUN_0001e150`, the reciprocal `/11`; device `0x245c6..0x245d4`
  `udiv`/`mls` on `LL+0x1e4` byte, `+5`).
- `unmapped = (hop*n + unmapped) % 37`; if the map bit is clear, `idx = used[unmapped % num_used]`
  (`FUN_0001aaf4`).
- `LL+0x50` is the u32 netaddr, so the "low byte" = `netaddr & 0xFF` as written to BASE.

**Beacon layout** (controller parser `FUN_00024164`; RX buffer = `[S0][LEN][S1 pad][payload]`):
- S0 must be 4, and `LEN-14 < 0x25` (14..50);
- map = `p0>>3 | p1<<5 | p2<<13 | p3<<21 | p4<<29` (+ `p4>>3` high bits), at least 8 channels set;
- `p5 < 37` → unmapped;
- `p0 & 6` → DM countdown `(p0&7)>>1`;
- `u16 p[6..7]` → session nonce (`LL+0x298`);
- `u32 p[8..11] + u16 p[12..13]` → 48-bit timestamp, LE;
- CL from p14. Byte 15 = rx mask (host `FUN_0001cdcc` sets bit `slot` in `CL+0xf3`).

**Timing:**
- beacon period 2000 (`FUN_00023e54`: `n*2000 + 2000 + anchor`);
- window `[t - w, t + 0xfc + w]`, with `w = (n+1)*80000/1e6 + 6`, capped at 0x398 (920);
- anchor = capture − 0x14 (`FUN_00024164`, `LL+0x278`);
- slot offset table `0x32504 = {0,225,525,825,1125}`, `+0x15e` (350) (`0x28af6..0x28b06`).

**Pairing (controller side):**
- the 0x12 read returns the 32-byte pubkey and consumes the 32-byte host pubkey (`FUN_00003948`);
- 0x11/0x1d decrypt `payload+8`, 0x18 bytes, IV = `payload[0..7]`, counter 0 (`FUN_00009198` args);
- a decrypted length other than 0x14 is rejected;
- store: 20 B at record +0, key at record +0x14 (`FUN_000038e8`);
- wrap key = 4 words of the X25519 secret (`FUN_00009084`). Host side: 32 bytes = IV 8 +
  CT 20 + MIC 4.
- `WriteAESKey 0x14` = `FUN_000081bc` stub. Reset 0x15 → `FUN_00002a04`.

**CCM block:**
- KEY at `cfg+0x110` (CNFPTR = `ctx+0x110`, `FUN_0001b0a4`);
- PKTCTR at `+0x120` written as a 64-bit pair, bounded `< 2^39` (`cmp/sbcs` against
  `0x7f:ffffffff` at `0x1b20e..0x1b21a`);
- IV at `+0x129/+0x12d`; MIC 4; output `len+4`; MODE extended length, 2 Mbit.

**Version 0x1701:**
- the only `movw rX,#0x1701` in elk-app is `0x18b90` → `strh [r4,#8]`;
- no `movw #0x1701` in syncboss;
- it lands at request bytes 10..11 (A3/A14).

**Input:**
- `FUN_00021fd4(0x37, buf, 0x3d)` reads the 61-byte sample;
- CRC-32 over `[0:0x39]` vs u32 at 0x39 (A18);
- buttons reg 9: all 12 bits as documented (decomp of `FUN_000173bc`: low byte
  `b0,b2,b4,c2,b6,b1,b3,b5`, high nibble `b7,c3,c0,c1`);
- reg 3 = `a | b<<12` from 0x23/0x25;
- reg 0x15 = u16 @0x37; reg 2 = u32 @0;
- reg 0xb = 12 B (`FUN_00014c1c`).

**Not re-verified here** (left as they are tagged): the Gate A keyword sweep; the DM-beacon cadence
and 4000 µs branch (INFERRED); the pairing-link 900..2000 µs timing; the libsyncboss host-API names in
Q4/Q5.

---

## FRAME-TRACKER §8 spot-check

Done by a helper from the decomp text only: its shell was blocked, so there was no disassembly.
**No §8 claim was found wrong.** Re-derived and consistent with `driver/src/blockqueue.h`,
`cv_tracker.cpp` and `cv_source.cpp`:

**Queue Create args** (driver_cv `FUN_001d9a40`):

| queue | args |
|---|---|
| data | `(0x30, 0x200, 4, 0)` |
| event | `(0x6010, 0x200, 4, 0)` |
| `/xrservice/controller_<id>/pose` | `(0x90, 0x200, 4, 1)` |

- Connect (slot +0x08) is used when not first.
- Slots +0x18/+0x20/+0x40/+0x28/+0x38 are as in `blockqueue.h`.
- XRService requests `IVRBlockQueue_005` and only Connects (partial decomp coverage).

**Create validation** (vrserver `FUN_0035ff28`):
- returns 5/8/9/7 as documented;
- returns **1** when the segment already exists, so §8's INFERRED "QueueAlreadyExists = 1" can be
  CONFIRMED (static);
- `flags & 1` records the creator as a reader (OwnerIsReader).

**Event block** (`FUN_001dfe78`):
- id +0, type +4, hwid +8;
- onboard config at +0x10 and default at +0x3010 (`strncpy … 0x2fff`);
- PathWrite layout and WritePathBatch/StringToHandle slots match.

**IMU block** (`FUN_001d46c0`): `u32 id@0, f64 t@8, 6×f32 @0x10, u32 flags @0x28`. The IMU and pose
timestamps share one offset clock.

**Pose block** (`FUN_001d9e60`): `t@8` (−1 = invalid), quat w at +0x10. Position and velocity are
rotated; angular velocity at +0x60 is not. This matches `ConvertPoseBlock`.

**Issues:**
- **F1 (wording):** §8.5/§8.6 and `blockqueue.h:267-270` still tag the IMU vector order, units and
  metres as INFERRED. §9.1 live-verified them; upgrade the tags.
- **F2 (risk, HARMLESS today):** XRService reads the **event** queue at most once per second
  (`FUN_00f2d650`, a `now − last ≥ 1.0` gate, one event per call). With a ring of 4 blocks, a
  burst of more than 4 events in about 4 s (two Touch Plus, real controllers, re-announces) can
  overrun. Space our event writes ≥ 1 s apart and document it.
- **F3 (risk):** XRService skips registration and config delivery for a deviceId already in its
  list (`goto LAB_00f2dd78`). No removal was seen in the decompiled part. After our
  disconnect → re-Start with the same id in one XRService lifetime, the config may not be re-sent,
  and `CvTracker`'s "re-send on silence" won't help. Test on device, or use a fresh deviceId per
  session.
- **F4 (wording):** the consumer only tests `type == 0`. §8.4 "parsed only for 1" may hold inside
  `0xf29cf0`, which is not in the decomp set.

**Could not be checked statically:**
- XRService `0xf29b20` / `0xf29cf0` read type and timeout;
- the "missing property → length 0" rule;
- vrserver vtable addresses;
- the `0x4a4db0` axis constant. It is live-verified by §9.4.

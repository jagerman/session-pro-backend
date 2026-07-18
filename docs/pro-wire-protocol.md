# Session Pro — wire & proof format (authoritative spec)

> **Status: authoritative, pre-launch, mutable.** This is the single source of truth for the Session
> Pro proof, signed-request, and revocation-list formats, implemented by **both** the backend (signer)
> and libsession-util + clients (verifier / request-builder). It **replaces** the old scheme of
> `// must match <github permalink>` comments scattered across the two repos.
>
> The format is **not frozen** until Pro launches (no client can validate a real proof yet — the
> backend signing pubkey isn't finalized). Until then, fix it here and both sides implement to it. It
> freezes at launch.
>
> This document describes the **target** format. Some fields differ from what the code emits today; the
> **§Deltas** section lists exactly what changes. Do not implement from the current code — implement
> from this spec.

## 1. Primitives & conventions

- **Hash:** BLAKE2b, 32-byte digest, 16-byte **personalisation** (ASCII, `_`-right-padded to 16), **no
  key, no salt**. (The one historical salted use — the generation token — is removed; see §Deltas.)
- **Signatures:** Ed25519. A signature is over the 32-byte BLAKE2b digest described per message.
- **Integer encoding in signed hashes:** every multi-byte integer is **explicit little-endian**, fixed
  width as stated. (Implementations MUST serialize explicitly — never rely on host byte order.)
- **Time quantities:** **UNIX-epoch seconds** everywhere (never milliseconds), for both timestamps and
  durations. Almost every value is a JSON **integer**: every expiry, every duration, and anything the
  backend computes or rounds lands on a whole second (Session Pro expiries are day-aligned, never
  sub-second). The **only** exception is a short, explicitly-enumerated set of **upstream provider event
  instants** — currently `purchased_ts` (provider purchase time) and `revoked_ts` (provider revocation
  time) — emitted as JSON **floats** so the provider's sub-second precision survives; the fractional part
  is just the sub-second remainder, still seconds. (A binary64 float resolves current-era timestamps to
  ~238 ns, so this preserves milliseconds exactly.) Every value **serialized into a signed hash is an
  integer**, 8-byte LE — the hashed quantities are all whole-second by nature, and a client-supplied
  hashed timestamp (`ts`, `refund_requested_ts`) MUST be an integer. The DB stores every instant at full
  `timestamptz` (µs) precision regardless of wire type, so an integer wire field is a *display* choice,
  not data loss — a field can widen to a float later with no storage change.
- **Field-name markers (no unit suffix, ever).** Seconds is the universal unit, so **no** field carries a
  `_ms`/`_s` marker. Timestamps take a short **`_ts`** suffix (the redundant `_unix` is dropped — the
  value is just seconds-since-epoch): `expiry_ts`, `effective_ts`, `revoked_ts`, and a request nonce is
  bare `ts`. Durations are named `…_duration` (e.g. `grace_period_duration`). The `_ts`/`_duration`
  marker stays because the field names are often past participles (`revoked`, `redeemed`) that would
  otherwise read as booleans; only the *unit* suffix is dropped, never the type marker. A value needing
  finer resolution than a whole second is a JSON **float** (see Time quantities), never a `_ms`-suffixed
  integer — so the unit suffix never reappears.
- **Byte strings on the JSON wire:** lowercase hex, no `0x` prefix. Fixed lengths: pubkeys 32 B (64 hex),
  signatures 64 B (128 hex), `revocation_tag` 32 B (64 hex).
- **JSON numbers:** only for values whose *realistically-occurring* value stays `< 2^53`. Anything that
  can exceed that (opaque IDs, tokens, provider transaction ids) is a **string**. `ticket` is typed
  `int64` for headroom + signedness + restore-safety, but its *value* is a monotonic counter that stays
  far below 2^53 (it ticks only when a revocation is **added** — never on expiry/prune-removal, see §4), so it rides as a **number** — the int64 is
  a storage/type choice, not a value range. All `_ts` / `_duration` values likewise stay numbers
  (seconds ~1.7e9 « 2^53).
- **Enums are transmitted as stable string `code`s, never integers** (backed by lookup tables — item 9;
  the DB keeps a surrogate int `id`, but the wire *and the signed hashes* use the `code`, so no magic
  number ever crosses the wire and new values are additive `INSERT`s):
  - `payment_provider`: `"google_play"`, `"app_store"`, `"rangeproof"`
  - `status`: `"unredeemed"`, `"redeemed"`, `"expired"`, `"revoked"` — **`"revoked"`** is the terminal
    revoked state (refund/chargeback/protocol kill); distinct from the separate `refund_requested_ts`
    field (refund-*requested* ≠ *revoked*). There is no `"refunded"` status.
  - `plan`: a compact **billing-period code** — `"1m"`, `"3m"`, `"1y"` (`N` + unit `d`/`w`/`m`/`y`),
    free-form for non-period plans (`"lifetime"`). Canonical per period (a 12-month product is `"1y"`,
    not `"12m"`). **Display/accounting only** (never computed with); recurrence is the separate
    `auto_renewing` field, *not* part of this code. Client maps/parses it for display; backend groups by it.
  - A `nil`/unset value is never valid on the wire — every stored row has a real code.

## 2. The Pro proof (signed by the backend)

The proof certifies that a rotating key is Pro-entitled until an expiry. It is **self-contained and
verified offline**; it carries **no user identity**.

**Wire (JSON):**
```
{ "version": 0,
  "revocation_tag": "<64 hex>",   // opaque 32-byte value; see §2.1
  "rotating_pkey":  "<64 hex>",   // Ed25519 public key the proof entitles
  "expiry_ts": <int>,             // seconds; entitlement valid until this instant
  "sig": "<128 hex>" }            // Ed25519 over the digest below
```

**Signed digest** — `sig = Ed25519(backend_key, H)` where
```
H = BLAKE2b-256(
      person = "ProProof________",              # 16 bytes
      version  .to_bytes(1,  'little')
   ‖  revocation_tag                             # 32 bytes, raw
   ‖  rotating_pkey                              # 32 bytes, raw
   ‖  expiry_ts.to_bytes(8,  'little'))          # seconds
```
Verifiers reconstruct `H` from the proof fields and check `sig` against the backend's public key, then
check `expiry_ts` against their clock and `revocation_tag` against the revocation list (§4).

### 2.1 `revocation_tag`
A per-**generation** opaque **random 32-byte value** (a generation = one epoch of a user's aggregate
entitlement). Clients treat it as an **opaque blob compared for equality** against revocation-list
entries — nothing derives or interprets it. (Formerly `gen_index_hash`, a keyed BLAKE2b of a counter;
now a stored random value — see §Deltas. The name change is because it is not a hash of anything the
client can or should compute.)

## 3. Signed requests (signed by the user's master key)

Each request is authorised by an Ed25519 signature from the account **master key** over a
personalised BLAKE2b-256 digest. Field order and widths are exact. `ts` is the caller's clock
(backend accepts it within a tolerance window, currently ±70 s).

**3.1 generate-proof** — person `ProGenerateProof`
```
version(1) ‖ master_pkey(32) ‖ rotating_pkey(32) ‖ ts(8)
```

**3.2 add-payment** — person `ProAddPayment___`  (note: **no timestamp**)
```
version(1) ‖ master_pkey(32) ‖ rotating_pkey(32) ‖ provider_code ‖ payment_id (§3.5)
```

**3.3 set-refund-requested** — person `ProSetRefundReq_`  (note: **no rotating_pkey**, two timestamps)
```
version(1) ‖ master_pkey(32) ‖ ts(8) ‖ refund_requested_ts(8) ‖ provider_code ‖ payment_id (§3.5)
```

**3.4 get-pro-details** — person `ProGetProDetReq_`
```
version(1) ‖ master_pkey(32) ‖ ts(8) ‖ count(4)
```

**3.5 payment_id** — one **opaque UTF-8 string** identifying the payment, appended verbatim for add-payment
& set-refund. The client treats it as a single opaque token (received from the provider's purchase flow,
passed through unread); the backend, which alone acts on it, owns its encoding.

**Each provider owns its `payment_id` encoding.** The one cross-cutting invariant is that `payment_id` is
an **exact byte string** — it enters the signed hash verbatim, so both sides must agree on the exact bytes.
Beyond that, structure is a private contract between the provider's client flow and the backend's ingest:
- `google_play` → `google_payment_token + "|" + google_order_id`, **split once on the first `|`**. Safe
  today because the token is base64url (`[A-Za-z0-9._-]`) and the order id is `GPA.####-…` — neither
  contains `|`.
- `app_store`   → `apple_tx_id`
- `rangeproof`  → `rangeproof_order_id`  *(add-payment only)*

> This collapses the old per-provider wire fields to one opaque value: the wire/hash no longer needs to
> know a payment identifier has sub-fields. If a future provider's identifier can itself contain the
> delimiter, **that provider** picks a scheme (length-prefix / fixed structure) — a local choice, because
> using the value already requires provider-specific logic. No global length-prefixing: an ambiguous
> composite is anyway unreachable (the digest is master-signed + onion-encrypted, and the backend splits
> then looks up by the separate fields, never by the raw composite), so a prefix width would be pure
> arbitrariness for no reachable gain.

## 4. Revocation list

Poll endpoint; response is JSON and **not signed** (fetched over TLS/onion). The client sends its
last-seen `ticket`; the backend returns the full list only if the ticket advanced.

**Request:** `{ "version": 0, "ticket": <int64> }`
**Response:**
```
{ "version": 0,
  "ticket":     <int64>,   // int64 type; VALUE stays « 2^53, so a JSON number (see §1); restore-safe
  "retry_in":   <int>,     // recommended poll interval / throttle (seconds)
  "retain_for": <int>,     // seconds a client should keep each entry after seeing it (≈ the max
                           //   proof-validity window, ~30d). Sent, not hardcoded, so it can vary.
  "items": [ { "revocation_tag": "<64 hex>",
               "effective_ts":   <int> },   // start rejecting matching proofs at/after this
             ... ] }        // empty if caller's ticket == current ticket
}
```
A proof is revoked iff its `revocation_tag` matches a listed entry **and** the client clock ≥ that
entry's `effective_ts`.

**Local aging is a memory-only cleanup timer — no per-entry expiry.** A client keeps each entry until
roughly `(when it saw the entry) + retain_for`, then drops it. Correctness does not depend on precision
here: holding a stale entry too long is harmless (its random `revocation_tag` never matches a live proof
— those have expired, and a new generation gets a fresh random tag), and `retain_for ≥` the proof-validity
window guarantees a client never drops an entry while a valid proof could still carry it. The backend
prunes its *own* served list on the same basis (`creation + retain_for`) to keep it small — **without**
bumping `ticket`, so a prune never triggers a client re-fetch. (This kills the old per-entry `expiry_ts`,
whose value was the entitlement expiry — up to a *year* for long subs, absurd for a cleanup timer.)

## 5. Other JSON responses

`get-pro-details` and payment/refund responses are unsigned JSON data. They carry the same conventions:
timestamps are `_ts` seconds — **integer** everywhere except the two upstream provider event instants
`purchased_ts` and `revoked_ts`, which are **floats** to keep provider sub-second precision (§1) — enums
are their string `code`s (§1), byte strings are hex, and no key name leaks an internal implementation
detail (see §6). (Their per-field shapes track `server.py`; only the naming/units rules here are
normative for them.)

## 6. Field-naming rule
Wire (JSON) field names describe **purpose to the consumer**, never server implementation, and carry
**no unit suffix** (the unit is the §1 default; add one only for a genuine deviation) — timestamps take
a `_ts` marker, durations `…_duration`. Audit every response key against both rules. Known renames:
`gen_index_hash` → `revocation_tag`; every `…_unix_ts_ms` → `…_ts`; `grace_period_duration_ms` →
`grace_period_duration`; `retry_in_s` → `retry_in`.

## Deltas from the current code (what to change on both sides)

1. **Timestamps ms → seconds** everywhere (proof `expiry`, all request-hash timestamps, all wire
   `…_unix_ts_ms` → `…_ts`). 8-byte LE in hashes unchanged (value is seconds now). Integer seconds
   everywhere **except** the two upstream provider event instants in the get-details response,
   `purchased_ts` and `revoked_ts`, which are JSON **floats** carrying the provider's sub-second
   precision (§1). No `…_ts_ms`/`_ms` field survives — the unit is always seconds; precision that
   exceeds a whole second rides in the float.
2. **`gen_index_hash` → `revocation_tag`**: rename the wire key **and** change its nature — it is now a
   stored **random** 32-byte value, not `BLAKE2b(gen_index, salt)`. The server-side counter + salt
   derivation is deleted; clients already treat it as opaque, so client-side this is a rename only.
3. **`ticket`: uint32 → int64**, and restore-monotonic on the server (a wrap or a DR rollback must not
   let a client silently miss revocations).
4. **Explicit little-endian** for every multi-byte integer in a signed hash (the client currently relies
   on host byte order via `reinterpret_cast`; make it explicit).
5. **Payment identifier → single opaque `payment_id` (§3.5)** — *both-sides-flip*. The per-provider wire
   fields (`google_payment_token`/`google_order_id`/`apple_tx_id`/`rangeproof_order_id`/`order_id`) collapse
   to one opaque UTF-8 `payment_id` in `payment_tx`, get-details items, **and** the signed add-payment /
   set-refund hash tail (`… ‖ provider_code ‖ payment_id`). Each provider owns its encoding; the only
   invariant is exact bytes (it's signed). Google's is `token ‖ "|" ‖ order_id`, split once on the first
   `|`; the backend still stores the split-out fields in its own typed columns. Length-prefixing considered
   and dropped (collision unreachable: master-sig + onion + backend looks up by split fields, never the raw
   composite). Client passes `payment_id` through opaque; backend owns split/join.
6. **Revocation list reshaped.** Per entry: keep `revocation_tag` + `effective_ts`; **drop `expiry_ts`**
   (its value was the entitlement expiry — up to a *year* for long subs, absurd for what is only a
   cleanup timer). Response gains a single **`retain_for`** (≈ proof-validity window, ~30d) that clients
   apply as `seen + retain_for` for **memory-only** local aging (§4). Client-side these are additions
   (the current `ProRevocationItem` has neither `effective_ts` nor a retain window). **`effective_ts` is
   a real semantic** — a matching tag is *not* revoked until the client clock ≥ `effective_ts`; rejecting
   on tag-match alone is too early. Backend: it already emits `effective`/`retry_in`; it must (a) rename
   to `_ts`, (b) add `retain_for`, (c) stop emitting the per-entry entitlement-based expiry (drop the
   field), (d) prune its served list at `creation + retain_for` **without** bumping `ticket`.
7. **Delete the dead `SeshProBackend__` personalisation** (libsession-util) — unused decoy; the live
   proof personalisation is `ProProof________`.
8. **Fix `examples/verify_pro_proof.py`** (backend) — it hashes with `SeshProBackend__` (wrong) and takes
   `--expiry-ts-ms` (wrong unit); correct to `ProProof________` + seconds. It's the file an implementer
   copies, so it must be right.
9. Minor: generate-proof signing hardcodes `version = 0` despite a version field — thread the real value.
10. **Enums → string `code`s** (§1): `payment_provider`, `status`, `plan` are transmitted as string codes,
    not integers — backed by lookup tables (backend item 9; DB keeps an int `id`, wire/hash use the
    `code`). `status`/`plan` are wire-only (unsigned responses) → easy. **`provider` is also in the
    add-payment / set-refund signed hashes** (was a 1-byte int, now the UTF-8 `provider_code`), so that's
    a **both-sides-flip**. `plan` is `"1m"/"3m"/"1y"` (period code, not a lookup of tiers-with-attributes).

## Open (coordination)
- **Spec home:** this file, in the backend repo (`docs/pro-wire-protocol.md`), is proposed as the
  authoritative location; libsession-util references it rather than re-hardcoding. Adjust if a neutral
  location is preferred.
- *(Resolved: revocation per-entry `expiry_ts` dropped in favour of a single `retain_for` window +
  memory-only client aging — §4. The old entitlement-based expiry is gone.)*

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

- **Signatures:** Ed25519 over the **message directly** — NOT over a hash of it. Ed25519 already hashes
  internally and these messages are tiny, so there is no pre-hash (no BLAKE2b). Each signed message is
  built by the same rule (§1.1).
- **§1.1 Signed-message construction.** A signed message is: a **16-byte domain prefix** (ASCII,
  `_`-right-padded to 16 — the value that used to be the BLAKE2b personalisation) followed by the fields
  in the stated order, each encoded by type:
  - **public key / raw bytes** (`master_pkey`, `rotating_pkey`, `revocation_tag`): appended **verbatim**
    (fixed width — 32 bytes — so self-delimiting).
  - **integer** (`ts`, `count`, `expiry`, …): its **canonical decimal ASCII** — no grouping, no leading
    zeros, `-` for negatives (Python `str(int).encode()`, C++ `std::to_chars` base 10; both are
    locale-independent and MUST be used, not locale-aware formatters). This is why `count = -1` and
    unbounded values need no special handling.
  - **string** (`provider_code`, `payment_id`): its **UTF-8** bytes verbatim.
  - **Framing:** a single `\0` (NUL) byte is inserted **between two adjacent variable-length fields** (i.e.
    between two int/str fields). Fixed-width fields (keys/tag) need no separator. A `\0` cannot occur in a
    decimal integer or a `provider_code`; the only field that can contain a `\0` is the opaque
    `payment_id`, which is **always the final field**, so it is never followed by a separator and the
    parse is unambiguous.
  (The old scheme — sign a BLAKE2b-256 digest with fixed-width little-endian integers — is removed; see
  §Deltas.)
- **Time quantities:** **UNIX-epoch seconds** everywhere (never milliseconds), for both timestamps and
  durations. Almost every value is a JSON **integer**: every expiry, every duration, and anything the
  backend computes or rounds lands on a whole second (Session Pro expiries are day-aligned, never
  sub-second). The **only** exception is a short, explicitly-enumerated set of **upstream provider event
  instants** — currently `purchased_ts` (provider purchase time) and `revoked_ts` (provider revocation
  time) — emitted as JSON **floats** so the provider's sub-second precision survives; the fractional part
  is just the sub-second remainder, still seconds. (A binary64 float resolves current-era timestamps to
  ~238 ns, so this preserves milliseconds exactly.) A value that enters a **signed message is always a
  whole-second integer** (encoded as canonical decimal ASCII per §1.1), never a float — the signed
  timestamps (`ts`, `refund_requested_ts`, proof `expiry_ts`) are whole-second by nature; the float
  `purchased_ts`/`revoked_ts` are get-details *response* fields, never signed. The DB stores every instant at full
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
  the DB keeps a surrogate int `id`, but the wire *and the signed messages* use the `code`, so no magic
  number ever crosses the wire and new values are additive `INSERT`s):
  - `payment_provider`: `"google_play"`, `"app_store"`, `"rangeproof"`
  - `status`: TWO distinct fields share this name at different nesting levels. Each get-details **item**
    carries a *payment* `status`: `"unredeemed"`, `"redeemed"`, `"expired"`, `"revoked"` — **`"revoked"`**
    is the terminal revoked state (refund/chargeback/protocol kill); distinct from the separate
    `refund_requested_ts` field (refund-*requested* ≠ *revoked*). There is no `"refunded"` status. The
    **top-level** get-details `status` is the account's overall *Pro* status: `"never"` (never been Pro),
    `"active"`, `"expired"`.
  - `plan`: a compact **billing-period code** — `"1m"`, `"3m"`, `"1y"` (`N` + unit `d`/`w`/`m`/`y`),
    free-form for non-period plans (`"lifetime"`). Canonical per period (a 12-month product is `"1y"`,
    not `"12m"`). **Display/accounting only** (never computed with); recurrence is the separate
    `auto_renewing` field, *not* part of this code. Client maps/parses it for display; backend groups by it.
  - A `nil`/unset value is never valid on the wire — every stored row has a real code.
- **No version byte in any signed message; no `version` field on requests/responses** (Delta #11).
  Requests are domain-separated by their **domain prefix** (§1.1) and their **endpoint**; a new *request*
  shape earns a **new endpoint**, so requests carry no version at all. The **proof** is the exception: it
  is free-floating and offline-verified (no endpoint), so it keeps a **plaintext `version` field** — but
  that field is a verification *input*, not a signed byte. The verifier reads it and maps the proof
  **data → (domain prefix, message)**: `version` selects the domain prefix for that version (v0 →
  `ProProof_v0_____`; the map is arbitrary per-version, so a future version may pick any prefix),
  which is what binds the version into the signature. You can't learn a version
  *through* a signature you haven't verified — you must already know it to reconstruct the message — so the
  version rides in the clear as data and a version byte inside the message would be redundant. The
  version→domain-prefix map is per-version and arbitrary — a future version may choose any
  domain prefix; a verifier refuses versions it doesn't know, so nothing old breaks.

## 2. The Pro proof (signed by the backend)

The proof certifies that a rotating key is Pro-entitled until an expiry. It is **self-contained and
verified offline**; it carries **no user identity**.

**Wire (JSON):**
```
{ "version": 0,                   // plaintext; selects the domain prefix (see below). NOT hashed.
  "revocation_tag": "<64 hex>",   // opaque 32-byte value; see §2.1
  "rotating_pkey":  "<64 hex>",   // Ed25519 public key the proof entitles
  "expiry_ts": <int>,             // seconds; entitlement valid until this instant
  "sig": "<128 hex>" }            // Ed25519 over the message below (§1.1)
```
`version` is a **plaintext data element**, deliberately **not** a byte in the signed message (§1, Delta #11).
Verification is a mapping from the transmitted **data → (domain prefix, message)**: the verifier reads
`version`, looks up the domain prefix + field layout for that version (v0 → `ProProof_v0_____`),
reconstructs the message, and checks `sig`. So the version is a verification **input**, known before
verification — never something discovered *through* a signature (you must already know it to reconstruct
the message at all). It needs no signing: tampering with it just makes the verifier use the wrong
prefix and the signature fails. A verifier that doesn't recognise a `version` **refuses to
interpret the proof** — it *cannot* verify a format it doesn't know. The version→prefix map is
arbitrary and per-version: a future version may pick **any** prefix (or reshape the proof
entirely), and no existing verifier breaks because it never attempts an unknown version. (A version byte
*inside* the message would be pure redundancy — "extra bits for nothing" — since the version is already
the plaintext input that picks the prefix.)

**Signed message** — `sig = Ed25519(backend_key, M)` over the message **directly** (no pre-hash; §1.1);
the verifier picks the 16-byte domain prefix from the plaintext `version` (`0` → `ProProof_v0_____`), then:
```
M =  "ProProof_v0_____"        # 16-byte domain prefix; the "_v0" is the version, chosen from the data
  ‖  revocation_tag            # 32 bytes, raw
  ‖  rotating_pkey             # 32 bytes, raw
  ‖  dec(expiry_ts)            # canonical decimal ASCII seconds (trailing field → no separator)
```
Verifiers reconstruct `M` from the proof fields and check `sig` against the backend's public key, then
check `expiry_ts` against their clock and `revocation_tag` against the revocation list (§4).

### 2.1 `revocation_tag`
A per-**generation** opaque **random 32-byte value** (a generation = one epoch of a user's aggregate
entitlement). Clients treat it as an **opaque blob compared for equality** against revocation-list
entries — nothing derives or interprets it. (Formerly `gen_index_hash`, a keyed BLAKE2b of a counter;
now a stored random value — see §Deltas. The name change is because it is not a hash of anything the
client can or should compute.)

## 3. Signed requests (signed by the user's master key)

Each request is authorised by an Ed25519 signature from the account **master key** over the message built
per §1.1 (16-byte domain prefix + typed fields, no pre-hash). Field order is exact. `ts` is the caller's
clock (backend accepts it within a tolerance window, currently ±70 s). **No message carries a `version`**
field or prefix (§1, Delta #11) — the domain prefix + the endpoint already domain-separate each message; a
new request shape gets a new endpoint. Below, `dec(x)` = the canonical decimal-ASCII integer of §1.1, raw
32-byte fields are self-delimiting, and `\0` separates adjacent variable-length fields.

**3.1 generate-proof** — domain `ProGenerateProof`
```
master_pkey(32) ‖ rotating_pkey(32) ‖ dec(ts)
```

**3.2 add-payment** — domain `ProAddPayment___`  (note: **no timestamp**)
```
master_pkey(32) ‖ rotating_pkey(32) ‖ provider_code ‖ \0 ‖ payment_id (§3.5)
```

**3.3 set-refund-requested** — domain `ProSetRefundReq_`  (note: **no rotating_pkey**, two timestamps)
```
master_pkey(32) ‖ dec(ts) ‖ \0 ‖ dec(refund_requested_ts) ‖ \0 ‖ provider_code ‖ \0 ‖ payment_id (§3.5)
```

**3.4 get-pro-details** — domain `ProGetProDetReq_`
```
master_pkey(32) ‖ dec(ts) ‖ \0 ‖ dec(count)
```

**3.5 payment_id** — one **opaque UTF-8 string** identifying the payment, appended verbatim for add-payment
& set-refund. The client treats it as a single opaque token (received from the provider's purchase flow,
passed through unread); the backend, which alone acts on it, owns its encoding.

**Each provider owns its `payment_id` encoding.** The one cross-cutting invariant is that `payment_id` is
an **exact byte string** — it enters the signed message verbatim, so both sides must agree on the exact bytes.
Beyond that, structure is a private contract between the provider's client flow and the backend's ingest:
- `google_play` → `google_payment_token + "|" + google_order_id`, **split once on the first `|`**. Safe
  today because the token is base64url (`[A-Za-z0-9._-]`) and the order id is `GPA.####-…` — neither
  contains `|`.
- `app_store`   → `apple_tx_id`
- `rangeproof`  → `rangeproof_order_id`  *(add-payment only)*

> This collapses the old per-provider wire fields to one opaque value: the wire/signed message no longer needs to
> know a payment identifier has sub-fields. If a future provider's identifier can itself contain the
> delimiter, **that provider** picks a scheme (length-prefix / fixed structure) — a local choice, because
> using the value already requires provider-specific logic. No global length-prefixing: an ambiguous
> composite is anyway unreachable (the message is master-signed + onion-encrypted, and the backend splits
> then looks up by the separate fields, never by the raw composite), so a prefix width would be pure
> arbitrariness for no reachable gain.

## 4. Revocation list

Poll endpoint; response is JSON and **not signed** (fetched over TLS/onion). The client sends its
last-seen `ticket`; the backend returns the full list only if the ticket advanced.

**Request:** `{ "ticket": <int64> }`  (no `version` field — §1, Delta #11)
**Response:**
```
{ "ticket":     <int64>,   // int64 type; VALUE stays « 2^53, so a JSON number (see §1); restore-safe
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

## 5. Response envelope

Every endpoint returns HTTP 200 with a JSON object discriminated by **`status`** (the envelope `status` is
authoritative for the application outcome; HTTP status is not used for it):

- `"ok"` — success; the payload is in **`result`** (an object, shape per endpoint). No `error`/`error_code`.
- `"fail"` — the request was understood but rejected by the client's input or a state precondition (the
  HTTP-4xx family: bad args, not-found, conflict). The client's to fix or accept; retrying the *identical*
  request generally won't help (the one exception is `stale_request`).
- `"error"` — the backend faulted while handling it (HTTP-5xx family: unhandled exception, DB fault). The
  client did nothing wrong; the same request may succeed later.

**`status` is a closed, exhaustive set** — `"ok"` / `"fail"` / `"error"` and nothing else, ever. A client
SHOULD treat any other `status` value as a protocol error (fail-closed), NOT a gracefully-ignored unknown.
The envelope will never grow a fourth `status`; a new category or extra detail is always conveyed by a new
**`error_code`** slug (which *is* open/additive — see §5.1) or a new field. Two deliberate extensibility
contracts: `status` is rigid (clients may model it as a fixed enum), `error_code` is extensible.

Non-`ok` responses carry two fields:
- **`error_code`** — a stable lowercase-`snake_case` machine slug, **always present** on non-`ok`. This is
  the identifier a client keys its localized (Crowdin) message off; an unrecognized (newer) slug degrades
  gracefully — the client falls back to `status`-level handling and/or shows `error`.
- **`error`** — a single human English string. It is a **fallback + diagnostic, NOT the user-facing text**
  (the user-facing text comes from the `error_code`→translation map). A client shows it only when it does
  not recognize the slug, and logs it. (Was an array `errors`; it is now one string, and on a malformed
  request the server reports the *first* bad field, not an accumulated list.)

```
{ "status": "ok",    "result": { … } }
{ "status": "fail",  "error_code": "<slug>", "error": "<english>" }
{ "status": "error", "error_code": "<slug>", "error": "<english>" }
```

### 5.1 `error_code` vocabulary

| slug | status | when / client action |
| --- | --- | --- |
| `invalid_request` | fail | malformed JSON, missing/wrong-type field, bad hex, out-of-range value, unsupported/disabled provider. A correct client never sees this. |
| `bad_signature` | fail | a request signature failed to verify. A correct client never sees this. |
| `stale_request` | fail | request timestamp outside the replay-tolerance window. The client may re-fetch server time (`/status`) and retry. |
| `unknown_payment` | fail | `add_pro_payment`: no payment matching those provider IDs is known for this user. Often transient (provider notification not yet received) → retry later. |
| `subscription_expired` | fail | the user's entitlement has lapsed → "renew" CTA. (Named to stay disjoint from `user_status: expired` — §5.2 — so no token belongs to two fields.) |
| `not_subscribed` | fail | no entitlement on record (never subscribed, or pruned after long inactivity) → "subscribe" CTA. |
| `revoked` | fail | the user's current entitlement was revoked. Treat as `subscription_expired` (renew) on clients today; the distinct slug is reserved for a future revoked-specific flow. |
| `internal_error` | error | backend fault; not the client's doing. |

### 5.2 Result payloads

`get-pro-details` and payment/refund `result` bodies are unsigned JSON data. They carry the same
conventions: timestamps are `_ts` seconds — **integer** everywhere except the two upstream provider event
instants `purchased_ts` and `revoked_ts`, which are **floats** to keep provider sub-second precision (§1) —
enums are their string `code`s (§1), byte strings are hex, and no key name leaks an internal implementation
detail (see §6). (Their per-field shapes track `server.py`; only the naming/units rules here are normative
for them.) Note some non-error outcomes live *in* `result`, not as a `fail`: get-details reports account
state as `user_status` (`never`/`active`/`expired`; `user_` disambiguates it from the envelope `status`
and the per-item payment `status`), and set-refund returns `{ "updated": <bool> }`. `user_status` is a
distinct axis from the `error_code` slugs (§5.1) and their vocabularies are deliberately **disjoint** — the
"lapsed" `error_code` is `subscription_expired`, not `expired`, so a value never belongs to two fields;
`user_status: never` is the state behind an `error_code: not_subscribed` rejection.

## 6. Field-naming rule
Wire (JSON) field names describe **purpose to the consumer**, never server implementation, and carry
**no unit suffix** (the unit is the §1 default; add one only for a genuine deviation) — timestamps take
a `_ts` marker, durations `…_duration`. Audit every response key against both rules. Known renames:
`gen_index_hash` → `revocation_tag`; every `…_unix_ts_ms` → `…_ts`; `grace_period_duration_ms` →
`grace_period_duration`; `retry_in_s` → `retry_in`.

## Deltas from the current code (what to change on both sides)

1. **Timestamps ms → seconds** everywhere (proof `expiry`, all request timestamps, all wire
   `…_unix_ts_ms` → `…_ts`). (Their in-signature encoding is now canonical decimal ASCII, not 8-byte LE —
   superseded by #13.) Integer seconds
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
   on host byte order via `reinterpret_cast`; make it explicit). **[SUPERSEDED by #13 — signed inputs are
   now messages, not hashes, and integers are canonical decimal-ASCII; no LE integer survives in a signed
   input.]**
5. **Payment identifier → single opaque `payment_id` (§3.5)** — *both-sides-flip*. The per-provider wire
   fields (`google_payment_token`/`google_order_id`/`apple_tx_id`/`rangeproof_order_id`/`order_id`) collapse
   to one opaque UTF-8 `payment_id` in `payment_tx`, get-details items, **and** the signed add-payment /
   set-refund signed-message tail (`… ‖ provider_code ‖ payment_id`). Each provider owns its encoding; the only
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
    not integers — backed by lookup tables (backend item 9; DB keeps an int `id`, wire/signed-message use the
    `code`). `status`/`plan` are wire-only (unsigned responses) → easy. **`provider` is also in the
    add-payment / set-refund signed messages** (was a 1-byte int, now the UTF-8 `provider_code`), so that's
    a **both-sides-flip**. `plan` is `"1m"/"3m"/"1y"` (period code, not a lookup of tiers-with-attributes).
11. **Drop the in-digest version byte everywhere; version requests via the endpoint, the proof via a
    plaintext field that selects its domain prefix** (Q11 + Q12) — *both-sides-flip*. The leading
    `version(1)` byte is removed from all five signed digests. Rationale: you can never learn a version
    *through* a signature you have not yet verified, while verifying requires you to already know it — so
    an in-message byte discovers nothing. For **requests** the version goes entirely (field + any marker): a
    new request shape earns a **new endpoint**, whose domain prefix is the discriminator. For the
    **proof** — a free-floating, offline-verified credential with no endpoint — the version stays as a
    **plaintext `version` field** (a verification input): the verifier reads it and maps the proof
    **data → (domain prefix, layout)**, looking up the domain prefix for that version (v0 →
    `ProProof_v0_____`; the map is per-version and arbitrary — a future version may pick any
    domain prefix, and a verifier just refuses versions it doesn't know). The domain prefix — not a
    byte — is what binds the version into the signature; tampering with the plaintext field just makes
    verification fail. Backend + libsession flip
    in lockstep (proof domain prefix `ProProof________` → `ProProof_v0_____`).
12. **Response envelope: string `status` + `error_code` slug + single `error` string** (§5) —
    *both-sides-flip*. Replaces the integer status codes (`0` ok, `1` generic error, `2` parse error,
    `100` already-redeemed, `101` unknown-payment). Concretely:
    - **`status`**: int → `"ok"` / `"fail"` / `"error"` — `fail` = client's fault / precondition (4xx
      family), `error` = backend fault (5xx family). Success payload stays in `result`.
    - **`errors` (array) → `error` (single string)**, and it is now *fallback/diagnostic only* — the
      user-facing text comes from mapping `error_code` to a localized (Crowdin) string. On a malformed
      request the server reports the **first** bad field, not an accumulated list.
    - new **`error_code`** slug, always present on non-`ok`; full vocabulary in §5.1. Slugs are plain (no
      `pro_` prefix on the wire); clients own their prefixed translation keys. New slugs are additive —
      an unrecognized one must degrade to `status`-level handling, never hard-fail the parse.
    - **`add_pro_payment` is now idempotent.** A re-redeem of an already-redeemed payment returns `"ok"` +
      a freshly-signed proof for the user's current entitlement (identical to a first redemption), instead
      of the old `already_redeemed` (100) error — that slug is **deleted**. This establishes the invariant
      **`ok` ⟹ a proof is present** on the proof-returning endpoints. A genuinely lapsed entitlement
      (`subscription_expired`/`revoked`) or unrecognised payment (`unknown_payment`) is a `fail` with that slug.
    - HTTP status is always **200**; the envelope `status` is authoritative.
    - Fixes current miscategorisation: signature failure and timestamp-out-of-tolerance (today variously
      `PARSE_ERROR`/`GENERIC_ERROR`) become `fail` + `bad_signature` / `stale_request`.
    - **Client actions:** parse `{status, result}` vs `{status, error_code, error}`; treat `ok`⟹proof
      present; map each `error_code` to a Crowdin string (developer-facing `invalid_request`/
      `bad_signature`/`internal_error` may share one generic message); **delete the already-redeemed
      special-case** (Android's no-op branch, iOS's `needsRefreshProProof` skip — the normal success path
      now covers it); `subscription_expired`→renew, `not_subscribed`→subscribe, `revoked`→renew (until/unless a
      revoked-specific flow is built). *(Backend-internal, not wire: the `make_error_response` returns
      become raised exceptions and `ErrorSink` is removed — no client impact.)*
13. **Sign the message, not a hash; canonical field encoding** (§1.1, §2, §3.1–3.4) — *both-sides-flip,
    touches ALL FIVE signatures incl. the offline-verified proof.* Supersedes #4 (and the LE parts of #1).
    - Ed25519 signs the **message directly** — no BLAKE2b pre-hash. Each message = 16-byte domain prefix
      (the value that was the BLAKE2b personalisation, unchanged) + the fields.
    - Field encoding by type: raw bytes for keys/`revocation_tag` (fixed width); **canonical decimal
      ASCII** for integers (`ts`, `count`, `expiry`, `refund_requested_ts`) — Python `str(int)` / C++
      `std::to_chars(base 10)`, both locale-independent (NOT `std::to_string`/`printf`/locale formatters);
      UTF-8 for `provider_code`/`payment_id`.
    - Framing: a single `\0` between two **adjacent variable-length** fields (int/str); fixed-width fields
      unseparated. `payment_id` (the only field that may contain `\0`) is always last. This also fixes the
      old undelimited `provider_code‖payment_id` ambiguity.
    - Consequences: `count = -1` (unlimited) now works with no special-casing; no fixed-width/signedness
      trap anywhere in a signed input; BLAKE2b is gone from the signing path entirely.
    - Backend: done (`backend.signed_message` + the `make_*_message`/`build_proof_message` builders;
      verify/sign sites unchanged since they already `verify(msg,sig)`/`sign(msg)`). libsession must
      rebuild all five signed inputs to §1.1 in lockstep. The example files (`verify_pro_proof.py`,
      `endpoint_example.py`) still show the old scheme → fix with #8's example sweep.

## Open (coordination)
- **Spec home:** this file, in the backend repo (`docs/pro-wire-protocol.md`), is proposed as the
  authoritative location; libsession-util references it rather than re-hardcoding. Adjust if a neutral
  location is preferred.
- *(Resolved: revocation per-entry `expiry_ts` dropped in favour of a single `retain_for` window +
  memory-only client aging — §4. The old entitlement-based expiry is gone.)*
- *(Resolved: response envelope reworked — §5 + Delta #12. `status` → `ok`/`fail`/`error`, single `error`
  string, `error_code` slug vocabulary. Confirmed with the client agent: `add_pro_payment` idempotent
  (`already_redeemed` deleted, `ok`+proof returned — both clients drop their special-case); lapsed slugs
  `subscription_expired`/`not_subscribed` are distinct client CTAs (renew vs subscribe), `revoked` distinct
  on the wire but treated as `subscription_expired` on clients for now. Note the `error_code` vocabulary is
  deliberately DISJOINT from `user_status` {never,active,expired} — hence `subscription_expired`, not
  `expired` — so no token identifies two different fields (Q16).)*

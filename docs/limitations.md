# Session Pro Backend — known limitations

This file has two parts. **Part 1 (the bulk)** is *payment-provider limitations & store-config
invariants*: dormant notification/state handlers that are safe only while the matching store feature is
turned off. **Part 2** (at the end) is *accepted design limitations*: deliberate trade-offs we are
knowingly not fixing (e.g. residual metadata side-channels).

## Payment-provider limitations & store-config invariants

**Read this before enabling ANY new feature in Google Play Console or App Store Connect.**

The backend does not (yet) handle every payment-provider notification, subscription state, or product
type. Each unhandled path is **dormant and safe *only* because the corresponding store-side feature is
currently turned off**. Flip that switch without first wiring the handler and you get a silent
correctness/entitlement hole — an over-entitled user (kept Pro after a refund) or a paid-but-no-Pro user
(payment never registered) — often failing *un-loudly* (an RTDN that retries forever, or an HTTP 500 that
Apple eventually stops retrying).

This file is the single, human-visible list of those constraints. It is the **proactive** half of the
safeguard; the **reactive** half is a planned loud-guard: a shared `unsupported_feature(name, …)` helper
that logs CRITICAL (→ ops alert) and safely skips (never raises / wedges) when one of these branches is
hit. Neither substitutes for actually implementing the handler before the feature is enabled.

Keep this in sync with the code — it describes real branches, not intentions.

### Legend
- **Consequence** — what happens to a real customer if the branch is hit in production.
- **Fails** — *silent* (no human notified: RTDN retry-loop / swallowed / no-op) vs *loud-ish* (HTTP 500 +
  provider retries) vs *crash* (raises). None currently alerts ops; that's what the Phase-4 loud-guard adds.

---

## Google Play

**Keep OFF until wired:**

| Feature / notification | Enabled in Play Console by… | Current behaviour if hit | Consequence | Fails |
|---|---|---|---|---|
| **One-time (managed) product** — `voidedPurchaseNotification` `productType=ONE_TIME` | offering any one-time / managed product SKU | `handle_voided_notification` appends `unsupported!` → RTDN retry-loop + purchase-token error state | refunded one-time purchase keeps full Pro (over-entitlement) | loud-ish |
| **One-time product purchase** — `OneTimeProduct` notification | offering any one-time / managed product SKU | mapped to `Nil` → silent no-op (the explicit `OneTimeProduct` error branch is dead code) | one-time purchase grants no Pro (paid-but-no-Pro) | silent |
| **Prepaid base plan** — `prepaidPlan` line item (`platform_google_api.py`) | adding a prepaid (non-auto-renewing) base plan to a subscription | `handle_not_implemented('prepaidPlan')` → error propagates → RTDN retry-loop + purchase-token error state | prepaid subscriber's purchase never registers (paid-but-no-Pro); notification loops forever | silent |
| **Subscription pause** — `PAUSED` / `PAUSE_SCHEDULE_CHANGED` notifications | enabling **pause** on any base plan | appends `unsupported!` → `tx.cancel` → RTDN retry-loop + token error state | paused user may stay entitled; notification stuck | silent |
| **Deferred billing / recurrence change** — `DEFERRED` notification | issuing a deferred upgrade/downgrade or recurrence-date extension | same as pause (retry-loop + token error) | deferred renewal mis-timed; notification stuck | silent |
| **Partial / quantity-based refund** — `voidedPurchaseNotification` `refundType=QUANTITY_BASED_PARTIAL_REFUND` | issuing a partial refund (only possible on multi-quantity purchases) | `handle_voided_notification` appends `unsupported!` → RTDN retry-loop + purchase-token error state | partial refund not reflected in entitlement | loud-ish |
| **New / changed base plan** — `pro_plan_from_base_plan_id` | adding any base plan beyond the three known ones* | reported to the ErrorSink; the caller declines to write and the notification is retried | any purchase of the new plan registers no Pro until the plan is supported — recoverable, since the payload is retained and a later deploy applies it | loud-ish |

\* known base plans: `session-pro-{1-month,3-months,12-months}`.

**Handled / intentionally safe (no action needed):**
- **Subscription full refund / revoke** — `voidedPurchaseNotification` `SUBSCRIPTION`+`FULL_REFUND` is an
  intentional **no-op** because subscription revocation is handled by the separate **`SUBSCRIPTION_REVOKED`**
  RTDN. (This is *why* the dispatch typo noted below had no live subscription impact.)
- **Price-change / pending-purchase notifications** — `PRICE_CHANGE_CONFIRMED`/`PRICE_CHANGE_UPDATED`/
  `PENDING_PURCHASE_CANCELED`/`PRICE_STEP_UP_CONSENT_UPDATED` are benign no-ops (no entitlement action).

**Dispatch reaches these branches now, which changes what "dormant" costs:**
- Voided RTDNs were mis-dispatched as `payload_type = Test` rather than `Voided` (a one-word typo), so
  `handle_voided_notification` was unreachable dead code and every void was quietly acked. It is now
  reachable, which means the `ONE_TIME` and partial-refund rows above **fail loudly rather than silently**
  the moment either feature is enabled — the notification is retried and retained instead of acked away.
  That is the intended trade: a wedged notification is recoverable once a handler exists, whereas the
  silent ack it replaced let a refunded purchase keep Pro with nobody told.
- An unknown `SubscriptionNotificationType` — one Google adds later — is likewise reported rather than
  falling through as a silent no-op. If a new *benign* type starts arriving in volume, add it to the no-op
  list above; do not soften the default.

---

## Apple App Store

**Keep OFF until wired:**

| Feature / notification | Enabled in App Store Connect by… | Current behaviour if hit | Consequence | Fails |
|---|---|---|---|---|
| **Promotional offers / offer codes / win-back offers** — `OFFER_REDEEMED` | configuring any offer for the subscription group | `assert isinstance(expiresDate, str)` — but `expiresDate` is an int → **AssertionError** | offer redemption crashes the handler → paid-but-no-Pro | crash (500) |
| **External purchases / alternative marketplaces** — `EXTERNAL_PURCHASE_TOKEN` | enabling the External Purchase entitlement | appends `we do not support 3rd party stores` → 500; Apple retries, then catch-up logs+skips it each pass | 3rd-party-store purchase never handled | loud-ish |
| **Renewal-date extensions** — `RENEWAL_EXTENSION` / `RENEWAL_EXTENDED` | requesting a subscription renewal-date extension (e.g. outage compensation) | appends `we don't handle … extension` → 500; Apple retries, then catch-up logs+skips it each pass | extension never applied | loud-ish |
| **New / changed subscription SKU** — `pro_plan_from_product_id` | adding any product id beyond the three known SKUs* | reported to the ErrorSink; the caller declines to write | any purchase of the new SKU registers no Pro until the SKU is supported | loud-ish |

\* known SKUs: `com.getsession.org.pro_sub_{1_month,3_months,12_months}`.

None of the rows above stops the *other* Apple notifications being recovered. A notification the handler
cannot process is logged at ERROR and skipped by `catchup_on_missed_notifications`, which carries on with
the rest and advances its checkpoint; it is re-read for as long as the history window overlaps it, then
abandoned. So the cost of each row is confined to the feature it names — but nothing alerts on it, which
is what the loud-guard is for.

**Handled / intentionally safe (no action needed):**
- Silent no-ops (entitlement self-expires or nothing to do): `DID_CHANGE_RENEWAL_PREF` (empty subtype),
  `DID_FAIL_TO_RENEW` (grace ended), `REFUND_DECLINED`, `TEST`, `EXPIRED`, `GRACE_PERIOD_EXPIRED`,
  `CONSUMPTION_REQUEST`, `PRICE_INCREASE`. (Caveat: several of these *error* if the notification arrives
  without `tx_info` — `CONSUMPTION_REQUEST` in particular can — which would 500; worth folding into the
  loud-guard.)
- The final `else` (any unrecognised `notificationType`) errors → 500; it catches future Apple
  notification types, and should route through the loud-guard so a new type is surfaced rather than
  merely logged.
- `REFUND_REVERSED` is now **handled** (was a wedge; see bugs-fixed #13): `reinstate_apple_payment`
  un-revokes the reversed transaction, restores the original expiry (never extends), and mints a fresh
  generation iff the current one was revoked and the window is still live. Idempotent; an unknown tx acks
  rather than wedging. A reversal that lands after the paid window has lapsed correctly restores nothing live.
  **Edge:** the `REFUND` path (`add_apple_revocation`) revokes *all* cycles sharing the `original_tx_id`,
  while reinstate un-revokes only the reversed `(original_tx_id, tx_id)`. Correct in the common case (older
  cycles are already expired no-ops); the only under-restore is a still-live *other* cycle that the
  over-broad `REFUND` revoked — a pre-existing consequence of `add_apple_revocation`'s breadth, not of the
  reinstate.

---

## Observability gaps (not branches — silent conditions worth alerting on)
- **Google `EXPIRED`/`ON_HOLD` over-entitlement detector** revokes when a proof would outlive expiry but
  raises **no alert** on that anomalous condition (`# TODO … devs need to be notified somehow`).
- **`appAccountToken` missing** (Apple) falls back to an empty `platform_obfuscated_account_id` rather than
  flagging it — a payment can be registered unattributed to a user.

---

*Source: audit of `platform_google.py`, `platform_google_api.py`, `platform_apple.py` at branch
`phase2-foundation` (2026-07-19). If you add a handler or change a branch, update the corresponding row.*

---

## Part 2 — Accepted design limitations

Deliberate trade-offs, not bugs or dormant handlers. Recorded so they aren't rediscovered as surprises.

### Proof expiry-value metadata channel (privacy; accepted 2026-07-20, narrowed 2026-07-30)

Proofs ride on the user's messages, so a conversation partner or group member — who already knows the
sender — can read the proof's `expiry_ts`. **Short-plan** proofs hug a near-term *pinned* entitlement
expiry, while **long-plan** proofs sit at a *sliding* cap. The two are distinguishable regardless of the
generation/`revocation_tag` fix, so an observer can infer roughly which plan tier a user is on.

**The sharp part of this channel is now closed.** A proof expiry used to sit on the account's exact true
expiry once pinned, publishing (a) the precise purchase/renewal instant, hence a stable per-account
time-of-day fingerprint, and (b) the plan cadence, since a monthly auto-renewal pinned to a non-midnight
instant while a longer plan pinned to midnight. `expiry_ts` is now rounded up onto a **random per-account
grid** (one point every 24 h, re-drawn each billing cycle), so no exact instant, no persistent
time-of-day, and no midnight-vs-not tell survives. That grid also spreads renewal traffic, which a
deterministic expiry — the plan anniversary, or a plain UTC-midnight boundary — would herd into one minute.

**What remains** is the coarse slide-vs-pin shape: an observer still sees the expiry stop stepping and
settle as the subscription end comes into range, so they learn the sender is within ~29 d of their term
end, and can bound the true expiry to within ~25 h. Don't oversell the fix as more than that.

- **Not fixed by coarsening the grid.** A weekly grid doesn't change slide-vs-pin and buys up to 7 days of
  exploitable overhang (free Pro past cancellation for end-of-term users; it also widens the
  revocation-skip margin from 1 day to 7).
- **The only real lever left is the cap length.** A shorter proof-lifetime cap shrinks the window in which
  a short-plan user reveals a pinned date — at the cost of more refresh traffic and worse offline
  resilience. Judged not worth it.
- **The grid offset itself is readable** (`expiry_ts` modulo 24 h) and that's fine: it is a uniform random
  per-cycle value that leaves the true expiry bounded to the same ~24 h window either way, and it is less
  identifying than the per-generation `revocation_tag` already in the proof. **Minting a generation always
  re-draws the offset**, so it adds no cross-roll linkage — this is load-bearing rather than incidental, and
  it is forced at the mint site precisely because the re-draw is otherwise extension-only (a revocation is a
  *shrink*, which keeps the offset so that reducing an entitlement cannot serve a later expiry than before).
  Where the generation persists, the unchanged tag already links those proofs, so a held offset adds nothing.
- **A served-expiry step-down is an unambiguous shrink signal.** With the offset held across a shrink, the
  grid is fixed, so a conversation partner who sees `expiry_ts` move earlier learns the entitlement was
  reduced, where a re-draw would have blurred the direction. The same fixed grid also means a shrink landing
  inside one grid cell is invisible where a re-draw would have signalled *something* changed. Both are
  accepted: shrinks are rare (refunds, early-out revocations), and the alternative reintroduces the
  monotonicity break above.
- **Decision: accept the residual slide-vs-pin shape as a known limitation.**

Note the *distinct* subscription-**cadence** leak (an observer watching how often the `revocation_tag`
changes to infer renewal frequency) **was** closed — items 1+3 make the tag stable for the whole
subscription lifetime, and that is covered by a test. **Binding-revocation observability** (the tag necessarily
changes on a revocation) is likewise intrinsic and accepted.

*(Ref: wire spec §2.3.)*

### Google RTDN ordering (accepted; the safety property is load-bearing)

Google does not set Pub/Sub ordering keys on RTDNs, so notifications for one purchase token arrive out of
order, both within a single pull and on a replay. The subscriber sorts a batch by `eventTimeMillis`, which
orders only *within* that batch; across batches, ordering is handled by the handler failing and the message
being retried with a back-off until whatever it depended on has landed. There is no reorder buffer.

**What makes that safe is an invariant, not the sort:** every mutating branch in
`handle_subscription_notification` gates on the `subscription_state` from a *freshly fetched* subscription
resource, so a notification whose type no longer matches the store's current state does nothing rather than
applying a stale change. The notification is a hint; the resource is the truth (as `google.md` says).

**Wiring any dormant branch above without that guard breaks it.** A handler that acts on the notification
type alone will apply stale changes out of order. The same applies to a handler that needs a payment row to
already exist: it will fail and retry until the row appears, which is correct but costs a `user_error` and
error-level logs in the meantime.

### Credits are not clawed back on refund (accepted)

A one-shot payment (a voucher; anything minted) is consumed only while nothing else covers the account. When
a subscription is refunded, the time the account already spent under it is **not** charged back to a credit
it holds. So a year-long voucher held through two months of a subscription that is then refunded still owes
a full year, and those two months were free.

Accepted deliberately: a refund is the store deciding to return money for service already delivered, and
charging the voucher for it would manufacture entitlement out of a refund. It also makes the outcome
independent of whether the voucher was granted just before or just after the refund landed, which a clawback
could not be. Both facts are asserted by tests, so a later decision to claw back will show up as failures
rather than as a silent change.

The exposure scales with how long the refunded subscription was consumed, and the half we control is
developer-initiated refunds: issuing those routinely on voucher-holding accounts is what would make this
matter.

### `revoked_at` means "entitlement stopped here" (invariant, not a limitation)

`payments.revoked_at` carries the *store's* refund instant, and the entitlement it granted up to that
instant stands — the user really was subscribed until then. It must never be repurposed to mean "this
payment never existed": the credit accounting above depends on it, and back-dating it to a purchase instant
would retroactively turn a consumed term into uncovered time, silently charging any credit that was alive
during it. Whether the same voucher was worth two months or eleven would then depend on when in the term it
was granted.

(`generations.revoked_at` is a different thing: our own clock, stamped at the write site, because the served
list turns it into `effective_ts`.)

### Credit drain: coverage is sampled, not reconstructed (accepted)

A drain pass asks only whether a subscription covers the account *right now*, then charges the whole span
since that account's checkpoint. The charge is exact however late the pass runs, but at a genuine coverage
transition it is off by up to the gap between passes: a lapse is charged for the whole span it falls in, a
start for none of it. Renewals are not transitions (expiry moves before the old term lapses), so in practice
this is a couple of events per subscription lifetime. Both directions are pinned by tests.

After an outage the error is bounded by the outage rather than by the interval, and in the "lapse" direction
it is against the user: a backlog drained after days of downtime can charge a voucher for days it was in
fact covered. There is no code fix planned — after any incident that drains a large notification backlog,
re-grant the affected voucher days by hand.

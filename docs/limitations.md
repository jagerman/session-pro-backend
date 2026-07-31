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
safeguard; the **reactive** half is a planned loud-guard (Phase 4 — see `docs/refactor-plan.md`): a shared
`unsupported_feature(name, …)` helper that logs CRITICAL (→ ops alert) and safely skips (never raises /
wedges) when one of these branches is hit. Neither substitutes for actually implementing the handler
before the feature is enabled.

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
| **One-time (managed) product** — `voidedPurchaseNotification` `productType=ONE_TIME` | offering any one-time / managed product SKU | `handle_voided_notification` appends `unsupported!` (and today is unreachable — see the `.Test` bug below — so it's a silent no-op) | refunded one-time purchase keeps full Pro (over-entitlement) | silent |
| **One-time product purchase** — `OneTimeProduct` notification | offering any one-time / managed product SKU | mapped to `Nil` → silent no-op (the explicit `OneTimeProduct` error branch is dead code) | one-time purchase grants no Pro (paid-but-no-Pro) | silent |
| **Prepaid base plan** — `prepaidPlan` line item (`platform_google_api.py`) | adding a prepaid (non-auto-renewing) base plan to a subscription | `handle_not_implemented('prepaidPlan')` → error propagates → RTDN retry-loop + purchase-token error state | prepaid subscriber's purchase never registers (paid-but-no-Pro); notification loops forever | silent |
| **Subscription pause** — `PAUSED` / `PAUSE_SCHEDULE_CHANGED` notifications | enabling **pause** on any base plan | appends `unsupported!` → `tx.cancel` → RTDN retry-loop + token error state | paused user may stay entitled; notification stuck | silent |
| **Deferred billing / recurrence change** — `DEFERRED` notification | issuing a deferred upgrade/downgrade or recurrence-date extension | same as pause (retry-loop + token error) | deferred renewal mis-timed; notification stuck | silent |
| **Partial / quantity-based refund** — `voidedPurchaseNotification` `refundType=QUANTITY_BASED_PARTIAL_REFUND` | issuing a partial refund (only possible on multi-quantity purchases) | `handle_voided_notification` appends `unsupported!` (unreachable today via the `.Test` bug → silent no-op) | partial refund not reflected in entitlement | silent |

**Handled / intentionally safe (no action needed):**
- **Subscription full refund / revoke** — `voidedPurchaseNotification` `SUBSCRIPTION`+`FULL_REFUND` is an
  intentional **no-op** because subscription revocation is handled by the separate **`SUBSCRIPTION_REVOKED`**
  RTDN. (This is *why* the `.Test` dispatch bug below has no live subscription impact today.)
- **Price-change / pending-purchase notifications** — `PRICE_CHANGE_CONFIRMED`/`PRICE_CHANGE_UPDATED`/
  `PENDING_PURCHASE_CANCELED`/`PRICE_STEP_UP_CONSENT_UPDATED` are benign no-ops (no entitlement action).

**Bug (not merely dormant), coupled to the above:**
- **Voided RTDNs are mis-dispatched.** `parse_notification` tags every `voidedPurchaseNotification` as
  `payload_type = Test` instead of `Voided` (a one-word typo), so `handle_voided_notification` is
  **unreachable dead code**. Live impact today is nil (subscription refunds go via `SUBSCRIPTION_REVOKED`;
  one-time/partial are dormant per above), but it must be fixed **together** with wiring the `ONE_TIME`/
  partial handlers — otherwise any handler/loud-guard placed there never runs. Tracked in the bug ledger +
  Phase 4.
- **No `case _:` default** in `handle_subscription_notification`'s `match` — a *future* Google
  `SubscriptionNotificationType` would fall through as a silent no-op. Add a default that hits the loud-guard.

---

## Apple App Store

**Keep OFF until wired:**

| Feature / notification | Enabled in App Store Connect by… | Current behaviour if hit | Consequence | Fails |
|---|---|---|---|---|
| **Promotional offers / offer codes / win-back offers** — `OFFER_REDEEMED` | configuring any offer for the subscription group | `assert isinstance(expiresDate, str)` — but `expiresDate` is an int → **AssertionError** | offer redemption crashes the handler → paid-but-no-Pro | crash (500) |
| **External purchases / alternative marketplaces** — `EXTERNAL_PURCHASE_TOKEN` | enabling the External Purchase entitlement | appends `we do not support 3rd party stores` → 500; Apple retries, then catch-up logs+skips it each pass | 3rd-party-store purchase never handled | loud-ish |
| **Renewal-date extensions** — `RENEWAL_EXTENSION` / `RENEWAL_EXTENDED` | requesting a subscription renewal-date extension (e.g. outage compensation) | appends `we don't handle … extension` → 500; Apple retries, then catch-up logs+skips it each pass | extension never applied | loud-ish |
| **New / changed subscription SKU** — `pro_plan_from_product_id` | adding any product id beyond the three known SKUs* | `assert False, 'Invalid apple plan_id'` → crash | any purchase of the new SKU crashes the handler (paid-but-no-Pro) | crash (500) |

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
  identifying than the per-generation `revocation_tag` already in the proof. Because a revocation moves the
  true expiry, the offset re-draws in the same moment the tag rolls, so it adds no cross-roll linkage.
- **Decision: accept the residual slide-vs-pin shape as a known limitation.**

Note the *distinct* subscription-**cadence** leak (an observer watching how often the `revocation_tag`
changes to infer renewal frequency) **was** closed — items 1+3 make the tag stable for the whole
subscription lifetime, and that is covered by a test. **Binding-revocation observability** (the tag necessarily
changes on a revocation) is likewise intrinsic and accepted.

*(Ref: wire spec §2.3.)*

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
  provider retries) vs *crash* (raises). **None of them alerts anyone today** — the loud-guard described at
  the top of this file is the planned remedy and is not built.

---

## Google Play

**Keep OFF until wired:**

| Feature / notification | Enabled in Play Console by… | Current behaviour if hit | Consequence | Fails |
|---|---|---|---|---|
| **One-time (managed) product** — `voidedPurchaseNotification` `productType=ONE_TIME` | offering any one-time / managed product SKU | `handle_voided_notification` appends `unsupported!` → `tx.cancel` → RTDN retry-loop | refunded one-time purchase keeps full Pro (over-entitlement) | loud-ish |
| **One-time product purchase** — `OneTimeProduct` notification | offering any one-time / managed product SKU | mapped to `Nil` → silent no-op (the explicit `OneTimeProduct` error branch is dead code) | one-time purchase grants no Pro (paid-but-no-Pro) | silent |
| **Prepaid base plan** — `prepaidPlan` line item (`providers/google_play/api.py`) | adding a prepaid (non-auto-renewing) base plan to a subscription | `handle_not_implemented('prepaidPlan')` fires in the drain's resource parse → the token stays in `google_reconcile_queue` and retries with a backoff | prepaid subscriber's purchase never registers (paid-but-no-Pro); the token retries indefinitely, with the reason in its `last_error` | silent |
| **Partial / quantity-based refund** — `voidedPurchaseNotification` `refundType=QUANTITY_BASED_PARTIAL_REFUND` | issuing a partial refund (only possible on multi-quantity purchases) | `handle_voided_notification` appends `unsupported!` → `tx.cancel` → RTDN retry-loop | partial refund not reflected in entitlement | loud-ish |
| **New / changed base plan** — `pro_plan_from_base_plan_id` | adding any base plan beyond the three known ones* | reported to the ErrorSink; the caller declines to write and the notification is retried | any purchase of the new plan registers no Pro until the plan is supported — recoverable, since the payload is retained and a later deploy applies it | loud-ish |

\* known base plans: `session-pro-{1-month,3-months,12-months}`.

**No longer dormant — `PAUSED`, `PAUSE_SCHEDULE_CHANGED` and `DEFERRED`.** These were rows in the table
above, on the grounds that the notification dispatch had no arm for them and so appended `unsupported!`,
cancelled the transaction and left the RTDN redelivering forever. That dispatch no longer exists: handling
does not consult the notification type at all, so each of these records the purchase token, fetches the
subscription resource and writes what it says.

Play documents a pause as taking effect *only after the current billing period ends* — so a scheduled pause
takes nothing away, the term the user paid for runs out normally, and resume (`SUBSCRIPTION_RECOVERED`,
which is also the account-hold recovery type) renews into a fresh cycle. A deferral states a later expiry on
the cycle it names, which convergence takes. Covered by
`test_google_paused_and_deferred_notifications_converge_instead_of_wedging`, which follows that documented
sequence.

One thing Play does NOT document is what `expiryTime` holds while a subscription is paused; it says only
that `PausedStateContext` carries the expected resume time. Nothing here depends on knowing: coverage is
whatever the resource states, so the handling is right either way. It does mean an operator debugging a
paused subscriber should read the resource rather than trust a rule of thumb about it.

Enabling pause or issuing deferrals is therefore no longer gated on a code change. The remaining rows
above are still dormant and still worth keeping off.

**Resubscription from the Play subscriptions center attributes through the EXPIRED subscription.**

A lapsed subscriber pressing "Resubscribe" in Play makes a purchase our app never sees, so nothing calls
`setObfuscatedAccountId` and the new purchase carries no account id of its own — Play documents the field as
present only "if account linking happened as part of the subscription purchase flow" or if it "was specified
using `setObfuscatedAccountId` when the purchase was made". Play's substitute is `outOfAppPurchaseContext`,
which carries the *expired* subscription's identifiers and is "present exclusively for unacknowledged
resubscription purchases". The backend reads it, preferring in order: the purchase's own account id, the
expired subscription's, then our own record of who owned the expired purchase token.

Two consequences worth knowing:

- **Attribution must precede acknowledgement**, because the context vanishes once the purchase is acked.
  The order is register (flagging `needs_ack`) and then let the ack sweep run. Anything that acknowledged
  first would destroy the only evidence of ownership permanently.
- **A user who lost their Session identity between subscriptions is attributed to the keys they no longer
  hold.** The payment then waits, unredeemed, for a master pkey that may not exist. This is the narrow
  intersection of two uncommon events and it is what Play prescribes, so it is accepted rather than worked
  around; a support-minted voucher is the remedy. Worth recognising rather than debugging from scratch.

If attribution fails entirely the purchase is deliberately left unregistered, which means it is never
acknowledged, which means Google auto-refunds it after three days. That is the better failure: the user is
made whole automatically, where acknowledging an unattributable purchase would strand paid money in a row no
account could ever claim.

**Store-config invariant — never set a base plan's grace period to 0 days.**

Play does not honour a zero grace. It substitutes a 24-hour **silent grace period** during which the
subscription still reads `SUBSCRIPTION_STATE_ACTIVE` and **no RTDN is sent at all**:

> "You can set a grace period of 0 days, but Play will wait a minimum of 1 day to ensure sufficient time
> for payment retries. This silent grace period offers a safety net for payment processing. During this
> 24-hour period the subscription remains in the `ACTIVE` state."
> — https://developer.android.com/google/play/billing/lifecycle/subscriptions

Every other grace setting reaches us as an extended `expiryTime` on the subscription resource, which is
where we read grace from. A zero setting is the one value that produces a documented silence instead, so a
subscriber whose renewal fails would lapse a day early with nothing in any log to say why. This costs
entitlement rather than latency, and it is one toggle away in the Play Console. All current plans are set
to 1 day.

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
- A `SubscriptionNotificationType` Google adds later is reported rather than falling through as a silent
  no-op, and — because parsing maps an unrecognised value to `UNKNOWN` instead of rejecting it — the
  message is *stored* first, so a deploy that adds the type applies the backlog. If a new *benign* type
  starts arriving in volume, add it to the no-op list above; do not soften the default.

**A note on what "retry-loop" now means, and on `user_error`.** Nothing above retries an RTDN any more:
the notification is acked as soon as its token is queued, and the failure happens later in the drain, which
retries the TOKEN with a backoff and records `attempts` and `last_error` on its `google_reconcile_queue`
row. That row is the durable record of a stuck purchase, and it is where an operator should look.

Consequently **no Google `user_error` can ever persist**: every remaining failure path in
`_process_notification_message` sets `tx.cancel`, which rolls back the row written in the same transaction.
So `get_pro_status`'s `error_report` is permanently 0 for Google accounts while Apple still populates it —
a wire field that silently stopped meaning anything for one provider. It was never actionable by a user
in any case: one undocumented bit, no reason, no remedy. Pending a decision to repoint it at the drain's
`attempts` or to retire it, treat Google's `error_report` as dead and the queue row as the truth.

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
- **A stuck reconcile token is silent.** `google_reconcile_queue.attempts` and `last_error` record a token
  the drain cannot finish, and nothing alerts on it — a purchase can fail attribution or plan mapping
  indefinitely with the evidence sitting in a table nobody reads. This replaces the old
  `EXPIRED`/`ON_HOLD` over-entitlement detector, which was a branch of the deleted dispatch; the
  over-entitlement question it asked is now answered by convergence plus
  `refresh_entitlement_and_revoke_overreaching_proofs`.
- **`appAccountToken` missing** (Apple) falls back to an empty `platform_obfuscated_account_id` rather than
  flagging it — a payment can be registered unattributed to a user.

---

*Source: audit of the provider paths at branch `phase2-foundation` (2026-07-19), revised on branch
`simplify-google-processing` (2026-08-03) after the Google notification path became convergent — the files
audited then (`platform_google.py`, `platform_google_api.py`, `platform_apple.py`) are now
`providers/google_play/` and `providers/app_store.py`. If you add a handler or change a branch, update the
corresponding row.*

---

## Part 2 — Accepted design limitations

Deliberate trade-offs, not bugs or dormant handlers. Recorded so they aren't rediscovered as surprises.

### Changing Session identity loses a store subscription — KNOWN GAP, NOT ACCEPTED (raised 2026-08-03)

The one entry here that is **not** a trade-off. It is a real user-visible defect with no code remedy today,
recorded so it is a known TODO rather than a support mystery.

A user who deletes and recreates their Session account keeps paying their store subscription and silently
loses Pro. There is no way for them to recover it, and no way for us to move it.

Why it is structural rather than a bug in one path:

- Both stores bind a subscription to an account identifier at PURCHASE time and never revise it. Google's
  `obfuscatedAccountId` is set by `setObfuscatedAccountId` when the billing flow is launched — Play
  documents the field as present because it "was specified using `setObfuscatedAccountId` when the purchase
  was made" — and Apple's `appAccountToken` is `uuid_from_master_pk(pubkey)`. A renewal does not re-run the
  purchase flow, so the resource reports the ORIGINAL key for the life of the subscription.
- Claiming is key equality with no override: `reconcile_pending_payments` treats holding the master key as
  the claim itself, because the store attests the identifier as a function of that key. A new identity
  presents a key that matches nothing.
- Nothing rewrites the stored account id. `google_converge_payment` refuses deliberately — it "adjusts the
  terms of a payment, never who holds it" — which is the right rule for convergence and the reason this
  cannot be fixed by accident.

So every renewal registers a payment attributed to a key the user no longer controls, and their new account
sees nothing.

**What support can do today:** `cli.py voucher` grants a *parallel* complimentary payment to the new master
pkey. It restores the user's Pro but does not move the store payment or stop the charging, so the account is
covered twice while the old subscription runs on. The alternative is cancel-and-repurchase, forfeiting the
remainder of the paid term.

**Candidate fixes, in increasing cost:**

1. An admin re-attribution command: point an existing payment's account id at a new master pkey and re-run
   the claim. Small, support-operable, no wire or client change — it makes the existing manual remedy exact
   instead of approximate.
2. A client-driven re-association route. The client on the new identity can enumerate its own store
   purchases and submit the purchase token; the backend verifies it against the store and re-attributes.
   This is the real fix. Possession is reasonable evidence — only a device signed into that store account
   can enumerate it — but it is a new authenticated route plus client work on both platforms, and it needs
   designing so a token cannot be used to capture someone else's subscription.

Note the narrower form of this already exists inside the resubscription fallback above: a user who rotated
identities between subscriptions is attributed to the keys they no longer hold. Same root cause.

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

### Google RTDN ordering (not a limitation any more; kept because the reasoning matters)

Google does not set Pub/Sub ordering keys on RTDNs, so notifications for one purchase token arrive out of
order, both within a single delivery and on a replay. **Nothing depends on their order**, because handling
never reads the notification type: a notification records that its token owes a look, and a later drain
fetches the resource and writes what it currently says. Two notifications collapse to one fetch, and a
replay converges onto the same values.

This entry used to describe the opposite arrangement — a per-batch sort by `eventTimeMillis`, a per-message
retry backoff, and a state-guard in every mutating branch of a type dispatch — and it warned that wiring any
dormant branch without that guard would break ordering safety. None of that exists. The sort ordered only
within one batch and so bought nothing across batches; the guard was needed only because the dispatch read
the notification type in the first place.

**The reason it is kept:** the failure it warned about is still available to anyone who reintroduces
per-type handling. `docs/google.md` §2 states the rule and `CLAUDE.md` repeats it. `REVOKED` is the sole
branch that reads a type, because a refund is the one fact the resource cannot express.

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

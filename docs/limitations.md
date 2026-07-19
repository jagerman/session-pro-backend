# Session Pro Backend — payment-provider limitations & store-config invariants

**Read this before enabling ANY new feature in Google Play Console or App Store Connect.**

The backend does not (yet) handle every payment-provider notification, subscription state, or product
type. Each unhandled path is **dormant and safe *only* because the corresponding store-side feature is
currently turned off**. Flip that switch without first wiring the handler and you get a silent
correctness/entitlement hole — an over-entitled user (kept Pro after a refund) or a paid-but-no-Pro user
(payment never registered) — often failing *un-loudly* (an RTDN that retries forever, or an HTTP 500 that
wedges Apple catch-up).

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
| **Refund reversal** — `REFUND_REVERSED` | a refund being reversed (dispute resolved in your favour — rare) | always appends a TODO error → HTTP 500 + Apple retries, **and wedges the catch-up checkpoint** | customer whose refund was reversed is **not** re-granted Pro; all missed-notification catch-up stalls | loud-ish + wedge |
| **External purchases / alternative marketplaces** — `EXTERNAL_PURCHASE_TOKEN` | enabling the External Purchase entitlement | appends `we do not support 3rd party stores` → 500 + retries + catch-up wedge | 3rd-party-store purchase not handled | loud-ish + wedge |
| **Renewal-date extensions** — `RENEWAL_EXTENSION` / `RENEWAL_EXTENDED` | requesting a subscription renewal-date extension (e.g. outage compensation) | appends `we don't handle … extension` → 500 + retries + catch-up wedge | extension not applied; catch-up stalls | loud-ish + wedge |
| **New / changed subscription SKU** — `pro_plan_from_product_id` | adding any product id beyond the three known SKUs* | `assert False, 'Invalid apple plan_id'` → crash | any purchase of the new SKU crashes the handler (paid-but-no-Pro) | crash (500) |

\* known SKUs: `com.getsession.org.pro_sub_{1_month,3_months,12_months}`.

**Handled / intentionally safe (no action needed):**
- Silent no-ops (entitlement self-expires or nothing to do): `DID_CHANGE_RENEWAL_PREF` (empty subtype),
  `DID_FAIL_TO_RENEW` (grace ended), `REFUND_DECLINED`, `TEST`, `EXPIRED`, `GRACE_PERIOD_EXPIRED`,
  `CONSUMPTION_REQUEST`, `PRICE_INCREASE`. (Caveat: several of these *error* if the notification arrives
  without `tx_info` — `CONSUMPTION_REQUEST` in particular can — which would 500/wedge; worth folding into
  the loud-guard.)
- The final `else` (any unrecognised `notificationType`) errors → 500 + wedge; it catches future Apple
  notification types, and should route through the loud-guard so a new type doesn't wedge catch-up.

---

## Observability gaps (not branches — silent conditions worth alerting on)
- **Google `EXPIRED`/`ON_HOLD` over-entitlement detector** revokes when a proof would outlive expiry but
  raises **no alert** on that anomalous condition (`# TODO … devs need to be notified somehow`).
- **`appAccountToken` missing** (Apple) falls back to an empty `platform_obfuscated_account_id` rather than
  flagging it — a payment can be registered unattributed to a user.

---

*Source: audit of `platform_google.py`, `platform_google_api.py`, `platform_apple.py` at branch
`phase2-foundation` (2026-07-19). If you add a handler or change a branch, update the corresponding row.*

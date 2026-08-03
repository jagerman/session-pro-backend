# Google Play subscriptions in this backend

How a Play purchase becomes Session Pro, and what the backend does with every notification Google sends
about it. Written against the code; where a store behaviour is asserted, the Play documentation is cited so
the claim can be rechecked rather than trusted.

The short version: **a notification is a cache-invalidation ping, not an event to apply.** It says only
"something about this purchase token changed". The backend records that the token owes a look, and a
separate pass fetches the subscription resource and writes whatever it currently says. Nothing reads the
notification type.

## 1. How a notification reaches us

Google Play does not deliver to our server. It publishes to a Google Cloud Pub/Sub topic, and the backend
holds a streaming subscription to that topic's queue — `[google] cloud_project_id` and
`cloud_subscription_name` in the ini name it. The subscriber runs in the maintenance mule, post-fork,
because gRPC's background threads do not survive a fork (`notifications.init` has the detail).

Some of the delivery behaviour lives in the *queue's* configuration rather than in this repo — retry
backoff, expiry, exactly-once. `docs/deploy.md` lists what must be set and why.

## 2. What a notification contains, and what we do with it

A subscription notification carries `packageName`, `eventTimeMillis`, and inside `subscriptionNotification`:
a version, a `notificationType`, and a `purchaseToken`. **There is no event id**, and
`purchases.subscriptionsv2.get` accepts a token and nothing else — no revision, no as-of parameter. So the
only identifier names the *subscription*, and there is no way to ask what a subscription looked like at some
past event.

That shape is why handling is convergent. On arrival the backend:

1. Records the message id and payload in `google_notification_history` — **before** handling, because the
   handler treats a missing history row as "already handled" and acks.
2. Upserts the purchase token into `google_reconcile_queue`. This is the only durable step, and the only one
   whose failure loses anything: a first sighting of a token cannot be recovered from anywhere else, since
   no Play endpoint enumerates subscribers and no client route submits a token.
3. Acks the message.

`REVOKED` is the single exception that reads the type, because a refund is the one fact the resource cannot
express — Google reports a refunded subscription as `SUBSCRIPTION_STATE_EXPIRED` with a back-dated term,
indistinguishable from one that simply ran out.

An unrecognised `notificationType` is mapped to `UNKNOWN` rather than rejected, and then handled like any
other: the token is queued and the resource converged. Rejecting at parse would discard the message before
it was written down, so it would redeliver until Pub/Sub's retention lapsed and then be gone.

## 3. The reconcile queue and the drain

`google_reconcile_queue` is keyed by `payment_token`, so ten notifications about one subscription are one
piece of work — whatever the tenth would have told us is already in the snapshot the first fetch returns.

Its columns answer different questions and must not be conflated:

- `eligible_at` is a **floor**, not a deadline: nothing is owed by it, and a fresh notification pulls it
  *earlier* while a failure pushes it later with a backoff.
- `leased_until` is a genuine **deadline** held by a worker. Kept separate so a notification arriving
  mid-fetch cannot hand the token to a second runner while the first still holds it.
- `revision` is bumped on every enqueue, so a worker can tell whether the obligation it claimed is still the
  one in front of it. A notification that arrives during a fetch describes a state that fetch cannot have
  seen, so finishing it must not clear the queue entry.

The drain claims a batch (`FOR UPDATE SKIP LOCKED`), fetches each resource **outside** any transaction, and
converges each in its own transaction — one bad token cannot cost the others. It runs from two places: the
subscriber wakes it after a burst of messages, for latency, and the mule runs it periodically as a backstop
for tokens enqueued while the subscriber was down. The backstop is not optional, and not because of proof
latency: `needs_ack` is only written when the drain registers a payment, and **Google auto-refunds a
purchase left unacknowledged for three days.**

## 4. What converging writes

From the fetched resource:

- **`expiry_at`** — the line item's `expiryTime`, taken as stated. This is revisable, which is what lets a
  term the store has shortened, extended or deferred actually reach the database.
- **`auto_renewing`** — `autoRenewingPlan.autoRenewEnabled`, read from the resource rather than inferred
  from why we were woken.
- **`grace_period`** — always NULL for Google. Play applies grace by *extending* `expiryTime`, so a Google
  row's grace is already inside its expiry; writing it beside the expiry as well counted it twice. The
  column is written (not skipped) so a row stamped by the retired per-type dispatch self-heals.
- **`needs_ack`** — whether the store still reports the purchase as unacknowledged.

Two things convergence will not overrule: a **revoked** row is terminal and left entirely alone, and a
**claimed** row's ownership — it adjusts the terms of a payment, never who holds it.

The line item is *chosen*, not assumed: Google sends a second item during a deferred change, documented as
having no `latestSuccessfulOrderId` because the user does not own it yet. Ownership is the filter, furthest
expiry the tie-break.

Idempotency is load-bearing rather than an optimisation. Re-converging an unchanged snapshot must leave
`users.expiry_at` untouched, because a move there re-draws the account's proof-expiry offset — and a pass
that "changed" nothing on every run would hand an observer repeated samples against one true expiry, which
is the attack the offset exists to prevent.

## 5. A payment row is a billing cycle

Rows are keyed `(payment_token, order_id)`. A renewal is a new order id on the same token, so it is a new
row; the entitlement fold takes the newest row **per token**, which is what identifies the subscription.
Grouping by anything derived from the order id's shape is wrong — Google's per-cycle suffixes (`GPA.x`,
`GPA.x..0`) are an internal format, and a subscription whose base changes mid-life would split into two
competing subscriptions.

## 6. Attribution: whose purchase is it

Google attests the account as a function of the master key: `obfuscatedAccountId` is the master pubkey
verbatim, set by the client calling `setObfuscatedAccountId` when the billing flow is launched. So holding
the key *is* the claim, and there is no separate token to match.

Three fallbacks, in order, because one documented flow carries no account id at all:

1. The purchase's own `externalAccountIdentifiers.obfuscatedExternalAccountId`.
2. `outOfAppPurchaseContext.expiredExternalAccountIdentifiers.obfuscatedAccountId` — the *expired*
   subscription's id. A resubscribe from the Play subscriptions center is a purchase our app never sees, so
   nothing called `setObfuscatedAccountId`; Play documents the field as present only when it "was specified
   using `setObfuscatedAccountId` when the purchase was made".
3. Our own record of who owned `outOfAppPurchaseContext.expiredPurchaseToken`, which reaches even an expired
   subscription that never carried an account id, because redemption bound that row to its owner regardless.

These identifiers are **transient** — present only while the purchase is unacknowledged — so attribution
must precede acknowledgement. That is the order the code uses; reversing it would destroy the only evidence
of ownership permanently.

If all three fail the purchase is deliberately left unregistered, and therefore never acknowledged, and
therefore auto-refunded by Google at three days. That is the better failure: the user is made whole
automatically, where acknowledging an unattributable purchase would strand paid money in a row no account
could ever claim.

## 7. Lifecycle states, and why none of them need special handling

Each documented state defines what `expiryTime` means, and convergence writes it down — so the states
mostly need no code of their own. From
https://developer.android.com/google/play/billing/lifecycle/subscriptions:

| state | what Play says | what we do |
|---|---|---|
| `ACTIVE` | `expiryTime` in the future | converge it |
| `IN_GRACE_PERIOD` | Play "dynamically extends the `expiryTime`" | converge it; the extension arrives inside the expiry |
| `ON_HOLD` | `expiryTime` "set to a past timestamp", block access | converge it; coverage has already passed |
| `CANCELED` | `expiryTime` is "when the user should lose access" | converge it |
| `PAUSED` | user loses access; `autoRenewEnabled` stays **true** | converge it |
| `EXPIRED` | user loses access | converge it |

**Pause** is the clearest illustration. A pause "takes effect only after the current billing period ends",
so nothing is back-dated: the paid term runs out normally, and resume arrives as `SUBSCRIPTION_RECOVERED` —
the same notification type as recovering from account hold, which is one more reason type dispatch was the
wrong shape. Play does not document what `expiryTime` holds *during* a pause, and nothing here needs to
know.

**Upgrades, downgrades and in-app resubscribes** invalidate the old purchase and create a new one with a new
token, and the new resource carries `linkedPurchaseToken` naming the old. The backend enqueues that old
token rather than acting on it: its own resource is the authority on what became of it, exactly as this one
is.

**Account hold** lasts `60 days − grace period`, so the window in which a recovery can still arrive — term
plus grace plus hold — is exactly 60 days whatever the grace is set to. That is why the auto-redeem deadline
adds a flat 60 days and subtracts nothing.

## 8. Refunds

The void feed (`voidedPurchaseNotification`) and `SUBSCRIPTION_REVOKED` both mean money came back.
`payments.revoked_at` records the store's refund instant, and the entitlement granted up to that instant
**stands** — the user really was subscribed until then. Coverage is clamped to `min(expiry, revoked_at)`, a
clamp and never an assignment: a payment refunded after it had already lapsed keeps its own expiry, because
assigning would hand the account coverage across a gap it never had.

Whether outstanding proofs are revoked is a separate question, decided by
`refresh_entitlement_and_revoke_overreaching_proofs` from the recomputed account rather than from the
notification: does what survives still cover the proofs we have already signed?

## 9. What is not supported

`docs/limitations.md` is the authority. In summary: one-time and prepaid products, partial refunds, and base
plans beyond the three we sell. Also there: never configure a Google grace period of 0 days, because Play
substitutes a silent 24-hour one with no notification at all.

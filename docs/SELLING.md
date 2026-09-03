# Selling and fulfillment runbook

How a purchase becomes an activated Pro license, how to test that flow end to end
before going live, and how to keep the books. Afterlife licenses are minted
locally with your offline signing key (`scripts/issue_license.py`); the storefront
(Polar) only takes the money and hands the buyer the token you mint. Nothing
phones home.

## The loop, in one line

Buyer checks out on Polar, you get an order notification, you run
`issue_license.py` with their organization name, you email them the token, they
set `AFTERLIFE_LICENSE` and are on Pro.

## Part 1: create the TEST100 discount (100% off, for dry runs)

A 100%-off code lets you complete a real checkout at $0 and exercise the whole
flow without paying. Create it in Polar:

1. Dashboard → **Discounts** → **New discount** (or **Create discount**).
2. **Type:** Percentage, **100%**.
3. **Code:** `TEST100`.
4. **Applies to:** Afterlife Pro (or all products).
5. **Duration** (subscriptions): **once** is enough to reach $0 at checkout for a
   dry run.
6. **Max redemptions:** set a low cap (for example **5**) so a stray visitor
   cannot use it. You will delete or disable it before going live anyway.
7. Save.

## Part 2: dry-run checklist (prove buy to activation)

**Prerequisite:** your Polar organization must be **activated to accept payments**
first (identity verification + payout connected; see Part 6). Polar blocks every
checkout until then, including a $0 TEST100 one, with "Organization is not ready
to accept payments." Once activated, TEST100 makes this a real $0 checkout so you
exercise the whole flow without spending money. (To rehearse before activation,
use Polar's separate sandbox at sandbox.polar.sh, which needs no KYC.)

Run this once, start to finish. Check each box.

- [ ] **Checkout at $0.** Open your checkout link
      (`https://buy.polar.sh/polar_cl_qvXw4txhqGaPXKuepbXsgfjVnlbpzp0Wbxnm730BFMK`),
      apply `TEST100`, confirm the total is **$0.00**, enter a test
      **Organization name** in the custom field, use your own email, and
      complete the checkout.
- [ ] **Order landed.** Confirm the order shows in Polar under **Sales**
      (or **Orders**) and that you received the order-notification email.
- [ ] **Read the org name.** Open the order and note the buyer's
      **Organization name** (the custom field) and email. This is what you mint
      the license to.
- [ ] **Mint the license.** In the repo:
      ```bash
      python scripts/issue_license.py "Their Org Name" --days 365
      ```
      The **token** prints on stdout; the **jti** and customer print on stderr
      (`issued jti=... customer='Their Org Name' validity=365d`). Record the jti.
- [ ] **Log it** in `customers.csv` (see Part 4).
- [ ] **Deliver the token.** Email it to the buyer, or paste it into the Polar
      order's delivery message. Include the two activation lines from Part 3.
- [ ] **Activate as the customer.** In a clean shell:
      ```bash
      export AFTERLIFE_LICENSE=<the token>
      afterlife license
      ```
      Confirm it prints **Edition: Pro**, **Licensed to: Their Org Name**, and an
      expiry ~365 days out.
- [ ] **Confirm a Pro feature unlocks.** With that token still set:
      ```bash
      afterlife evidence -o /tmp/test-evidence.json
      afterlife verify-evidence /tmp/test-evidence.json
      ```
      The first should write a pack (not refuse); the second should print
      **Signature VALID**. Then `unset AFTERLIFE_LICENSE` and rerun
      `afterlife evidence`; it should now **refuse** (proves the gate works).
- [ ] **Clean up the test.** In Polar, cancel the test subscription and (if you
      like) refund/void the $0 order so it does not pollute your metrics.

If every box is checked, the storefront is proven end to end.

## Part 3: the per-order fulfillment loop (real orders)

Same as the dry run, minus TEST100. For each paid order:

1. Read the buyer's Organization name and email from the Polar order.
2. Mint: `python scripts/issue_license.py "Their Org" --days 365`.
3. Log the jti in `customers.csv`.
4. Email the token with these activation instructions:

   > Your Afterlife Pro license is attached below. To activate, set it as an
   > environment variable (or write it to a file):
   >
   > `export AFTERLIFE_LICENSE=<token>`  (or `AFTERLIFE_LICENSE_FILE=/path/to/file`)
   >
   > Confirm with `afterlife license`. Thanks, and reply here for support.

That is the whole recurring task: one mint and one email per sale.

## Part 4: the customer ledger (`customers.csv`)

Keep a local ledger so you can renew and, if needed, revoke. It holds emails and
names, so it is **gitignored** (never commit it). Create `customers.csv` with:

```csv
issued_at,customer_org,email,jti,term_days,expires_at,polar_order_id,notes
2026-09-10,Acme Inc.,ops@acme.example,282dafc6159d4883b1f75f1004b18706,365,2027-09-10,ord_123,founding
```

The `jti` is how you revoke a single license later (add it to `_REVOKED_JTIS` in
`licensing.py` and cut a release, or to a deployer's `AFTERLIFE_LICENSE_DENYLIST`;
see [KEY-MANAGEMENT.md](KEY-MANAGEMENT.md#revoking-a-single-license)).

## Part 5: renewals

Annual. When a subscription renews in Polar (or a year passes), mint a fresh
365-day token for the same organization and email it, then update the row's
`jti` and `expires_at`. At expiry an un-renewed license simply locks the Pro
features; the full free core keeps running, so a lapse never breaks the tool.

## Part 6: activate the store (do this first, and before promoting the site)

Until this is done, checkout shows "Organization is not ready to accept
payments" and nothing can be purchased.

- [ ] Finish Polar **identity verification (KYC)** and connect a **payout
      account** (Dashboard → **Finish setting up your account** / **Continue
      setup**, or **Settings → Finance/Payout**). Complete every required step;
      Polar then reviews and activates the organization.
- [ ] **Delete or disable `TEST100`** (or confirm its redemption cap is spent) so
      no real visitor checks out for free.
- [ ] Confirm the signing key is **backed up offsite** (see
      [KEY-MANAGEMENT.md](KEY-MANAGEMENT.md)); you cannot mint without it.
- [ ] Do one more real dry run in live mode with a genuine card if you want full
      confidence (you can refund yourself).

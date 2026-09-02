# Managing the license-signing key

Afterlife's Pro tier is unlocked by an offline license: a JWT signed with the
vendor's Ed25519 **private key** and verified on the customer's machine against
the **public key** embedded in [`src/afterlife/licensing.py`](../src/afterlife/licensing.py)
(`VENDOR_PUBLIC_KEY`). There is no license server and nothing phones home, which
is the whole point of the design. It also means one file carries the entire
commercial model.

## The one file that matters

```
.secrets/afterlife_license_key.pem
```

This private key is the only thing that can mint Pro licenses. Three facts
follow from that, and they drive everything below:

- **It is irreplaceable.** It is deliberately not in git (`.secrets/` and
  `*.pem` are gitignored). If the only copy is lost, you can never issue or
  renew a Pro license again without shipping a new release (see
  [Rotation](#rotating-the-key)).
- **It is the crown jewel.** Anyone who obtains it can mint licenses that your
  builds will accept as genuine. Treat it like a code-signing key.
- **It must match the shipped public key.** A private key that does not
  correspond to `VENDOR_PUBLIC_KEY` produces licenses that fail verification on
  every customer install. Confirm the match before you ever sell:

  ```bash
  scripts/key_backup.sh verify
  ```

## Current protections

- File mode `600`, directory `.secrets/` mode `700` (owner-only).
- Gitignored via `.secrets/` and `*.pem`, so neither the key nor an encrypted
  backup blob written into `.secrets/` can be committed.
- The keypair has been verified to match the embedded `VENDOR_PUBLIC_KEY`.

What is still missing until you act: **an offsite backup.** A single copy on one
laptop is one disk failure, one theft, or one `rm` away from ending the
business. Fix that now.

## Backing it up

Use the helper. It encrypts the key with a passphrase **you** choose, verifies
the backup actually decrypts (an untested backup is not a backup), and writes
the blob into the gitignored `.secrets/` directory:

```bash
scripts/key_backup.sh backup
```

The script never sees your passphrase; the encryption tool (age, gpg, or
openssl, whichever is installed) prompts you directly. Then follow the 3-2-1
rule for the resulting blob:

- **3 copies**, **2 different media**, **1 offsite.** Concretely, store the
  encrypted blob in at least two of:
  - your password manager as a secure-note / file attachment (1Password,
    Bitwarden, etc.),
  - an encrypted offline USB drive kept somewhere physically separate,
  - a cloud secrets store or KMS (AWS Secrets Manager, GCP Secret Manager,
    1Password Vault) if you already run one.
- **Store the passphrase separately from the blob.** Put the passphrase in your
  password manager; do not keep it in the same place as the file it unlocks.
  The blob is useless without the passphrase, and the passphrase is useless
  without the blob. That separation is the point.
- **Once the offsite copies exist, delete the local blob.** Leaving
  `.secrets/afterlife_license_key.pem.age` next to the key adds attack surface
  for no benefit.

## Restoring it

On a new machine (or after loss), decrypt a backup back into place. The script
picks the tool from the file extension (`.age`, `.gpg`, `.enc`) and re-verifies
the restored key against the embedded public key:

```bash
scripts/key_backup.sh restore .secrets/afterlife_license_key.pem.age
```

Then prove the whole chain end to end by minting a throwaway license and letting
the issuer self-verify it:

```bash
python scripts/issue_license.py "Restore Smoke Test" --days 1
```

If that prints a token without error, the restored key is correct and matches
the public key your builds ship.

## Issuing licenses

Day to day, minting is one command per sale or renewal:

```bash
python scripts/issue_license.py "Acme Corp" --days 365     # annual
python scripts/issue_license.py "Acme Corp" --days 0       # perpetual
```

The issuer signs with `.secrets/afterlife_license_key.pem` and self-verifies the
result against `VENDOR_PUBLIC_KEY` before printing, so a broken or mismatched
key fails loudly at mint time rather than silently at the customer.

## Rotating the key

Rotation is expensive by design, so do it only when the private key is lost or
believed compromised, never routinely.

1. Generate a new keypair:

   ```bash
   openssl genpkey -algorithm ed25519 -out .secrets/afterlife_license_key.pem
   chmod 600 .secrets/afterlife_license_key.pem
   openssl pkey -in .secrets/afterlife_license_key.pem -pubout
   ```

2. Paste the printed public key into `VENDOR_PUBLIC_KEY` in
   [`src/afterlife/licensing.py`](../src/afterlife/licensing.py).
3. Run `scripts/key_backup.sh verify` to confirm the new pair matches, then
   `make check`.
4. Cut a new release. **Every customer must upgrade to a build carrying the new
   public key**, because their current build only trusts the old one.
5. Re-mint and redeliver a license to every active customer with the new key.
6. Back up the new key ([above](#backing-it-up)) before you retire the old one.

The blast radius, stated plainly: **rotation breaks every license already sold
until each customer both upgrades and receives a re-minted key.** That is why
the backup exists: so you never have to rotate over a lost key.

## Revoking a single license

Rotation is the nuclear option. To kill **one** leaked or refunded license
without touching any other, use its `jti` (JWT ID). Every minted token carries a
unique one, and `scripts/issue_license.py` prints it to stderr at mint time:

```
issued jti=75f0af7ed30a482ebaa698aa179625a8 customer='Acme Corp' validity=365d
```

Record that jti against the customer. To revoke:

- **Ship it (the durable way).** Add the jti to `_REVOKED_JTIS` in
  [`src/afterlife/licensing.py`](../src/afterlife/licensing.py) and cut a
  release. Every updated install then rejects that one token and nothing else.
- **Locally (deployer-side).** A self-hosted operator can revoke on their own
  box by listing jtis in `AFTERLIFE_LICENSE_DENYLIST` (comma-separated) or
  `AFTERLIFE_LICENSE_DENYLIST_FILE` (one jti per line).

The honest limitation: nothing phones home, so a revocation only takes effect
where the updated build or denylist is present. It is a "revoke in the next
release" kill switch, not instant remote revocation. But unlike rotation, it
leaves every other customer's license working.

## Incident response

**Key lost (no backup).** You cannot recover it. Rotate (above), which forces a
release and a re-mint for every customer. Prevent this by backing up now.

**Key leaked or possibly compromised** (committed by mistake, copied off a
stolen laptop, exposed in a log):

1. Treat every license mintable by that key as untrusted.
2. Rotate immediately (above) so builds stop trusting the leaked key.
3. If the key ever touched git history, purging the working copy is not enough;
   the object remains in history and must be considered public. Rotate
   regardless of any history rewrite.
4. If only one license leaked (not the signing key itself), prefer
   [revoking that single license](#revoking-a-single-license) by its `jti` over
   a full rotation. Rotate only when the private key is what leaked.

## Do not

- Do not commit the key or an unencrypted copy anywhere, in this repo or any
  other.
- Do not paste it into chat, an issue, a CI log, a screenshot, or an AI tool.
- Do not store the encrypted blob and its passphrase in the same place.
- Do not put the private key in a CI secret unless and until you automate
  minting; a webhook minter is the one case that justifies it, and it puts the
  crown jewel online, so treat that as a deliberate, least-privilege decision
  (see the fulfillment tiers in [GO-TO-MARKET.md](GO-TO-MARKET.md)).

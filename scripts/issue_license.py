#!/usr/bin/env python3
"""Mint an Afterlife Pro license. Vendor-side: requires the private key.

The private key (.secrets/afterlife_license_key.pem by default) is the only
secret that can create licenses. Keep it offline and out of version control.
Run this after a purchase and send the printed token to the customer, who sets
it as AFTERLIFE_LICENSE (or writes it to a file named by AFTERLIFE_LICENSE_FILE).

    python scripts/issue_license.py "Acme Corp" --days 365
    python scripts/issue_license.py "Acme Corp" --days 0        # perpetual
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from afterlife.licensing import issue_license, verify_license


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Mint an Afterlife Pro license.")
    parser.add_argument("customer", help="Customer name to embed in the license.")
    parser.add_argument(
        "--days", type=int, default=365,
        help="Validity in days (0 = perpetual). Default 365.",
    )
    parser.add_argument(
        "--key", default=".secrets/afterlife_license_key.pem",
        help="Path to the vendor Ed25519 private key (PEM).",
    )
    parser.add_argument(
        "--features", nargs="*", default=None,
        help="Restrict to specific Pro feature ids (default: all).",
    )
    args = parser.parse_args(argv)

    key_path = Path(args.key)
    if not key_path.exists():
        print(f"error: private key not found at {key_path}", file=sys.stderr)
        return 1

    token = issue_license(
        key_path.read_text(),
        args.customer,
        features=args.features,
        expires_in_days=(None if args.days == 0 else args.days),
    )
    # Sanity check against the embedded public key before handing it out.
    lic = verify_license(token)
    if lic is None:
        print("error: minted token failed self-verification", file=sys.stderr)
        return 1

    # Record this jti against the customer: it is how you revoke this one license
    # later (add it to AFTERLIFE_LICENSE_DENYLIST) without affecting any other.
    validity = "perpetual" if args.days == 0 else f"{args.days}d"
    print(
        f"issued jti={lic.jti} customer={args.customer!r} validity={validity}",
        file=sys.stderr,
    )
    print(token)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

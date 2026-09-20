#!/usr/bin/env python3
"""Safely inspect TON wallet addresses without network access."""

from __future__ import annotations

import argparse
import getpass
import os

from FragmentAPI import derive_wallet, derive_wallet_accounts


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--mnemonic-type", choices=("auto", "ton", "bip39"), default="auto"
    )
    parser.add_argument("--account-index", type=int, default=0)
    parser.add_argument("--wallet-version", choices=("V4R2", "V5R1"), default="V5R1")
    parser.add_argument("--scan", type=int, default=0, metavar="COUNT")
    args = parser.parse_args()

    seed = os.environ.get("TON_WALLET_SEED") or getpass.getpass("Enter mnemonic: ")
    if args.scan:
        accounts = derive_wallet_accounts(
            seed,
            start_index=args.account_index,
            count=args.scan,
            wallet_version=args.wallet_version,
        )
        for account in accounts:
            print(f"{account.account_index:<4} {account.address}  {account.public_key}")
        return

    wallet = derive_wallet(
        seed,
        mnemonic_type=args.mnemonic_type,
        account_index=args.account_index,
        wallet_version=args.wallet_version,
    )
    print(f"Mnemonic type: {wallet.mnemonic_type}")
    print(f"Account index: {wallet.account_index}")
    print(f"Wallet version: {wallet.wallet_version}")
    print(f"Address: {wallet.address}")
    print(f"Public key: {wallet.public_key}")


if __name__ == "__main__":
    main()

# Testing notes

- Run the offline regression suite with `python -m pytest`. Its derivation
  vectors independently reproduce BIP39 PBKDF2 and SLIP-0010 HMAC derivation,
  then assert Tonkeeper-compatible V5R1 public keys and addresses for indexes
  0–2.
- Tests intentionally use public BIP39 and TON mnemonic fixtures only. Do not
  add real wallet phrases or live purchase/authentication tests.
- `scripts/derive_wallet.py` is an offline diagnostic: read the mnemonic from
  `TON_WALLET_SEED` or its hidden prompt, never from command-line arguments.

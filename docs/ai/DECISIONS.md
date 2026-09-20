# Decisions

## Centralized TON wallet derivation

- Decision: all auth, address, balance, and signing paths use
  `FragmentAPI/utils/mnemonic.py`.
- Reason: a Fragment proof and its later transaction must always use the same
  account/key pair.
- Invariants: TON-native mnemonics retain the TON KDF; Keeper multichain
  mnemonics use BIP39 seed + SLIP-0010 Ed25519 at
  `m/44'/607'/{account_index}'`; `account_index` is not `subwallet_id`.
- Safety: 24-word phrases valid in both formats fail auto detection and require
  an explicit type. Public helpers never return private key material.
- Public contract: `FragmentClient` accepts `mnemonic_type` (`auto`, `ton`, or
  `bip39`) and `account_index`; the same options are forwarded through
  authentication, storage restore, and cookie refresh. `derive_wallet()` and
  `derive_wallet_accounts()` are offline-only and return `DerivedWalletInfo`.
- Dependency: `bip-utils` supplies the standard BIP39 seed and SLIP-0010
  Ed25519 implementation; it must not be replaced with TON's mnemonic KDF for
  multichain accounts.
- Relevant files: `FragmentAPI/utils/mnemonic.py`, `client.py`, `utils/auth.py`,
  `utils/wallet.py`, `utils/nokyc.py`, `types/models.py`.

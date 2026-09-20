# Repository map

- `FragmentAPI/client.py`: public `FragmentClient` API and session lifecycle.
- `FragmentAPI/utils/mnemonic.py`: sole wallet key derivation and offline account discovery.
- `FragmentAPI/utils/auth.py`: Fragment TON Proof and Telegram OAuth.
- `FragmentAPI/utils/wallet.py`: TON/USDT balance lookup and local transaction signing.
- `FragmentAPI/utils/nokyc.py`: MarketApp unsigned transaction building; signing remains local.
- `FragmentAPI/types/`: constants and public Pydantic result models.
- `tests/`: offline derivation, compatibility, and proof vectors.
- `pyproject.toml`: package metadata and dependencies.

See `DECISIONS.md` for mnemonic derivation invariants.

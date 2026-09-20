"""Centralized TON-native and Tonkeeper-compatible BIP39 wallet derivation."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from bip_utils import Bip32Slip10Ed25519, Bip39MnemonicValidator, Bip39SeedGenerator
from ton_core import NetworkGlobalID, PrivateKey, mnemonic_is_valid, words as ton_words

from FragmentAPI.exceptions import (
    AmbiguousMnemonicError,
    ConfigurationError,
    InvalidMnemonicError,
)
from FragmentAPI.types.constants import (
    MnemonicType,
    SUPPORTED_MNEMONIC_TYPES,
    SUPPORTED_WALLET_VERSIONS,
    WALLET_CLASSES,
)
from FragmentAPI.types.models import DerivedWalletInfo


class OfflineClient:
    """Minimal client required by tonutils for deterministic wallet construction."""

    network = NetworkGlobalID.MAINNET


@dataclass(frozen=True)
class DerivedWallet:
    """Internal derivation material; callers must not serialize this object."""

    wallet: Any = field(repr=False)
    private_key: PrivateKey = field(repr=False)
    public_key: Any
    mnemonic_type: str
    account_index: int
    wallet_version: str


def _normalize(seed: str) -> tuple[str, list[str]]:
    phrase = " ".join(str(seed).strip().lower().split())
    return phrase, phrase.split()


def _is_bip39(phrase: str) -> bool:
    return Bip39MnemonicValidator().IsValid(phrase)


def _is_ton(words: list[str]) -> bool:
    if len(words) == 24:
        return mnemonic_is_valid(words)
    # tonutils historically accepted 12/18 words and applied the TON KDF.
    return len(words) in (12, 18) and all(word in ton_words for word in words)


def resolve_mnemonic_type(seed: str, mnemonic_type: MnemonicType | str = "auto") -> str:
    """Validate and resolve a mnemonic without exposing it in errors."""
    phrase, words = _normalize(seed)
    requested = str(mnemonic_type).lower()
    if requested not in SUPPORTED_MNEMONIC_TYPES:
        raise ConfigurationError(
            ConfigurationError.INVALID_MNEMONIC_TYPE.format(mnemonic_type=requested)
        )

    ton_valid = _is_ton(words)
    bip39_valid = _is_bip39(phrase)

    if requested == "ton":
        if not ton_valid:
            raise InvalidMnemonicError("Invalid TON-native mnemonic.")
        return "ton"
    if requested == "bip39":
        if not bip39_valid:
            raise InvalidMnemonicError("Invalid BIP39 mnemonic checksum or word list.")
        return "bip39"

    if len(words) == 12:
        if not bip39_valid:
            raise InvalidMnemonicError(
                "Invalid 12-word BIP39 mnemonic checksum or word list."
            )
        return "bip39"
    if len(words) == 24:
        if ton_valid and bip39_valid:
            raise AmbiguousMnemonicError(AmbiguousMnemonicError.MESSAGE)
        if ton_valid:
            return "ton"
        if bip39_valid:
            return "bip39"
        raise InvalidMnemonicError("Invalid 24-word TON-native or BIP39 mnemonic.")
    if len(words) == 18 and ton_valid:
        return "ton"
    raise InvalidMnemonicError(
        "Auto detection supports 12-word BIP39 and 24-word TON-native/BIP39 mnemonics."
    )


def derive_wallet_material(
    seed: str,
    *,
    mnemonic_type: MnemonicType | str = "auto",
    account_index: int = 0,
    wallet_version: str = "V5R1",
    client: Any | None = None,
) -> DerivedWallet:
    """Derive the selected key and construct its TON wallet contract."""
    if (
        isinstance(account_index, bool)
        or not isinstance(account_index, int)
        or not 0 <= account_index < 0x80000000
    ):
        raise ConfigurationError(ConfigurationError.INVALID_ACCOUNT_INDEX)
    version = str(wallet_version).upper()
    if version not in SUPPORTED_WALLET_VERSIONS:
        raise ConfigurationError(
            ConfigurationError.UNSUPPORTED_VERSION.format(
                version=version, supported=", ".join(sorted(SUPPORTED_WALLET_VERSIONS))
            )
        )

    phrase, words = _normalize(seed)
    resolved = resolve_mnemonic_type(phrase, mnemonic_type)
    if resolved == "ton" and account_index != 0:
        raise ConfigurationError(
            "account_index applies only to BIP39 multichain mnemonics."
        )
    wallet_cls = WALLET_CLASSES[version]
    ton_client = client or OfflineClient()

    if resolved == "ton":
        wallet, public_key, private_key, _ = wallet_cls.from_mnemonic(
            client=ton_client, mnemonic=words
        )
    else:
        bip39_seed = Bip39SeedGenerator(phrase).Generate()
        path = f"m/44'/607'/{account_index}'"
        key_seed = (
            Bip32Slip10Ed25519.FromSeed(bip39_seed)
            .DerivePath(path)
            .PrivateKey()
            .Raw()
            .ToBytes()
        )
        private_key = PrivateKey(key_seed)
        public_key = private_key.public_key
        wallet = wallet_cls.from_private_key(client=ton_client, private_key=private_key)

    return DerivedWallet(
        wallet=wallet,
        private_key=private_key,
        public_key=public_key,
        mnemonic_type=resolved,
        account_index=account_index,
        wallet_version=version,
    )


def derive_wallet(
    seed: str,
    *,
    mnemonic_type: MnemonicType | str = "auto",
    account_index: int = 0,
    wallet_version: str = "V5R1",
) -> DerivedWalletInfo:
    """Derive public wallet information locally, without network access."""
    result = derive_wallet_material(
        seed,
        mnemonic_type=mnemonic_type,
        account_index=account_index,
        wallet_version=wallet_version,
    )
    return DerivedWalletInfo(
        address=result.wallet.address.to_str(
            is_user_friendly=True, is_bounceable=False
        ),
        public_key=result.public_key.as_hex,
        wallet_version=result.wallet_version,
        mnemonic_type=result.mnemonic_type,
        account_index=result.account_index,
    )


def derive_wallet_accounts(
    seed: str,
    *,
    start_index: int = 0,
    count: int = 10,
    wallet_version: str = "V5R1",
) -> list[DerivedWalletInfo]:
    """Derive a range of BIP39 accounts locally, without balance lookups."""
    if (
        isinstance(start_index, bool)
        or not isinstance(start_index, int)
        or not 0 <= start_index < 0x80000000
    ):
        raise ConfigurationError("start_index must be a non-negative integer.")
    if isinstance(count, bool) or not isinstance(count, int) or count < 1:
        raise ConfigurationError("count must be a positive integer.")
    if start_index + count > 0x80000000:
        raise ConfigurationError(
            "requested account range exceeds the SLIP-0010 index limit."
        )
    return [
        derive_wallet(
            seed,
            mnemonic_type="bip39",
            account_index=index,
            wallet_version=wallet_version,
        )
        for index in range(start_index, start_index + count)
    ]

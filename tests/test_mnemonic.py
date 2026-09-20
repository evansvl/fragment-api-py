import base64
import hashlib
import hmac
import struct
from types import SimpleNamespace

import pytest
from nacl.signing import VerifyKey
from ton_core import Cell, StateInit

import FragmentAPI.client as client_module
from FragmentAPI import (
    AmbiguousMnemonicError,
    FragmentClient,
    FragmentPageError,
    InvalidMnemonicError,
    derive_wallet,
    derive_wallet_accounts,
)
from FragmentAPI.utils import mnemonic as mnemonic_module
from FragmentAPI.utils import wallet as wallet_module
import FragmentAPI.utils.auth as auth_module
from FragmentAPI.utils.auth import _generate_proof, authenticate


BIP39_12 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
BIP39_24 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
TON_24 = "exercise float bracket anxiety error body aerobic refuse derive junk price horse shove dress deal scrub volume save measure brush globe hole target crush"

# Reference vector produced independently from Tonkeeper's mnemonicService.ts and
# ed25519.ts algorithm (BIP39 PBKDF2 + SLIP-0010), then @ton/ton WalletContractV5R1.
V5_VECTORS = {
    0: (
        "7952e94118f34607c75e23258dd9220d66ccac5a3ee074125c25068e8107bfbf",
        "UQBHyu-oZVDHRYQ1-rKlGqpHy5yAqanPBirEQNMNOmfHLtaT",
    ),
    1: (
        "1d87da6f9190dddea5650e9156ff32ca359e61fb473642f0c76b7b79514f0d4d",
        "UQAockb65N9NqreZHrYfhipG94Q_gZYTBkV0mvaopLEEzOgi",
    ),
    2: (
        "f4048c346dc4efbd6cabf8aae7248b8a82cef35c558bbdb14fc65899f8a574ca",
        "UQD8esjfHjcGSc0Oj-QzD0hK1--zxSZAmwuDrqsVzPop9VSg",
    ),
}


def _reference_slip10_seed(phrase: str, index: int) -> bytes:
    seed = hashlib.pbkdf2_hmac("sha512", phrase.encode(), b"mnemonic", 2048)
    digest = hmac.new(b"ed25519 seed", seed, hashlib.sha512).digest()
    key, chain = digest[:32], digest[32:]
    for value in (44, 607, index):
        data = b"\x00" + key + struct.pack(">I", value + 0x80000000)
        digest = hmac.new(chain, data, hashlib.sha512).digest()
        key, chain = digest[:32], digest[32:]
    return key


@pytest.mark.parametrize("index", [0, 1, 2])
def test_tonkeeper_bip39_vectors(index):
    info = derive_wallet(BIP39_12, mnemonic_type="bip39", account_index=index)
    assert (info.public_key, info.address) == V5_VECTORS[index]
    material = mnemonic_module.derive_wallet_material(
        BIP39_12, mnemonic_type="bip39", account_index=index
    )
    assert material.private_key.as_bytes == _reference_slip10_seed(BIP39_12, index)


def test_account_discovery_is_offline_and_distinct():
    accounts = derive_wallet_accounts(BIP39_12, count=3)
    assert [a.account_index for a in accounts] == [0, 1, 2]
    assert len({a.address for a in accounts}) == 3


def test_legacy_ton_address_is_unchanged():
    info = derive_wallet(TON_24, mnemonic_type="ton")
    assert info.address == "UQD8pLuIJfbckvb8hK5bq2zU4tMJ3OFfaLUL90wXmeOV1YmQ"
    assert (
        info.public_key
        == "12cd48fab5c2eed8112e7c7243bfd8e43d020a69309e5fcb3c729cb9e99b28b1"
    )


def test_auto_detection():
    assert derive_wallet(BIP39_12).mnemonic_type == "bip39"
    assert derive_wallet(BIP39_24).mnemonic_type == "bip39"
    assert derive_wallet(TON_24).mnemonic_type == "ton"
    with pytest.raises(InvalidMnemonicError, match="checksum"):
        derive_wallet("abandon " * 12)


def test_ambiguous_auto_requires_explicit_type(monkeypatch):
    monkeypatch.setattr(mnemonic_module, "_is_ton", lambda words: True)
    monkeypatch.setattr(mnemonic_module, "_is_bip39", lambda phrase: True)
    with pytest.raises(AmbiguousMnemonicError, match="both TON-native and BIP39"):
        mnemonic_module.resolve_mnemonic_type(BIP39_24)


def test_ton_proof_uses_selected_bip39_account():
    payload = "test-challenge"
    account, _, proof = _generate_proof(BIP39_12.split(), "V5R1", payload, "bip39", 1)
    expected = derive_wallet(BIP39_12, mnemonic_type="bip39", account_index=1)
    expected_material = mnemonic_module.derive_wallet_material(
        BIP39_12, mnemonic_type="bip39", account_index=1
    )
    assert account["publicKey"] == expected.public_key
    assert account["address"] == expected_material.wallet.address.to_str(
        is_user_friendly=False
    )
    assert base64.b64decode(account["walletStateInit"])

    workchain, address_hash = account["address"].split(":")
    domain = proof["domain"]["value"].encode()
    msg = (
        b"ton-proof-item-v2/"
        + struct.pack(">i", int(workchain))
        + bytes.fromhex(address_hash)
        + struct.pack("<I", len(domain))
        + domain
        + struct.pack("<Q", proof["timestamp"])
        + payload.encode()
    )
    digest = hashlib.sha256(
        b"\xff\xffton-connect" + hashlib.sha256(msg).digest()
    ).digest()
    VerifyKey(bytes.fromhex(account["publicKey"])).verify(
        digest, base64.b64decode(proof["signature"])
    )


def test_client_keeps_derivation_selection():
    client = FragmentClient(
        seed=BIP39_12,
        mnemonic_type="bip39",
        account_index=2,
        wallet_version="V4R2",
    )
    assert client.mnemonic_type == "bip39"
    assert client.account_index == 2
    assert client.derive_wallet(BIP39_12, "bip39", 2, "V4R2").wallet_version == "V4R2"


class _TonContext:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None


class _FakeWallet:
    def __init__(self, address):
        self.address = address
        self.balance = 2_000_000_000
        self.state = SimpleNamespace(value="active")

    async def refresh(self):
        return None

    async def seqno(self):
        return 7


@pytest.mark.asyncio
async def test_wallet_info_and_usdt_use_selected_owner(monkeypatch):
    source = mnemonic_module.derive_wallet_material(
        BIP39_12, mnemonic_type="bip39", account_index=2
    )
    fake_wallet = _FakeWallet(source.wallet.address)
    calls = {}

    def fake_derive(seed, **kwargs):
        calls.update(kwargs)
        return SimpleNamespace(
            wallet=fake_wallet,
            wallet_version="V5R1",
            mnemonic_type="bip39",
            account_index=2,
        )

    async def fake_usdt(ton, owner):
        calls["usdt_owner"] = owner
        return 3.5

    monkeypatch.setattr(wallet_module, "_make_ton_client", lambda client: _TonContext())
    monkeypatch.setattr(wallet_module, "derive_wallet_material", fake_derive)
    monkeypatch.setattr(wallet_module, "_get_usdt_balance", fake_usdt)
    client = FragmentClient(
        seed=BIP39_12, api_key="test", mnemonic_type="bip39", account_index=2
    )
    info = await wallet_module.fetch_wallet_info(client)
    expected_owner = source.wallet.address.to_str(False, False)
    assert calls["account_index"] == 2
    assert calls["usdt_owner"] == expected_owner
    assert info.account_index == 2 and info.usdt_balance == 3.5


@pytest.mark.asyncio
async def test_transaction_uses_selected_bip39_signer(monkeypatch):
    source = mnemonic_module.derive_wallet_material(
        BIP39_12, mnemonic_type="bip39", account_index=1
    )
    fake_wallet = _FakeWallet(source.wallet.address)
    calls = {}

    def fake_derive(seed, **kwargs):
        calls.update(kwargs)
        return SimpleNamespace(wallet=fake_wallet)

    async def fake_broadcast(wallet, destinations, amounts, bodies, state_inits):
        calls["wallet"] = wallet
        calls["state_inits"] = state_inits
        return "test-hash"

    async def fake_confirmation(wallet, seqno, balance):
        return True, seqno + 1, balance - 0.1

    monkeypatch.setattr(wallet_module, "_make_ton_client", lambda client: _TonContext())
    monkeypatch.setattr(wallet_module, "derive_wallet_material", fake_derive)
    monkeypatch.setattr(wallet_module, "_broadcast_with_retry", fake_broadcast)
    monkeypatch.setattr(wallet_module, "_wait_confirmation", fake_confirmation)
    client = FragmentClient(
        seed=BIP39_12, api_key="test", mnemonic_type="bip39", account_index=1
    )
    result = await wallet_module._run_transaction(
        client,
        {
            "transaction": {
                "messages": [
                    {
                        "address": source.wallet.address.to_str(False, False),
                        "amount": "1",
                    }
                ]
            }
        },
        skip_balance_check=True,
    )
    assert result.confirmed is True
    assert calls["account_index"] == 1
    assert calls["wallet"] is fake_wallet
    assert calls["state_inits"] == [None]


@pytest.mark.asyncio
async def test_storage_and_refresh_preserve_derivation(monkeypatch):
    calls = []
    cookies = {
        "stel_ssid": "ssid",
        "stel_dt": "0",
        "stel_token": "token",
        "stel_ton_token": "ton-token",
    }

    async def fake_authenticate(**kwargs):
        calls.append(kwargs)
        return cookies

    class Storage:
        async def load(self, session_id):
            return None

        async def save(self, session_id, value):
            return None

    monkeypatch.setattr(client_module, "authenticate", fake_authenticate)
    client = await FragmentClient.from_storage(
        Storage(),
        "test",
        seed=BIP39_12,
        mnemonic_type="bip39",
        account_index=2,
    )
    await client.refresh_cookies()
    assert [call["mnemonic_type"] for call in calls] == ["bip39", "bip39"]
    assert [call["account_index"] for call in calls] == [2, 2]


@pytest.mark.asyncio
async def test_state_init_is_decoded_and_forwarded_for_single_and_batch():
    state_init = StateInit(code=Cell.empty(), data=Cell.empty())
    encoded = (
        base64.urlsafe_b64encode(state_init.serialize().to_boc()).decode().rstrip("=")
    )
    messages = [
        {"address": "0:" + "00" * 32, "amount": "1", "stateInit": encoded},
        {"address": "0:" + "11" * 32, "amount": "2", "state_init": encoded},
    ]
    destinations, amounts, bodies, state_inits = wallet_module._parse_messages(messages)
    assert [item.serialize().to_boc() for item in state_inits] == [
        state_init.serialize().to_boc(),
        state_init.serialize().to_boc(),
    ]

    class Wallet:
        async def transfer_message(self, builder):
            self.single = builder
            return "single"

        async def batch_transfer_message(self, builders):
            self.batch = builders
            return "batch"

    wallet = Wallet()
    await wallet_module._single_transfer(
        wallet, destinations[0], amounts[0], bodies[0], state_inits[0]
    )
    await wallet_module._batch_transfer(
        wallet, destinations, amounts, bodies, state_inits
    )
    assert (
        wallet.single.state_init.serialize().to_boc() == state_init.serialize().to_boc()
    )
    assert [builder.state_init.serialize().to_boc() for builder in wallet.batch] == [
        state_init.serialize().to_boc(),
        state_init.serialize().to_boc(),
    ]


def test_internal_derived_wallet_repr_redacts_private_material():
    material = mnemonic_module.derive_wallet_material(BIP39_12, mnemonic_type="bip39")
    rendered = repr(material)
    assert material.private_key.as_hex not in rendered
    assert BIP39_12 not in rendered
    assert "private_key=" not in rendered
    assert "wallet=" not in rendered


@pytest.mark.asyncio
async def test_authenticate_propagates_ambiguous_error_before_http(monkeypatch):
    monkeypatch.setattr(mnemonic_module, "_is_ton", lambda words: True)
    monkeypatch.setattr(mnemonic_module, "_is_bip39", lambda phrase: True)
    monkeypatch.setattr(
        auth_module.requests,
        "AsyncSession",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("HTTP attempted")),
    )
    with pytest.raises(AmbiguousMnemonicError):
        await authenticate(BIP39_24)


@pytest.mark.asyncio
async def test_auto_refresh_retries_expired_session_once(monkeypatch):
    old_cookies = {"stel_ssid": "old", "stel_dt": "0", "stel_token": "old-token"}
    new_cookies = {"stel_ssid": "new", "stel_dt": "0", "stel_token": "new-token"}
    client = FragmentClient(
        cookies=old_cookies,
        seed=BIP39_12,
        mnemonic_type="bip39",
        auto_refresh_cookies=True,
    )
    calls = {"hash": 0, "refresh": 0}

    class Session:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

    async def fake_hash(*args, **kwargs):
        calls["hash"] += 1
        if calls["hash"] == 1:
            raise FragmentPageError(
                FragmentPageError.BAD_STATUS.format(
                    status=401, url="https://fragment.com"
                )
            )
        return "hash"

    async def fake_post(*args, **kwargs):
        return {"ok": True}

    async def fake_refresh():
        calls["refresh"] += 1
        client.cookies = new_cookies
        return new_cookies

    monkeypatch.setattr(
        client_module.requests, "AsyncSession", lambda **kwargs: Session()
    )
    monkeypatch.setattr(client_module, "fetch_fragment_hash", fake_hash)
    monkeypatch.setattr(client_module, "post_fragment_api", fake_post)
    monkeypatch.setattr(client, "refresh_cookies", fake_refresh)
    assert await client.call("test") == {"ok": True}
    assert calls == {"hash": 2, "refresh": 1}
    assert client.cookies is new_cookies

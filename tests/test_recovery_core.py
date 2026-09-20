# -*- coding: utf-8 -*-
"""
Public reproducibility tests for exodus-bip39-recovery-research.

All vectors are synthetic/public test vectors. No real wallet backup,
mnemonic, passphrase, private key, or user transaction data is included.
"""

import importlib.util
import json
import zipfile
from pathlib import Path

import pytest
from mnemonic import Mnemonic

REPO_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = REPO_ROOT / "src" / "exodus_recovery_tool.py"

spec = importlib.util.spec_from_file_location("exodus_recovery_tool", MODULE_PATH)
recovery = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(recovery)


# Public BIP-39 test vector #1 entropy.
ENTROPY_128 = bytes.fromhex("00000000000000000000000000000000")
MNEMONIC_128 = (
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about"
)
ETH_RE = "0x" + ("12" * 20)


def test_normalize_eth_address_accepts_and_lowercases():
    mixed = "0x" + ("Ab" * 20)
    assert recovery.normalize_eth_address(mixed) == mixed.lower()


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "0x1234",
        "1234567890abcdef1234567890abcdef12345678",
        "0x" + ("zz" * 20),
        "0x" + ("11" * 19),
        "0x" + ("11" * 21),
    ],
)
def test_normalize_eth_address_rejects_invalid_values(bad):
    with pytest.raises(ValueError):
        recovery.normalize_eth_address(bad)


def test_entropy_to_mnemonic_matches_public_bip39_vector():
    assert recovery.entropy_to_mnemonic(ENTROPY_128) == MNEMONIC_128


@pytest.mark.parametrize("length", [0, 1, 15, 17, 19, 21, 31, 33])
def test_entropy_to_mnemonic_rejects_invalid_lengths(length):
    with pytest.raises(ValueError):
        recovery.entropy_to_mnemonic(bytes(length))


def test_verify_mnemonic_seed_roundtrip():
    stored_seed = Mnemonic.to_seed(MNEMONIC_128, passphrase="")
    assert recovery.verify_mnemonic_seed(MNEMONIC_128, stored_seed)


def test_verify_mnemonic_seed_rejects_wrong_seed():
    assert not recovery.verify_mnemonic_seed(MNEMONIC_128, bytes(64))


def test_bip32_master_matches_bip32_test_vector_1():
    # Official BIP-32 test vector 1:
    # seed = 000102030405060708090a0b0c0d0e0f
    seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    key, chain = recovery.bip32_master(seed)

    # m private key:
    # e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35
    assert key == int(
        "e8f32e723decf4051aefac8e2c93c9c"
        "5b214313817cdb01a1494b917c8436b35",
        16,
    )

    # m chain code:
    # 873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508
    assert chain.hex() == (
        "873dff81c02f525623fd1fe5167eac3a"
        "55a049de3d314bb42ee227ffed37d508"
    )


def test_read_passphrase_json():
    data = json.dumps({"passphrase": "synthetic-test-passphrase"}).encode("utf-8")
    assert recovery.read_passphrase_json(data) == "synthetic-test-passphrase"


@pytest.mark.parametrize(
    "obj",
    [
        {},
        {"passphrase": ""},
        {"passphrase": None},
        {"passphrase": 123},
    ],
)
def test_read_passphrase_json_rejects_missing_or_invalid(obj):
    with pytest.raises(ValueError):
        recovery.read_passphrase_json(json.dumps(obj).encode("utf-8"))


def test_parse_seco_rejects_too_small_input():
    with pytest.raises(ValueError):
        recovery.parse_seco(b"SECO")


def test_parse_seco_rejects_wrong_magic():
    fake = bytearray(
        recovery.HEADER_SIZE
        + recovery.CHECKSUM_SIZE
        + recovery.METADATA_SIZE
        + 4
    )
    fake[:4] = b"NOPE"
    with pytest.raises(ValueError):
        recovery.parse_seco(bytes(fake))


def test_extract_eth_addresses_from_csv_counts_case_insensitively(tmp_path):
    csv_path = tmp_path / "synthetic.csv"
    upper = ETH_RE.upper().replace("0X", "0x")
    csv_path.write_text(
        f"from,to\n{ETH_RE},{upper}\n{ETH_RE},not-an-address\n",
        encoding="utf-8",
    )

    counts = recovery.extract_eth_addresses_from_csv(str(csv_path))
    assert counts[ETH_RE] == 3


def test_folder_candidates_pairs_seed_and_passphrase(tmp_path):
    wallet = tmp_path / "backup" / "exodus.wallet"
    wallet.mkdir(parents=True)
    (wallet / "seed.seco").write_bytes(b"synthetic-seco")
    (wallet / "passphrase.json").write_text(
        '{"passphrase":"synthetic"}',
        encoding="utf-8",
    )

    found = list(recovery.folder_candidates(str(tmp_path)))
    assert len(found) == 1
    label, seed_bytes, pp_bytes = found[0]
    assert label.replace("\\", "/").endswith("exodus.wallet/seed.seco")
    assert seed_bytes == b"synthetic-seco"
    assert b"synthetic" in pp_bytes


def test_folder_candidates_ignores_unpaired_seed(tmp_path):
    wallet = tmp_path / "backup" / "exodus.wallet"
    wallet.mkdir(parents=True)
    (wallet / "seed.seco").write_bytes(b"synthetic-seco")

    assert list(recovery.folder_candidates(str(tmp_path))) == []


def test_zip_candidates_pairs_seed_and_passphrase(tmp_path):
    archive = tmp_path / "synthetic.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("backup/exodus.wallet/seed.seco", b"synthetic-seco")
        zf.writestr(
            "backup/exodus.wallet/passphrase.json",
            b'{"passphrase":"synthetic"}',
        )

    found = list(recovery.zip_candidates(str(archive)))
    assert len(found) == 1
    label, seed_bytes, pp_bytes = found[0]
    assert label == "backup/exodus.wallet/seed.seco"
    assert seed_bytes == b"synthetic-seco"
    assert b"synthetic" in pp_bytes


def test_ethereum_derivation_is_deterministic_for_public_bip39_vector():
    seed = Mnemonic.to_seed(MNEMONIC_128, passphrase="")
    priv1, addr1 = recovery.derive_eth_exodus(seed)
    priv2, addr2 = recovery.derive_eth_exodus(seed)

    assert priv1 == priv2
    assert addr1 == addr2
    assert recovery.normalize_eth_address(addr1) == addr1
    assert len(addr1) == 42

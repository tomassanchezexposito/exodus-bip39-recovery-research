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


def test_entropy_256_produces_24_word_bip39_mnemonic():
    mnemonic = recovery.entropy_to_mnemonic(bytes(32))
    assert len(mnemonic.split()) == 24
    assert Mnemonic("english").check(mnemonic)


def test_parse_bip32_path_default_eth_path():
    path = recovery.parse_bip32_path("m/44'/60'/0'/0/0")
    assert path == [
        44 | recovery.HARDENED,
        60 | recovery.HARDENED,
        0 | recovery.HARDENED,
        0,
        0,
    ]


def test_build_eth_paths_supports_multiple_accounts_indices_and_custom():
    paths = recovery.build_eth_paths(
        account_max=1,
        address_index_max=1,
        custom_paths="m/44'/60'/5'/0/7",
    )
    assert "m/44'/60'/0'/0/0" in paths
    assert "m/44'/60'/1'/0/1" in paths
    assert "m/44'/60'/5'/0/7" in paths
    assert len(paths) == 5


def test_derive_eth_path_matches_legacy_default_helper():
    seed = Mnemonic.to_seed(MNEMONIC_128, passphrase="")
    priv_a, addr_a = recovery.derive_eth_exodus(seed)
    priv_b, addr_b = recovery.derive_eth_path(seed, recovery.DEFAULT_ETH_PATH)
    assert priv_a == priv_b
    assert addr_a == addr_b


def test_csv_optional_early_exit_limits_unique_addresses(tmp_path):
    csv_path = tmp_path / "many.csv"
    a = "0x" + ("11" * 20)
    b = "0x" + ("22" * 20)
    c = "0x" + ("33" * 20)
    csv_path.write_text(f"{a}\n{b}\n{c}\n", encoding="utf-8")
    counts = recovery.extract_eth_addresses_from_csv(str(csv_path), max_unique=2)
    assert len(counts) == 2
    assert a in counts
    assert b in counts
    assert c not in counts


def test_encrypted_export_roundtrip():
    payload = {
        "target_address": ETH_RE,
        "verified_results": [
            {
                "mnemonic": MNEMONIC_128,
                "words": 12,
                "matching_paths": [recovery.DEFAULT_ETH_PATH],
                "backups": ["synthetic/seed.seco"],
            }
        ],
    }
    envelope = recovery.encrypt_export_payload(payload, "synthetic-password-123")
    recovered = recovery.decrypt_export_payload(envelope, "synthetic-password-123")
    assert recovered == payload


def test_scrypt_explicit_maxmem_avoids_openssl_32mib_default_limit():
    """Regression: N=2**15,r=8 fails on many OpenSSL builds if maxmem is omitted."""
    key = recovery.scrypt_derive(
        b"synthetic-password",
        salt=b"\x11" * 32,
        n=2**15,
        r=8,
        p=1,
        dklen=32,
    )
    assert isinstance(key, bytes)
    assert len(key) == 32
    assert recovery.scrypt_maxmem_for_params(2**15, 8, 1) >= 64 * 1024 * 1024


def test_scrypt_maxmem_supports_exodus_n_2_20_r8_within_configured_limit():
    """No ejecuta el KDF de 1 GiB; verifica que el cálculo permite ese parámetro."""
    maxmem = recovery.scrypt_maxmem_for_params(2**20, 8, 1)
    assert maxmem > 1024 * 1024 * 1024
    assert maxmem < recovery.SCRYPT_OPENSSL_MAXMEM


def test_memory_heavy_scrypt_automatically_reduces_parallel_workers(monkeypatch):
    monkeypatch.setattr(
        recovery,
        "parse_seco",
        lambda _data: {"n": 2**20, "r": 8, "p": 1},
    )
    candidates = [("a", b"x", b"y"), ("b", b"x", b"y")]
    workers, largest = recovery.effective_worker_count_for_candidates(candidates, 4)
    assert workers == 1
    assert largest > 1024 * 1024 * 1024


def test_research_logger_creates_text_and_jsonl_and_redacts_secrets(tmp_path):
    logger = recovery.ResearchLogger(tmp_path)
    logger.event(
        "synthetic_event",
        details={
            "mnemonic": MNEMONIC_128,
            "passphrase": "synthetic-secret-passphrase",
            "password": "synthetic-password",
            "seed_sha256": "ab" * 32,
            "safe_value": 123,
        },
    )

    text_path = Path(logger.text_path)
    jsonl_path = Path(logger.jsonl_path)
    assert text_path.exists()
    assert jsonl_path.exists()

    combined = text_path.read_text(encoding="utf-8") + jsonl_path.read_text(encoding="utf-8")
    assert MNEMONIC_128 not in combined
    assert "synthetic-secret-passphrase" not in combined
    assert "synthetic-password" not in combined
    assert "<REDACTED>" in combined
    assert "safe_value" in combined
    assert "ab" * 32 in combined


def test_research_logger_numbers_events_and_records_jsonl(tmp_path):
    logger = recovery.ResearchLogger(tmp_path)
    logger.event("first", details={"x": 1})
    logger.event("second", details={"x": 2})

    rows = [
        json.loads(line)
        for line in Path(logger.jsonl_path).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert [row["seq"] for row in rows] == [1, 2]
    assert [row["event"] for row in rows] == ["first", "second"]
    assert all(row["format"] == recovery.RESEARCH_LOG_FORMAT for row in rows)
    assert rows[0]["session_id"] == rows[1]["session_id"]


def test_process_candidate_logs_passphrase_json_source_without_value(tmp_path, monkeypatch):
    logger = recovery.ResearchLogger(tmp_path)
    secret_pp = "synthetic-export-passphrase-value"
    candidate = (
        "backup/exodus.wallet/seed.seco",
        b"synthetic-seed-container",
        json.dumps({"passphrase": secret_pp}).encode("utf-8"),
    )
    stored_seed = Mnemonic.to_seed(MNEMONIC_128, passphrase="")

    monkeypatch.setattr(
        recovery,
        "decrypt_seed_seco",
        lambda _seed, _pp, **_kwargs: b"synthetic-plaintext",
    )
    monkeypatch.setattr(
        recovery,
        "unpack_exodus_seed_payload",
        lambda _plain: stored_seed + ENTROPY_128,
    )
    monkeypatch.setattr(recovery, "verify_mnemonic_seed", lambda _m, _s: True)
    monkeypatch.setattr(
        recovery,
        "_derive_addresses_cached",
        lambda _s, _p, _c, _l, **_kwargs: ((recovery.DEFAULT_ETH_PATH, ETH_RE),),
    )

    result = recovery.process_candidate(
        candidate,
        ETH_RE,
        [recovery.DEFAULT_ETH_PATH],
        12,
        {},
        recovery.threading.Lock(),
        logger,
    )
    assert result["status"] == "match"
    assert result["credential_source"].endswith("passphrase.json")

    content = Path(logger.jsonl_path).read_text(encoding="utf-8")
    assert secret_pp not in content
    assert "paired passphrase.json from backup/export" in content
    assert "operator_wallet_password_prompted" in content
    assert '"operator_wallet_password_prompted": false' in content
    assert recovery._sha256_hex(secret_pp.encode("utf-8")) in content

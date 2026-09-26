#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Exodus BIP39 Recovery Tool — Local / 24-word ready
--------------------------------------------------
Recuperación LOCAL de una frase BIP-39 desde copias propias/autorizadas de Exodus.

Mejoras principales de esta versión:
- Soporte explícito para frases BIP-39 de 24 palabras (256 bits), configurable.
- Interfaz no bloqueante: el trabajo se ejecuta fuera del hilo de Tkinter.
- Descifrado paralelo con ThreadPoolExecutor y límite conservador de workers.
- Corrección del límite implícito de memoria de OpenSSL en hashlib.scrypt para SECO con N > 2^14.
- Barra de progreso real y registro incremental.
- Registro forense automático en .log + .jsonl con cada etapa, origen y huellas SHA-256.
- Caché de derivaciones por hash de seed para backups duplicados.
- Múltiples rutas Ethereum BIP-44 y rutas personalizadas.
- Escaneo CSV completo por defecto y modo rápido opcional con early-exit.
- Exportación opcional del resultado a un archivo local cifrado con scrypt + AES-256-GCM.
- Una coincidencia solo se acepta si la reconstrucción BIP-39 reproduce exactamente
  el seed almacenado y una ruta derivada coincide con la dirección objetivo.

IMPORTANTE:
- No envía nada a Internet.
- No necesita Etherscan ni API keys.
- No intenta adivinar ni hacer fuerza bruta sobre frases desconocidas.
- Las transacciones públicas se usan únicamente como ayuda para obtener una
  dirección de verificación; no son fuente de entropía de la frase.
"""

from __future__ import annotations

import base64
import csv
import hashlib
import hmac
import json
import os
import platform
import queue
import re
import struct
import sys
import threading
import time
import traceback
import uuid
import zipfile
import zlib
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.asymmetric import ec
except ImportError as exc:
    raise SystemExit(
        "Falta 'cryptography'. Ejecuta:\n"
        "  py -m pip install -r requirements.txt"
    ) from exc

try:
    from mnemonic import Mnemonic
except ImportError as exc:
    raise SystemExit(
        "Falta 'mnemonic'. Ejecuta:\n"
        "  py -m pip install -r requirements.txt"
    ) from exc

try:
    from Crypto.Hash import keccak
except ImportError as exc:
    raise SystemExit(
        "Falta 'pycryptodome'. Ejecuta:\n"
        "  py -m pip install -r requirements.txt"
    ) from exc


# ---------- Constantes SECO ----------
HEADER_SIZE = 224
CHECKSUM_SIZE = 32
METADATA_SIZE = 256

META_SALT_SIZE = 32
META_CIPHER_SIZE = 32
META_BLOB_KEY_IV_SIZE = 12
META_BLOB_KEY_AUTH_TAG_SIZE = 16
META_BLOB_KEY_KEY_SIZE = 32
META_BLOB_IV_SIZE = 12
META_BLOB_AUTH_TAG_SIZE = 16

SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
HARDENED = 0x80000000
ETH_ADDRESS_RE = re.compile(r"0x[a-fA-F0-9]{40}")
VALID_BIP39_WORD_COUNTS = {12, 15, 18, 21, 24}
DEFAULT_ETH_PATH = "m/44'/60'/0'/0/0"
MAX_DERIVATION_PATHS = 500
EXPORT_FORMAT = "exodus-bip39-recovery-encrypted-v1"
APP_VERSION = "0.3.0-research-log"
RESEARCH_LOG_FORMAT = "exodus-bip39-research-log-v1"

# Python delega hashlib.scrypt en OpenSSL. Cuando maxmem=0/omitido, OpenSSL
# aplica un límite implícito cercano a 32 MiB en muchas versiones. Eso hace
# fallar parámetros perfectamente válidos, por ejemplo N=2**15, r=8.
# OpenSSL/Python exige además maxmem < 2**31-1.
SCRYPT_OPENSSL_MAXMEM = 2_147_483_646
SCRYPT_MIN_MAXMEM = 64 * 1024 * 1024
SCRYPT_ABSOLUTE_SAFETY_LIMIT = 1536 * 1024 * 1024
SCRYPT_PARALLEL_MEMORY_BUDGET = 1536 * 1024 * 1024


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: str | os.PathLike[str], chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _passphrase_label_for_seed_label(seed_label: str) -> str:
    normalized = (seed_label or "").replace("\\", "/")
    if "/" in normalized:
        return normalized.rsplit("/", 1)[0] + "/passphrase.json"
    return "passphrase.json"


def _looks_base64_text(value: str) -> bool:
    text = (value or "").strip()
    if len(text) < 4 or len(text) % 4 != 0:
        return False
    return re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", text) is not None


class ResearchLogger:
    """Registro forense/reproducible en texto + JSONL, sin secretos en claro.

    El registro se vacía a disco en cada evento para conservar evidencia incluso
    si el proceso termina de forma inesperada. Nunca debe recibir la frase BIP-39,
    la passphrase, claves privadas, seeds o entropía en claro; para correlación se
    emplean únicamente huellas SHA-256.
    """

    def __init__(self, output_dir: str | os.PathLike[str]):
        self.output_dir = Path(output_dir).expanduser().resolve()
        self.output_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.session_id = f"{stamp}_{uuid.uuid4().hex[:8]}"
        self.text_path = self.output_dir / f"research_{self.session_id}.log"
        self.jsonl_path = self.output_dir / f"research_{self.session_id}.jsonl"
        self._lock = threading.Lock()
        self._seq = 0
        self._started = time.perf_counter()

    @staticmethod
    def _sanitize(value):
        if isinstance(value, dict):
            out = {}
            for key, item in value.items():
                key_s = str(key)
                # Cinturón de seguridad: nunca escribir secretos directos aunque
                # una llamada futura al logger los pase por error.
                if key_s.lower() in {
                    "mnemonic",
                    "passphrase",
                    "password",
                    "private_key",
                    "private_key_hex",
                    "stored_seed",
                    "seed_bytes",
                    "entropy",
                    "entropy_bytes",
                    "kdf_key",
                    "blob_key",
                }:
                    out[key_s] = "<REDACTED>"
                else:
                    out[key_s] = ResearchLogger._sanitize(item)
            return out
        if isinstance(value, (list, tuple)):
            return [ResearchLogger._sanitize(v) for v in value]
        if isinstance(value, bytes):
            return {"bytes": len(value), "sha256": _sha256_hex(value)}
        return value

    def event(
        self,
        event: str,
        *,
        details: dict | None = None,
        candidate: str | None = None,
        level: str = "INFO",
    ) -> dict:
        safe_details = self._sanitize(details or {})
        with self._lock:
            self._seq += 1
            record = {
                "format": RESEARCH_LOG_FORMAT,
                "session_id": self.session_id,
                "seq": self._seq,
                "utc": _utc_now_iso(),
                "elapsed_ms": round((time.perf_counter() - self._started) * 1000, 3),
                "level": level,
                "thread": threading.current_thread().name,
                "candidate": candidate,
                "event": event,
                "details": safe_details,
            }
            json_line = json.dumps(record, ensure_ascii=False, sort_keys=True)
            with self.jsonl_path.open("a", encoding="utf-8", newline="\n") as fh:
                fh.write(json_line + "\n")
                fh.flush()
            details_text = json.dumps(safe_details, ensure_ascii=False, sort_keys=True)
            with self.text_path.open("a", encoding="utf-8", newline="\n") as fh:
                fh.write(
                    f"[{record['seq']:06d}] {record['utc']} {level:<5} "
                    f"{event} candidate={candidate or '-'} {details_text}\n"
                )
                fh.flush()
            return record

    def paths(self) -> tuple[str, str]:
        return str(self.text_path), str(self.jsonl_path)


def estimate_scrypt_memory_bytes(n: int, r: int, p: int) -> int:
    """Estimación conservadora de memoria para scrypt.

    La parte dominante es ~128 * N * r. Añadimos el término de trabajo
    paralelo y un margen fijo para estructuras internas de OpenSSL.
    """
    n = int(n)
    r = int(r)
    p = int(p)
    if n <= 1 or (n & (n - 1)) != 0:
        raise ValueError(f"Parámetro scrypt N inválido: {n}; debe ser potencia de 2 > 1.")
    if r <= 0 or p <= 0:
        raise ValueError("Los parámetros scrypt r y p deben ser positivos.")

    dominant = 128 * n * r
    parallel_work = 256 * r * p
    return dominant + parallel_work


def scrypt_maxmem_for_params(n: int, r: int, p: int) -> int:
    """Calcula un maxmem explícito que evita el límite implícito de OpenSSL."""
    estimated = estimate_scrypt_memory_bytes(n, r, p)
    # Margen: al menos 32 MiB, o 12.5 % de la memoria dominante.
    margin = max(32 * 1024 * 1024, estimated // 8)
    requested = max(SCRYPT_MIN_MAXMEM, estimated + margin)

    if requested > SCRYPT_ABSOLUTE_SAFETY_LIMIT:
        raise ValueError(
            "Los parámetros scrypt del backup requieren aproximadamente "
            f"{estimated / (1024**3):.2f} GiB de RAM por descifrado. "
            "Se supera el límite de seguridad configurado (1.5 GiB por tarea)."
        )
    if requested >= SCRYPT_OPENSSL_MAXMEM:
        raise ValueError(
            "Los parámetros scrypt requieren más memoria de la que permite "
            "la interfaz hashlib/OpenSSL de esta aplicación."
        )
    return int(requested)


def scrypt_derive(
    password: bytes,
    *,
    salt: bytes,
    n: int,
    r: int,
    p: int,
    dklen: int = 32,
) -> bytes:
    """scrypt con maxmem explícito para evitar falsos 'formato incompatible'."""
    maxmem = scrypt_maxmem_for_params(n, r, p)
    try:
        return hashlib.scrypt(
            password,
            salt=salt,
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=int(dklen),
            maxmem=maxmem,
        )
    except ValueError as exc:
        msg = str(exc).lower()
        if "memory limit exceeded" in msg:
            estimated = estimate_scrypt_memory_bytes(n, r, p)
            raise ValueError(
                "OpenSSL rechazó scrypt por memoria pese al maxmem explícito. "
                f"Parámetros: N={n}, r={r}, p={p}; estimación ≈ "
                f"{estimated / (1024**2):.1f} MiB por tarea. "
                "Prueba con 1 worker y asegúrate de disponer de RAM suficiente."
            ) from exc
        raise


def effective_worker_count_for_candidates(candidates, requested_workers: int) -> tuple[int, int]:
    """Reduce workers when SECO scrypt parameters are memory-heavy.

    Returns (effective_workers, largest_maxmem_bytes). Invalid candidates are
    ignored here and will be reported normally during processing.
    """
    requested_workers = max(1, min(4, int(requested_workers)))
    largest = 0
    for candidate in candidates:
        try:
            info = parse_seco(candidate[1])
            largest = max(
                largest,
                scrypt_maxmem_for_params(info["n"], info["r"], info["p"]),
            )
        except Exception:
            continue

    if largest <= 0:
        return requested_workers, 0

    memory_limit = max(1, SCRYPT_PARALLEL_MEMORY_BUDGET // largest)
    return min(requested_workers, int(memory_limit)), largest


def normalize_eth_address(addr: str) -> str:
    addr = (addr or "").strip()
    if not ETH_ADDRESS_RE.fullmatch(addr):
        raise ValueError("La dirección Ethereum no tiene formato 0x + 40 hexadecimales.")
    return addr.lower()


def keccak256(data: bytes) -> bytes:
    h = keccak.new(digest_bits=256)
    h.update(data)
    return h.digest()


def ser32(i: int) -> bytes:
    return i.to_bytes(4, "big")


def ser256(i: int) -> bytes:
    return i.to_bytes(32, "big")


def compressed_pubkey_from_priv(priv_int: int) -> bytes:
    priv = ec.derive_private_key(priv_int, ec.SECP256K1())
    nums = priv.public_key().public_numbers()
    prefix = 2 + (nums.y & 1)
    return bytes([prefix]) + nums.x.to_bytes(32, "big")


def eth_address_from_priv(priv_int: int) -> str:
    priv = ec.derive_private_key(priv_int, ec.SECP256K1())
    nums = priv.public_key().public_numbers()
    raw_pub = nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big")
    digest = keccak256(raw_pub)
    return "0x" + digest[-20:].hex()


def bip32_master(seed: bytes):
    i = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    k = int.from_bytes(i[:32], "big")
    c = i[32:]
    if k == 0 or k >= SECP256K1_N:
        raise ValueError("Master key BIP32 inválida.")
    return k, c


def ckd_priv(k_parent: int, c_parent: bytes, index: int):
    if index >= HARDENED:
        data = b"\x00" + ser256(k_parent) + ser32(index)
    else:
        data = compressed_pubkey_from_priv(k_parent) + ser32(index)

    i = hmac.new(c_parent, data, hashlib.sha512).digest()
    il = int.from_bytes(i[:32], "big")
    child = (il + k_parent) % SECP256K1_N
    if il >= SECP256K1_N or child == 0:
        raise ValueError("Child key BIP32 inválida.")
    return child, i[32:]


def parse_bip32_path(path: str) -> list[int]:
    """Convierte m/44'/60'/0'/0/0 en índices BIP-32."""
    text = (path or "").strip()
    if text in {"m", "M"}:
        return []
    if not text.startswith(("m/", "M/")):
        raise ValueError(f"Ruta BIP-32 inválida: {path!r}")

    out: list[int] = []
    for part in text[2:].split("/"):
        part = part.strip()
        if not part:
            raise ValueError(f"Ruta BIP-32 inválida: {path!r}")

        hardened = part.endswith(("'", "h", "H"))
        if hardened:
            part = part[:-1]
        if not part.isdigit():
            raise ValueError(f"Componente BIP-32 inválido en {path!r}")

        value = int(part)
        if value < 0 or value >= HARDENED:
            raise ValueError(f"Índice BIP-32 fuera de rango en {path!r}")
        out.append(value | HARDENED if hardened else value)
    return out


def derive_eth_path(seed: bytes, path: str):
    """Deriva una clave/dirección Ethereum para una ruta BIP-32/BIP-44."""
    k, c = bip32_master(seed)
    for idx in parse_bip32_path(path):
        k, c = ckd_priv(k, c, idx)
    return k, eth_address_from_priv(k)


def derive_eth_exodus(seed: bytes):
    """Compatibilidad: Exodus Ethereum default m/44'/60'/0'/0/0."""
    return derive_eth_path(seed, DEFAULT_ETH_PATH)


def build_eth_paths(
    account_max: int = 0,
    address_index_max: int = 0,
    custom_paths: str | list[str] | tuple[str, ...] | None = None,
) -> list[str]:
    """
    Genera rutas m/44'/60'/account'/0/index y añade rutas personalizadas.
    El total se limita para evitar búsquedas accidentales enormes.
    """
    if not (0 <= account_max <= 50):
        raise ValueError("account_max debe estar entre 0 y 50.")
    if not (0 <= address_index_max <= 100):
        raise ValueError("address_index_max debe estar entre 0 y 100.")

    paths = [
        f"m/44'/60'/{account}'/0/{index}"
        for account in range(account_max + 1)
        for index in range(address_index_max + 1)
    ]

    if custom_paths:
        if isinstance(custom_paths, str):
            extras = re.split(r"[,;\n]+", custom_paths)
        else:
            extras = list(custom_paths)
        for p in extras:
            p = (p or "").strip()
            if not p:
                continue
            parse_bip32_path(p)  # validar
            if p not in paths:
                paths.append(p)

    if len(paths) > MAX_DERIVATION_PATHS:
        raise ValueError(
            f"Demasiadas rutas ({len(paths)}). Máximo permitido: {MAX_DERIVATION_PATHS}."
        )
    return paths


def parse_seco(file_bytes: bytes):
    if len(file_bytes) < HEADER_SIZE + CHECKSUM_SIZE + METADATA_SIZE + 4:
        raise ValueError("seed.seco demasiado pequeño.")
    if file_bytes[:4] != b"SECO":
        raise ValueError("No es un contenedor SECO.")

    version = struct.unpack(">L", file_bytes[4:8])[0]
    if version != 0:
        raise ValueError(f"Versión SECO no soportada: {version}")

    checksum = file_bytes[HEADER_SIZE:HEADER_SIZE + CHECKSUM_SIZE]
    meta_start = HEADER_SIZE + CHECKSUM_SIZE
    meta = file_bytes[meta_start:meta_start + METADATA_SIZE]

    pos = 0
    salt = meta[pos:pos + 32]
    pos += 32
    n, r, p = struct.unpack(">LLL", meta[pos:pos + 12])
    pos += 12
    cipher = meta[pos:pos + 32].rstrip(b"\x00").decode("ascii", errors="strict")
    pos += 32
    bk_iv = meta[pos:pos + 12]
    pos += 12
    bk_tag = meta[pos:pos + 16]
    pos += 16
    bk_ciphertext = meta[pos:pos + 32]
    pos += 32
    blob_iv = meta[pos:pos + 12]
    pos += 12
    blob_tag = meta[pos:pos + 16]
    pos += 16

    if cipher != "aes-256-gcm":
        raise ValueError(f"Cifrado SECO no soportado: {cipher}")

    blob_len_pos = meta_start + METADATA_SIZE
    blob_len = struct.unpack(">L", file_bytes[blob_len_pos:blob_len_pos + 4])[0]
    blob = file_bytes[blob_len_pos + 4:blob_len_pos + 4 + blob_len]
    if len(blob) != blob_len:
        raise ValueError("Blob SECO truncado.")

    digest = hashlib.sha256(meta + struct.pack(">L", blob_len) + blob).digest()
    if not hmac.compare_digest(digest, checksum):
        raise ValueError("Checksum SECO inválido: el archivo puede estar corrupto.")

    return {
        "salt": salt,
        "n": n,
        "r": r,
        "p": p,
        "bk_iv": bk_iv,
        "bk_tag": bk_tag,
        "bk_ciphertext": bk_ciphertext,
        "blob_iv": blob_iv,
        "blob_tag": blob_tag,
        "blob": blob,
    }


def decrypt_seed_seco(
    seed_seco: bytes,
    passphrase_text: str,
    *,
    research_logger: ResearchLogger | None = None,
    candidate_label: str | None = None,
) -> bytes:
    info = parse_seco(seed_seco)

    if research_logger:
        research_logger.event(
            "seco_parse_ok",
            candidate=candidate_label,
            details={
                "container_bytes": len(seed_seco),
                "container_sha256": _sha256_hex(seed_seco),
                "cipher": "aes-256-gcm",
                "checksum_valid": True,
                "scrypt_n": info["n"],
                "scrypt_r": info["r"],
                "scrypt_p": info["p"],
                "scrypt_estimated_memory_bytes": estimate_scrypt_memory_bytes(
                    info["n"], info["r"], info["p"]
                ),
                "scrypt_maxmem_bytes": scrypt_maxmem_for_params(
                    info["n"], info["r"], info["p"]
                ),
                "encrypted_blob_bytes": len(info["blob"]),
            },
        )

    # Exodus guarda la passphrase de sistema como texto Base64 dentro del JSON.
    # El secure-container recibe la CADENA UTF-8, no los bytes resultantes
    # de decodificar Base64. Esta passphrase procede del passphrase.json
    # emparejado dentro del backup/export; NO es una contraseña introducida
    # manualmente en esta aplicación.
    passphrase_bytes = passphrase_text.encode("utf-8")

    if research_logger:
        research_logger.event(
            "scrypt_start",
            candidate=candidate_label,
            details={
                "credential_source": "paired passphrase.json from backup/export",
                "operator_wallet_password_prompted": False,
                "passphrase_length_chars": len(passphrase_text),
                "passphrase_sha256": _sha256_hex(passphrase_bytes),
                "passphrase_looks_base64": _looks_base64_text(passphrase_text),
                "n": info["n"],
                "r": info["r"],
                "p": info["p"],
                "dklen": 32,
            },
        )

    t0 = time.perf_counter()
    kdf_key = scrypt_derive(
        passphrase_bytes,
        salt=info["salt"],
        n=info["n"],
        r=info["r"],
        p=info["p"],
        dklen=32,
    )
    if research_logger:
        research_logger.event(
            "scrypt_ok",
            candidate=candidate_label,
            details={
                "elapsed_ms": round((time.perf_counter() - t0) * 1000, 3),
                "derived_key_bytes": len(kdf_key),
                "derived_key_redacted": True,
            },
        )

    t1 = time.perf_counter()
    blob_key = AESGCM(kdf_key).decrypt(
        info["bk_iv"],
        info["bk_ciphertext"] + info["bk_tag"],
        None,
    )
    if research_logger:
        research_logger.event(
            "aes_gcm_blob_key_ok",
            candidate=candidate_label,
            details={
                "elapsed_ms": round((time.perf_counter() - t1) * 1000, 3),
                "blob_key_bytes": len(blob_key),
                "blob_key_redacted": True,
                "authentication_tag_verified": True,
            },
        )

    t2 = time.perf_counter()
    plaintext = AESGCM(blob_key).decrypt(
        info["blob_iv"],
        info["blob"] + info["blob_tag"],
        None,
    )
    if research_logger:
        research_logger.event(
            "aes_gcm_payload_ok",
            candidate=candidate_label,
            details={
                "elapsed_ms": round((time.perf_counter() - t2) * 1000, 3),
                "plaintext_bytes": len(plaintext),
                "plaintext_sha256": _sha256_hex(plaintext),
                "authentication_tag_verified": True,
            },
        )
    return plaintext


def unpack_exodus_seed_payload(plaintext: bytes) -> bytes:
    """
    En los seed.seco analizados:
      [4 bytes big-endian longitud gzip] + [gzip] + [padding]
    El contenido gzip descomprime a:
      64 bytes BIP39 seed + N bytes BIP39 entropy
    """
    if len(plaintext) < 8:
        raise ValueError("Payload descifrado demasiado corto.")

    gzip_len = struct.unpack(">L", plaintext[:4])[0]
    if gzip_len <= 0 or gzip_len > len(plaintext) - 4:
        raise ValueError("Longitud gzip inválida en seed.seco.")

    compressed = plaintext[4:4 + gzip_len]
    raw = zlib.decompress(compressed, 31)

    if len(raw) < 64 + 16:
        raise ValueError(f"Objeto seed serializado inesperado ({len(raw)} bytes).")
    return raw


def entropy_to_mnemonic(entropy: bytes) -> str:
    if len(entropy) not in (16, 20, 24, 28, 32):
        raise ValueError(
            f"Longitud de entropía BIP39 no válida: {len(entropy)} bytes "
            "(esperado 16/20/24/28/32)."
        )
    return Mnemonic("english").to_mnemonic(entropy)


def verify_mnemonic_seed(mnemonic: str, stored_seed: bytes) -> bool:
    calc = Mnemonic.to_seed(mnemonic, passphrase="")
    return hmac.compare_digest(calc, stored_seed)


def read_passphrase_json(data: bytes) -> str:
    obj = json.loads(data.decode("utf-8-sig"))
    pp = obj.get("passphrase")
    if not isinstance(pp, str) or not pp:
        raise ValueError("passphrase.json no contiene un campo 'passphrase' válido.")
    return pp


def zip_candidates(zip_path: str):
    """Devuelve (label, seed_bytes, passphrase_json_bytes)."""
    with zipfile.ZipFile(zip_path, "r") as zf:
        names = set(zf.namelist())
        for name in sorted(names):
            if not name.endswith("seed.seco"):
                continue
            directory = name.rsplit("/", 1)[0] if "/" in name else ""
            pp_name = (directory + "/passphrase.json") if directory else "passphrase.json"
            if pp_name in names:
                yield name, zf.read(name), zf.read(pp_name)


def folder_candidates(folder_path: str):
    root = Path(folder_path)
    for seed_path in sorted(root.rglob("seed.seco")):
        pp = seed_path.parent / "passphrase.json"
        if pp.exists():
            yield str(seed_path.relative_to(root)), seed_path.read_bytes(), pp.read_bytes()


def extract_eth_addresses_from_csv(
    csv_path: str,
    max_unique: int | None = None,
    max_rows: int | None = None,
):
    """
    Extrae y cuenta direcciones Ethereum de forma streaming.

    Por defecto analiza TODO el CSV para mantener el ranking correcto.
    max_unique activa un early-exit voluntario; el resultado será entonces parcial.
    """
    if max_unique is not None and max_unique <= 0:
        raise ValueError("max_unique debe ser positivo o None.")
    if max_rows is not None and max_rows <= 0:
        raise ValueError("max_rows debe ser positivo o None.")

    counts = Counter()
    with open(csv_path, "r", encoding="utf-8-sig", errors="replace", newline="") as f:
        for row_num, row in enumerate(csv.reader(f), start=1):
            for cell in row:
                for addr in ETH_ADDRESS_RE.findall(cell or ""):
                    counts[addr.lower()] += 1
                    if max_unique is not None and len(counts) >= max_unique:
                        return counts
            if max_rows is not None and row_num >= max_rows:
                break
    return counts


def _derive_addresses_cached(
    stored_seed: bytes,
    paths: list[str],
    cache: dict[bytes, tuple[tuple[str, str], ...]],
    lock: threading.Lock,
    *,
    research_logger: ResearchLogger | None = None,
    candidate_label: str | None = None,
) -> tuple[tuple[str, str], ...]:
    """Caché por SHA-256(seed); no conserva el seed como clave."""
    key = hashlib.sha256(stored_seed).digest()
    key_hex = key.hex()
    with lock:
        cached = cache.get(key)
    if cached is not None:
        if research_logger:
            research_logger.event(
                "derivation_cache_hit",
                candidate=candidate_label,
                details={
                    "seed_sha256": key_hex,
                    "paths_reused": len(cached),
                },
            )
            for path, addr in cached:
                research_logger.event(
                    "ethereum_path_reused",
                    candidate=candidate_label,
                    details={"path": path, "derived_address": addr},
                )
        return cached

    if research_logger:
        research_logger.event(
            "derivation_cache_miss",
            candidate=candidate_label,
            details={"seed_sha256": key_hex, "paths_to_derive": len(paths)},
        )

    derived_items: list[tuple[str, str]] = []
    for ordinal, path in enumerate(paths, start=1):
        t0 = time.perf_counter()
        _priv, addr = derive_eth_path(stored_seed, path)
        derived_items.append((path, addr))
        if research_logger:
            research_logger.event(
                "ethereum_path_derived",
                candidate=candidate_label,
                details={
                    "ordinal": ordinal,
                    "total_paths": len(paths),
                    "path": path,
                    "derived_address": addr,
                    "elapsed_ms": round((time.perf_counter() - t0) * 1000, 3),
                    "private_key_redacted": True,
                },
            )

    derived = tuple(derived_items)
    with lock:
        return cache.setdefault(key, derived)


def process_candidate(
    candidate,
    target: str,
    paths: list[str],
    expected_words: int | None,
    derivation_cache: dict[bytes, tuple[tuple[str, str], ...]],
    cache_lock: threading.Lock,
    research_logger: ResearchLogger | None = None,
):
    label, seed_bytes, pp_bytes = candidate
    pp_label = _passphrase_label_for_seed_label(label)

    if research_logger:
        research_logger.event(
            "candidate_start",
            candidate=label,
            details={
                "seed_path": label,
                "passphrase_path": pp_label,
                "seed_file_bytes": len(seed_bytes),
                "seed_file_sha256": _sha256_hex(seed_bytes),
                "passphrase_json_bytes": len(pp_bytes),
                "passphrase_json_sha256": _sha256_hex(pp_bytes),
                "target_address": target,
                "expected_words": expected_words,
                "paths_configured": len(paths),
            },
        )

    pp = read_passphrase_json(pp_bytes)
    if research_logger:
        research_logger.event(
            "passphrase_json_read",
            candidate=label,
            details={
                "passphrase_path": pp_label,
                "field_present": True,
                "credential_source": "paired passphrase.json from backup/export",
                "operator_wallet_password_prompted": False,
                "passphrase_value_redacted": True,
                "passphrase_length_chars": len(pp),
                "passphrase_sha256": _sha256_hex(pp.encode("utf-8")),
                "passphrase_looks_base64": _looks_base64_text(pp),
            },
        )

    plain = decrypt_seed_seco(
        seed_bytes,
        pp,
        research_logger=research_logger,
        candidate_label=label,
    )

    if research_logger:
        gzip_len = struct.unpack(">L", plain[:4])[0] if len(plain) >= 4 else None
        research_logger.event(
            "seed_payload_unpack_start",
            candidate=label,
            details={
                "decrypted_payload_bytes": len(plain),
                "declared_gzip_bytes": gzip_len,
            },
        )

    raw = unpack_exodus_seed_payload(plain)
    stored_seed = raw[:64]
    entropy = raw[64:]

    if research_logger:
        research_logger.event(
            "seed_payload_unpack_ok",
            candidate=label,
            details={
                "decompressed_bytes": len(raw),
                "stored_bip39_seed_bytes": len(stored_seed),
                "stored_bip39_seed_sha256": _sha256_hex(stored_seed),
                "entropy_length_bytes": len(entropy),
                "entropy_bits": len(entropy) * 8,
                "entropy_sha256": _sha256_hex(entropy),
                "secret_material_redacted": True,
            },
        )

    mnemonic = entropy_to_mnemonic(entropy)
    words = mnemonic.split()
    word_count = len(words)

    if research_logger:
        research_logger.event(
            "bip39_mnemonic_reconstructed",
            candidate=label,
            details={
                "word_count": word_count,
                "mnemonic_sha256": _sha256_hex(mnemonic.encode("utf-8")),
                "mnemonic_redacted": True,
                "bip39_language": "english",
            },
        )

    if word_count not in VALID_BIP39_WORD_COUNTS:
        raise ValueError(f"Número de palabras BIP-39 inesperado: {word_count}")

    if expected_words is not None and word_count != expected_words:
        if research_logger:
            research_logger.event(
                "candidate_filtered_by_word_count",
                candidate=label,
                details={
                    "actual_words": word_count,
                    "expected_words": expected_words,
                    "entropy_bits": len(entropy) * 8,
                },
            )
        return {
            "label": label,
            "status": "word-count-skip",
            "words": word_count,
            "entropy_bits": len(entropy) * 8,
        }

    # Mejora de corrección: no se acepta una frase si no reproduce el seed almacenado.
    bip39_ok = verify_mnemonic_seed(mnemonic, stored_seed)
    if research_logger:
        research_logger.event(
            "bip39_seed_verification",
            candidate=label,
            details={
                "verified": bip39_ok,
                "stored_seed_sha256": _sha256_hex(stored_seed),
                "mnemonic_redacted": True,
            },
        )
    if not bip39_ok:
        return {
            "label": label,
            "status": "bip39-seed-mismatch",
            "words": word_count,
            "entropy_bits": len(entropy) * 8,
        }

    derived = _derive_addresses_cached(
        stored_seed,
        paths,
        derivation_cache,
        cache_lock,
        research_logger=research_logger,
        candidate_label=label,
    )
    matching_paths = [
        path for path, addr in derived
        if hmac.compare_digest(addr.lower(), target)
    ]

    if research_logger:
        research_logger.event(
            "target_comparison_complete",
            candidate=label,
            details={
                "target_address": target,
                "tested_paths": len(derived),
                "matching_paths": matching_paths,
                "match": bool(matching_paths),
            },
        )

    if matching_paths:
        if research_logger:
            research_logger.event(
                "candidate_match",
                candidate=label,
                details={
                    "seed_source": label,
                    "credential_source": pp_label,
                    "target_address": target,
                    "matching_paths": matching_paths,
                    "word_count": word_count,
                    "mnemonic_redacted": True,
                },
            )
        return {
            "label": label,
            "status": "match",
            "mnemonic": mnemonic,
            "words": word_count,
            "entropy_bits": len(entropy) * 8,
            "address": target,
            "paths": matching_paths,
            "bip39_ok": True,
            "credential_source": pp_label,
        }

    if research_logger:
        research_logger.event(
            "candidate_no_match",
            candidate=label,
            details={
                "word_count": word_count,
                "entropy_bits": len(entropy) * 8,
                "tested_paths": len(derived),
            },
        )
    return {
        "label": label,
        "status": "no-match",
        "words": word_count,
        "entropy_bits": len(entropy) * 8,
        "tested_paths": len(derived),
    }


def encrypt_export_payload(payload: dict, password: str) -> dict:
    """Devuelve un sobre JSON cifrado con scrypt + AES-256-GCM."""
    if not password or len(password) < 10:
        raise ValueError("La contraseña de exportación debe tener al menos 10 caracteres.")

    salt = os.urandom(16)
    nonce = os.urandom(12)
    n, r, p = 2**15, 8, 1
    key = scrypt_derive(
        password.encode("utf-8"),
        salt=salt,
        n=n,
        r=r,
        p=p,
        dklen=32,
    )
    plaintext = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    aad = EXPORT_FORMAT.encode("ascii")
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
    return {
        "format": EXPORT_FORMAT,
        "kdf": {"name": "scrypt", "n": n, "r": r, "p": p, "dklen": 32},
        "cipher": "AES-256-GCM",
        "salt_b64": base64.b64encode(salt).decode("ascii"),
        "nonce_b64": base64.b64encode(nonce).decode("ascii"),
        "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"),
    }


def decrypt_export_payload(envelope: dict, password: str) -> dict:
    """Función complementaria para recuperar un export cifrado v1."""
    if envelope.get("format") != EXPORT_FORMAT:
        raise ValueError("Formato de exportación no soportado.")
    kdf = envelope.get("kdf") or {}
    if kdf.get("name") != "scrypt":
        raise ValueError("KDF no soportado.")
    salt = base64.b64decode(envelope["salt_b64"])
    nonce = base64.b64decode(envelope["nonce_b64"])
    ciphertext = base64.b64decode(envelope["ciphertext_b64"])
    key = scrypt_derive(
        password.encode("utf-8"),
        salt=salt,
        n=int(kdf["n"]),
        r=int(kdf["r"]),
        p=int(kdf["p"]),
        dklen=int(kdf.get("dklen", 32)),
    )
    plaintext = AESGCM(key).decrypt(
        nonce,
        ciphertext,
        EXPORT_FORMAT.encode("ascii"),
    )
    return json.loads(plaintext.decode("utf-8"))


class RecoveryApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Exodus BIP39 Research Recovery Tool — LOCAL — v0.3.0")
        self.geometry("1120x960")
        self.minsize(930, 720)

        self.source_var = tk.StringVar()
        self.target_var = tk.StringVar()
        self.status_var = tk.StringVar(value="Preparado.")
        self.expected_words_var = tk.StringVar(value="24")
        self.workers_var = tk.IntVar(value=max(1, min(2, os.cpu_count() or 1)))
        self.account_max_var = tk.IntVar(value=0)
        self.address_index_max_var = tk.IntVar(value=9)
        self.custom_paths_var = tk.StringVar(value="")
        self.csv_quick_var = tk.BooleanVar(value=False)
        self.log_dir_var = tk.StringVar(value=str(Path.cwd() / "research_logs"))

        self.matches: list[dict] = []
        self._last_research_log_paths: tuple[str, str] | None = None
        self._last_target = ""
        self._last_paths: list[str] = []
        self._event_queue: queue.Queue = queue.Queue()
        self._worker_thread: threading.Thread | None = None

        self._build_ui()
        self.after(100, self._poll_events)

    def _build_ui(self):
        pad = {"padx": 8, "pady": 5}

        title = ttk.Label(
            self,
            text="Recuperación local BIP-39 desde backups propios/autorizados de Exodus",
            font=("Segoe UI", 15, "bold"),
        )
        title.pack(pady=(12, 3))

        warning = ttk.Label(
            self,
            text=(
                "Modo por defecto: 24 palabras (256 bits). Todo se procesa localmente. "
                "Se genera un log forense .log + .jsonl. Frase, passphrase, seed y claves privadas "
                "NO se escriben en el log; se registran huellas SHA-256 y metadatos."
            ),
            wraplength=1040,
        )
        warning.pack(pady=(0, 8))

        frm = ttk.LabelFrame(self, text="1. Datos de entrada")
        frm.pack(fill="x", padx=14, pady=5)

        ttk.Label(frm, text="ZIP de Exodus o carpeta raíz:").grid(row=0, column=0, sticky="w", **pad)
        ttk.Entry(frm, textvariable=self.source_var, width=78).grid(row=0, column=1, columnspan=3, sticky="ew", **pad)
        ttk.Button(frm, text="Seleccionar ZIP", command=self.pick_zip).grid(row=0, column=4, **pad)
        ttk.Button(frm, text="Seleccionar carpeta", command=self.pick_folder).grid(row=0, column=5, **pad)

        ttk.Label(frm, text="Dirección Ethereum objetivo:").grid(row=1, column=0, sticky="w", **pad)
        ttk.Entry(frm, textvariable=self.target_var, width=54).grid(row=1, column=1, columnspan=2, sticky="ew", **pad)
        ttk.Button(frm, text="Detectar desde CSV", command=self.pick_csv).grid(row=1, column=3, **pad)
        ttk.Checkbutton(
            frm,
            text="CSV rápido (máx. 500 únicas; ranking parcial)",
            variable=self.csv_quick_var,
        ).grid(row=1, column=4, columnspan=2, sticky="w", **pad)

        ttk.Label(frm, text="Palabras BIP-39 esperadas:").grid(row=2, column=0, sticky="w", **pad)
        wc = ttk.Combobox(
            frm,
            textvariable=self.expected_words_var,
            values=("24", "Cualquiera", "12", "15", "18", "21"),
            width=12,
            state="readonly",
        )
        wc.grid(row=2, column=1, sticky="w", **pad)

        ttk.Label(frm, text="Workers paralelos:").grid(row=2, column=2, sticky="e", **pad)
        ttk.Spinbox(frm, from_=1, to=4, textvariable=self.workers_var, width=5).grid(row=2, column=3, sticky="w", **pad)
        ttk.Label(
            frm,
            text="Recomendado: 1–2. scrypt puede consumir bastante RAM.",
        ).grid(row=2, column=4, columnspan=2, sticky="w", **pad)

        ttk.Label(frm, text="Carpeta de logs de investigación:").grid(row=3, column=0, sticky="w", **pad)
        ttk.Entry(frm, textvariable=self.log_dir_var, width=78).grid(
            row=3, column=1, columnspan=3, sticky="ew", **pad
        )
        ttk.Button(frm, text="Seleccionar carpeta", command=self.pick_log_folder).grid(
            row=3, column=4, **pad
        )
        ttk.Label(
            frm,
            text="Genera automáticamente un .log legible y un .jsonl estructurado.",
        ).grid(row=3, column=5, sticky="w", **pad)

        frm.columnconfigure(1, weight=1)
        frm.columnconfigure(2, weight=1)

        pathfrm = ttk.LabelFrame(self, text="2. Rutas Ethereum de verificación")
        pathfrm.pack(fill="x", padx=14, pady=5)

        ttk.Label(pathfrm, text="Cuenta máxima (account'):").grid(row=0, column=0, sticky="w", **pad)
        ttk.Spinbox(pathfrm, from_=0, to=50, textvariable=self.account_max_var, width=6).grid(row=0, column=1, sticky="w", **pad)
        ttk.Label(pathfrm, text="Índice de dirección máximo:").grid(row=0, column=2, sticky="w", **pad)
        ttk.Spinbox(pathfrm, from_=0, to=100, textvariable=self.address_index_max_var, width=6).grid(row=0, column=3, sticky="w", **pad)
        ttk.Label(
            pathfrm,
            text="Genera m/44'/60'/account'/0/index. Por defecto prueba account 0, índices 0–9.",
        ).grid(row=0, column=4, sticky="w", **pad)

        ttk.Label(pathfrm, text="Rutas extra (opcional):").grid(row=1, column=0, sticky="w", **pad)
        ttk.Entry(pathfrm, textvariable=self.custom_paths_var).grid(row=1, column=1, columnspan=4, sticky="ew", **pad)
        ttk.Label(pathfrm, text="Separar por coma, ; o salto de línea.").grid(row=1, column=5, sticky="w", **pad)
        pathfrm.columnconfigure(4, weight=1)

        controls = ttk.Frame(self)
        controls.pack(fill="x", padx=14, pady=7)

        self.run_btn = ttk.Button(
            controls,
            text="RECUPERAR Y VERIFICAR",
            command=self.run_recovery,
        )
        self.run_btn.pack(side="left")

        ttk.Button(controls, text="Borrar resultado", command=self.clear_result).pack(side="left", padx=8)

        self.export_btn = ttk.Button(
            controls,
            text="Exportar resultado cifrado",
            command=self.export_encrypted_result,
            state="disabled",
        )
        self.export_btn.pack(side="left")

        self.open_logs_btn = ttk.Button(
            controls,
            text="Abrir carpeta de logs",
            command=self.open_log_folder,
            state="disabled",
        )
        self.open_logs_btn.pack(side="left", padx=8)

        ttk.Label(controls, textvariable=self.status_var).pack(side="right")

        pfrm = ttk.Frame(self)
        pfrm.pack(fill="x", padx=14, pady=(0, 4))
        self.progress = ttk.Progressbar(pfrm, mode="determinate", maximum=1, value=0)
        self.progress.pack(fill="x", expand=True)

        logfrm = ttk.LabelFrame(self, text="3. Progreso y comprobaciones")
        logfrm.pack(fill="both", expand=True, padx=14, pady=5)
        self.log = tk.Text(logfrm, height=15, wrap="word", font=("Consolas", 10))
        self.log.pack(fill="both", expand=True, padx=6, pady=6)

        resfrm = ttk.LabelFrame(self, text="4. Resultado LOCAL")
        resfrm.pack(fill="x", padx=14, pady=(5, 12))
        self.result = tk.Text(resfrm, height=10, wrap="word", font=("Consolas", 11, "bold"))
        self.result.pack(fill="x", padx=6, pady=6)
        self.result.insert(
            "1.0",
            "La frase solo aparecerá aquí si: (1) el seed BIP-39 reconstruido es exacto y "
            "(2) una ruta Ethereum probada coincide con la dirección objetivo.\n",
        )
        self.result.configure(state="disabled")

    def append_log(self, msg: str):
        self.log.insert("end", msg + "\n")
        self.log.see("end")

    def set_result(self, text: str):
        self.result.configure(state="normal")
        self.result.delete("1.0", "end")
        self.result.insert("1.0", text)
        self.result.configure(state="disabled")

    def clear_result(self):
        if self._worker_thread and self._worker_thread.is_alive():
            messagebox.showwarning("Proceso activo", "Espera a que termine el análisis actual.")
            return
        self.matches = []
        self._last_target = ""
        self._last_paths = []
        self.log.delete("1.0", "end")
        self.progress.configure(maximum=1, value=0)
        self.export_btn.configure(state="disabled")
        self._last_research_log_paths = None
        self.open_logs_btn.configure(state="disabled")
        self.set_result(
            "La frase solo aparecerá aquí si: (1) el seed BIP-39 reconstruido es exacto y "
            "(2) una ruta Ethereum probada coincide con la dirección objetivo.\n"
        )
        self.status_var.set("Preparado.")

    def pick_zip(self):
        p = filedialog.askopenfilename(
            title="Selecciona exodus.zip o un ZIP con backups",
            filetypes=[("ZIP", "*.zip"), ("Todos", "*.*")],
        )
        if p:
            self.source_var.set(p)

    def pick_folder(self):
        p = filedialog.askdirectory(title="Selecciona la carpeta raíz de Exodus/backups")
        if p:
            self.source_var.set(p)

    def pick_log_folder(self):
        p = filedialog.askdirectory(title="Selecciona dónde guardar los logs de investigación")
        if p:
            self.log_dir_var.set(p)

    def open_log_folder(self):
        if not self._last_research_log_paths:
            messagebox.showinfo("Logs", "Todavía no se ha generado ningún log de investigación.")
            return
        folder = str(Path(self._last_research_log_paths[0]).parent)
        try:
            if os.name == "nt":
                os.startfile(folder)  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                import subprocess
                subprocess.Popen(["open", folder])
            else:
                import subprocess
                subprocess.Popen(["xdg-open", folder])
        except Exception as exc:
            messagebox.showerror("Logs", f"No pude abrir la carpeta:\n{folder}\n\n{exc}")

    def pick_csv(self):
        p = filedialog.askopenfilename(
            title="Selecciona CSV de Exodus/Etherscan",
            filetypes=[("CSV", "*.csv"), ("Todos", "*.*")],
        )
        if not p:
            return
        try:
            quick = self.csv_quick_var.get()
            counts = extract_eth_addresses_from_csv(
                p,
                max_unique=500 if quick else None,
            )
        except Exception as exc:
            messagebox.showerror("CSV", str(exc))
            return

        if not counts:
            messagebox.showwarning("CSV", "No encontré direcciones Ethereum en el CSV.")
            return

        top = counts.most_common(20)
        win = tk.Toplevel(self)
        win.title("Direcciones encontradas en el CSV")
        win.geometry("800x450")
        label = "Selecciona una dirección propia como verificador."
        if quick:
            label += " MODO RÁPIDO: ranking parcial (primeras 500 direcciones únicas)."
        ttk.Label(win, text=label, wraplength=760).pack(pady=8)

        lb = tk.Listbox(win, width=110, height=14, font=("Consolas", 10))
        lb.pack(fill="both", expand=True, padx=10, pady=6)
        for addr, n in top:
            lb.insert("end", f"{addr}    apariciones={n}")

        def choose():
            sel = lb.curselection()
            if not sel:
                return
            self.target_var.set(top[sel[0]][0])
            win.destroy()

        ttk.Button(win, text="Usar esta dirección", command=choose).pack(pady=8)

    def _expected_words(self) -> int | None:
        value = self.expected_words_var.get().strip()
        if value.lower().startswith("cual"):
            return None
        n = int(value)
        if n not in VALID_BIP39_WORD_COUNTS:
            raise ValueError("Número de palabras BIP-39 no válido.")
        return n

    def run_recovery(self):
        if self._worker_thread and self._worker_thread.is_alive():
            messagebox.showwarning("Proceso activo", "Ya hay un análisis en curso.")
            return

        source = self.source_var.get().strip()
        if not source or not os.path.exists(source):
            messagebox.showerror("Fuente", "Selecciona un ZIP o carpeta existente.")
            return

        try:
            target = normalize_eth_address(self.target_var.get())
            expected_words = self._expected_words()
            workers = int(self.workers_var.get())
            if workers < 1 or workers > 4:
                raise ValueError("Workers debe estar entre 1 y 4.")
            account_max = int(self.account_max_var.get())
            index_max = int(self.address_index_max_var.get())
            paths = build_eth_paths(
                account_max,
                index_max,
                self.custom_paths_var.get(),
            )
            log_dir = self.log_dir_var.get().strip() or str(Path.cwd() / "research_logs")
        except Exception as exc:
            messagebox.showerror("Configuración", str(exc))
            return

        self.matches = []
        self._last_target = target
        self._last_paths = paths
        self.log.delete("1.0", "end")
        self.progress.configure(maximum=1, value=0)
        self.export_btn.configure(state="disabled")
        self._last_research_log_paths = None
        self.open_logs_btn.configure(state="disabled")
        self.set_result("Analizando...\n")
        self.run_btn.configure(state="disabled")
        self.status_var.set("Analizando...")

        self._worker_thread = threading.Thread(
            target=self._recovery_coordinator,
            args=(source, target, expected_words, workers, paths, log_dir),
            daemon=True,
        )
        self._worker_thread.start()

    def _recovery_coordinator(
        self,
        source: str,
        target: str,
        expected_words: int | None,
        workers: int,
        paths: list[str],
        log_dir: str,
    ):
        research_logger: ResearchLogger | None = None
        try:
            research_logger = ResearchLogger(log_dir)
            text_log, jsonl_log = research_logger.paths()
            self._event_queue.put(("research_log_paths", text_log, jsonl_log))
            research_logger.event(
                "session_start",
                details={
                    "app_version": APP_VERSION,
                    "python_version": sys.version.split()[0],
                    "platform": platform.platform(),
                    "source": str(Path(source).resolve()),
                    "source_kind": "zip" if os.path.isfile(source) else "folder",
                    "target_address": target,
                    "expected_words": expected_words,
                    "requested_workers": workers,
                    "ethereum_paths": paths,
                    "log_secrets_in_clear": False,
                    "important": (
                        "The application does not prompt for the Exodus UI password. "
                        "For each candidate it reads the paired passphrase.json from the export."
                    ),
                },
            )
            research_logger.event(
                "source_scan_start",
                details={"source": str(Path(source).resolve())},
            )
            if os.path.isfile(source) and source.lower().endswith(".zip"):
                candidates = list(zip_candidates(source))
            elif os.path.isdir(source):
                candidates = list(folder_candidates(source))
            else:
                raise ValueError("La fuente debe ser un ZIP o una carpeta.")

            if os.path.isfile(source):
                stat = os.stat(source)
                research_logger.event(
                    "source_file_fingerprint",
                    details={
                        "path": str(Path(source).resolve()),
                        "bytes": stat.st_size,
                        "mtime_ns": stat.st_mtime_ns,
                        "sha256": _sha256_file(source),
                    },
                )

            if not candidates:
                raise ValueError(
                    "No encontré pares seed.seco + passphrase.json dentro de la fuente."
                )

            total = len(candidates)
            research_logger.event(
                "source_scan_complete",
                details={"candidate_count": total},
            )
            for label, seed_bytes, pp_bytes in candidates:
                research_logger.event(
                    "candidate_discovered",
                    candidate=label,
                    details={
                        "seed_path": label,
                        "passphrase_path": _passphrase_label_for_seed_label(label),
                        "seed_file_bytes": len(seed_bytes),
                        "seed_file_sha256": _sha256_hex(seed_bytes),
                        "passphrase_json_bytes": len(pp_bytes),
                        "passphrase_json_sha256": _sha256_hex(pp_bytes),
                    },
                )

            effective_workers, largest_scrypt_maxmem = effective_worker_count_for_candidates(
                candidates, workers
            )
            research_logger.event(
                "execution_plan",
                details={
                    "candidate_count": total,
                    "requested_workers": workers,
                    "effective_workers": effective_workers,
                    "largest_scrypt_maxmem_bytes": largest_scrypt_maxmem,
                    "paths_per_seed": len(paths),
                },
            )
            self._event_queue.put(("setup", total))
            self._event_queue.put(("log", f"Backups candidatos encontrados: {total}"))
            self._event_queue.put((
                "log",
                "LOG FORENSE: cada paso se guarda en .log + .jsonl; secretos en claro = NO",
            ))
            self._event_queue.put(("log", f"Log texto: {text_log}"))
            self._event_queue.put(("log", f"Log JSONL: {jsonl_log}"))
            self._event_queue.put(("log", f"Dirección objetivo: {target}"))
            self._event_queue.put(("log", f"Rutas Ethereum a probar por seed: {len(paths)}"))
            self._event_queue.put(("log", "  " + "\n  ".join(paths[:20])))
            if len(paths) > 20:
                self._event_queue.put(("log", f"  ... y {len(paths)-20} rutas más"))
            if largest_scrypt_maxmem:
                self._event_queue.put((
                    "log",
                    "scrypt maxmem máximo por tarea: "
                    f"{largest_scrypt_maxmem / (1024**2):.1f} MiB",
                ))
            if effective_workers != workers:
                self._event_queue.put((
                    "log",
                    f"Workers solicitados: {workers} -> usados: {effective_workers} "
                    "(ajuste automático por memoria scrypt)",
                ))
            else:
                self._event_queue.put(("log", f"Workers: {effective_workers}"))
            self._event_queue.put(("log", ""))

            derivation_cache: dict[bytes, tuple[tuple[str, str], ...]] = {}
            cache_lock = threading.Lock()
            matches: list[dict] = []
            errors = 0
            skipped_words = 0
            seed_mismatches = 0
            completed = 0

            with ThreadPoolExecutor(max_workers=effective_workers, thread_name_prefix="exodus-recovery") as executor:
                futures = {
                    executor.submit(
                        process_candidate,
                        candidate,
                        target,
                        paths,
                        expected_words,
                        derivation_cache,
                        cache_lock,
                        research_logger,
                    ): candidate[0]
                    for candidate in candidates
                }

                for future in as_completed(futures):
                    label = futures[future]
                    completed += 1
                    try:
                        result = future.result()
                        status = result["status"]
                        words = result.get("words", "?")
                        bits = result.get("entropy_bits", "?")

                        if status == "match":
                            matches.append(result)
                            self._event_queue.put((
                                "log",
                                f"[{completed:03d}/{total:03d}] {label} | {bits} bits | "
                                f"{words} palabras | BIP39=OK | MATCH | "
                                f"ruta(s): {', '.join(result['paths'])}",
                            ))
                        elif status == "word-count-skip":
                            skipped_words += 1
                            self._event_queue.put((
                                "log",
                                f"[{completed:03d}/{total:03d}] {label} | {bits} bits | "
                                f"{words} palabras | omitido por filtro",
                            ))
                        elif status == "bip39-seed-mismatch":
                            seed_mismatches += 1
                            self._event_queue.put((
                                "log",
                                f"[{completed:03d}/{total:03d}] {label} | {bits} bits | "
                                "BIP39-seed=NO | no se acepta",
                            ))
                        else:
                            self._event_queue.put((
                                "log",
                                f"[{completed:03d}/{total:03d}] {label} | {bits} bits | "
                                f"{words} palabras | no match",
                            ))
                    except Exception as exc:
                        errors += 1
                        research_logger.event(
                            "candidate_error",
                            candidate=label,
                            level="ERROR",
                            details={
                                "exception_type": type(exc).__name__,
                                "message": str(exc),
                                "traceback": traceback.format_exc(),
                            },
                        )
                        self._event_queue.put((
                            "log",
                            f"[{completed:03d}/{total:03d}] {label} | ERROR: {exc}",
                        ))
                    finally:
                        self._event_queue.put(("progress", completed, total))

            research_logger.event(
                "session_complete",
                details={
                    "candidate_count": total,
                    "matches": len(matches),
                    "errors": errors,
                    "word_count_skips": skipped_words,
                    "bip39_seed_mismatches": seed_mismatches,
                    "unique_seed_derivations_cached": len(derivation_cache),
                    "matched_candidates": [m["label"] for m in matches],
                    "matched_paths": sorted({p for m in matches for p in m.get("paths", [])}),
                    "target_address": target,
                },
            )
            self._event_queue.put(("log", ""))
            self._event_queue.put((
                "log",
                "Finalizado. "
                f"Coincidencias: {len(matches)} | errores: {errors} | "
                f"omitidos por nº palabras: {skipped_words} | "
                f"seed BIP39 no reproducido: {seed_mismatches} | "
                f"seeds derivadas en caché: {len(derivation_cache)}",
            ))
            self._event_queue.put(("done", matches, target))

        except Exception as exc:
            if research_logger is not None:
                research_logger.event(
                    "session_fatal_error",
                    level="ERROR",
                    details={
                        "exception_type": type(exc).__name__,
                        "message": str(exc),
                        "traceback": traceback.format_exc(),
                    },
                )
            self._event_queue.put(("fatal", str(exc)))

    def _poll_events(self):
        try:
            while True:
                event = self._event_queue.get_nowait()
                kind = event[0]

                if kind == "setup":
                    total = event[1]
                    self.progress.configure(maximum=max(1, total), value=0)
                elif kind == "log":
                    self.append_log(event[1])
                elif kind == "progress":
                    completed, total = event[1], event[2]
                    self.progress.configure(maximum=max(1, total), value=completed)
                    self.status_var.set(f"Analizando... {completed}/{total}")
                elif kind == "research_log_paths":
                    self._last_research_log_paths = (event[1], event[2])
                    self.open_logs_btn.configure(state="normal")
                elif kind == "done":
                    self._finish_success(event[1], event[2])
                elif kind == "fatal":
                    self.run_btn.configure(state="normal")
                    self.export_btn.configure(state="disabled")
                    self.status_var.set("Error.")
                    self.set_result("ERROR. Revisa el registro de progreso.\n")
                    messagebox.showerror("Error", event[1])
        except queue.Empty:
            pass
        finally:
            self.after(100, self._poll_events)

    def _finish_success(self, matches: list[dict], target: str):
        self.matches = matches
        self.run_btn.configure(state="normal")

        if not matches:
            self.export_btn.configure(state="disabled")
            self.set_result(
                "NO SE ENCONTRÓ UNA COINCIDENCIA.\n\n"
                "Ningún backup compatible produjo una frase BIP-39 válida del número "
                "de palabras seleccionado y una dirección coincidente en las rutas probadas.\n"
            )
            self.status_var.set("Sin coincidencias.")
            return

        # Agrupar por frase por si varias copias contienen la misma wallet.
        unique: dict[str, dict] = {}
        for m in matches:
            bucket = unique.setdefault(
                m["mnemonic"],
                {"labels": [], "paths": set(), "credentials": set(), "words": m["words"]},
            )
            bucket["labels"].append(m["label"])
            bucket["paths"].update(m["paths"])
            if m.get("credential_source"):
                bucket["credentials"].add(m["credential_source"])

        blocks = []
        for num, (mnemonic, info) in enumerate(unique.items(), start=1):
            words = mnemonic.split()
            numbered = "\n".join(f"{i:02d}. {w}" for i, w in enumerate(words, start=1))
            blocks.append(
                f"=== WALLET COINCIDENTE {num} ===\n"
                f"Dirección verificada: {target}\n"
                f"Palabras: {len(words)}\n"
                f"Ruta(s) coincidente(s):\n  - " + "\n  - ".join(sorted(info["paths"])) + "\n"
                f"Copias coincidentes: {len(info['labels'])}\n"
                f"Backup(s):\n  - " + "\n  - ".join(info["labels"]) + "\n"
                f"Credencial usada para descifrar seed.seco:\n  - "
                + "\n  - ".join(sorted(info["credentials"]) or ["passphrase.json emparejado"])
                + "\nContraseña de Exodus introducida manualmente en esta app: NO\n\n"
                f"{numbered}\n"
            )

        self.set_result("\n\n".join(blocks))
        self.export_btn.configure(state="normal")
        self.status_var.set(f"RECUPERADA: {len(unique)} frase(s) única(s).")
        messagebox.showinfo(
            "Recuperación completada",
            "Se encontró al menos una frase BIP-39 que reproduce el seed almacenado "
            "y cuya derivación Ethereum coincide con la dirección objetivo.\n\n"
            "Anótala fuera de línea. No la pegues en webs ni chats.",
        )

    def export_encrypted_result(self):
        if not self.matches:
            messagebox.showwarning("Exportar", "No hay un resultado verificado para exportar.")
            return

        password = simpledialog.askstring(
            "Exportación cifrada",
            "Introduce una contraseña NUEVA para cifrar el archivo (mínimo 10 caracteres):",
            show="*",
            parent=self,
        )
        if password is None:
            return
        confirm = simpledialog.askstring(
            "Exportación cifrada",
            "Repite la contraseña:",
            show="*",
            parent=self,
        )
        if confirm is None:
            return
        if password != confirm:
            messagebox.showerror("Exportación cifrada", "Las contraseñas no coinciden.")
            return

        try:
            unique = {}
            for m in self.matches:
                bucket = unique.setdefault(
                    m["mnemonic"],
                    {"labels": [], "paths": set(), "words": m["words"]},
                )
                bucket["labels"].append(m["label"])
                bucket["paths"].update(m["paths"])

            payload = {
                "created_utc": datetime.now(timezone.utc).isoformat(),
                "target_address": self._last_target,
                "verified_results": [
                    {
                        "mnemonic": mnemonic,
                        "words": info["words"],
                        "matching_paths": sorted(info["paths"]),
                        "backups": info["labels"],
                    }
                    for mnemonic, info in unique.items()
                ],
            }
            envelope = encrypt_export_payload(payload, password)
        except Exception as exc:
            messagebox.showerror("Exportación cifrada", str(exc))
            return

        path = filedialog.asksaveasfilename(
            title="Guardar resultado cifrado",
            defaultextension=".json.enc",
            filetypes=[("Resultado cifrado", "*.json.enc"), ("Todos", "*.*")],
            initialfile="exodus_recovery_result.json.enc",
        )
        if not path:
            return

        try:
            Path(path).write_text(
                json.dumps(envelope, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        except Exception as exc:
            messagebox.showerror("Exportación cifrada", str(exc))
            return

        messagebox.showinfo(
            "Exportación cifrada",
            "Resultado guardado cifrado con scrypt + AES-256-GCM.\n\n"
            "No pierdas la contraseña: no se almacena en el archivo.",
        )


if __name__ == "__main__":
    app = RecoveryApp()
    app.mainloop()

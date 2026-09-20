#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Exodus BIP39 Recovery Tool
--------------------------
Recuperación LOCAL de una frase BIP-39 desde copias propias de Exodus.

Qué hace:
1) Lee un ZIP/carpeta de Exodus que contenga exodus.wallet/seed.seco
   y passphrase.json.
2) Descifra localmente el contenedor SECO usando los parámetros
   scrypt + AES-256-GCM documentados por Exodus.
3) Extrae la entropía BIP-39 del objeto serializado.
4) Genera la frase BIP-39 en inglés.
5) Deriva Ethereum por m/44'/60'/0'/0/0 y compara con una dirección
   pública objetivo.
6) Solo muestra la frase si la dirección derivada coincide.

IMPORTANTE:
- No envía nada a Internet.
- No necesita Etherscan ni API keys.
- Las transacciones públicas NO contienen suficiente información para
  reconstruir una BIP-39; la dirección pública se usa únicamente como
  verificador del backup local.
"""

import base64
import csv
import hashlib
import hmac
import json
import os
import re
import struct
import tempfile
import zipfile
import zlib
from collections import Counter
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

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


def derive_eth_exodus(seed: bytes):
    """Exodus Ethereum default: m/44'/60'/0'/0/0"""
    k, c = bip32_master(seed)
    path = [
        44 | HARDENED,
        60 | HARDENED,
        0 | HARDENED,
        0,
        0,
    ]
    for idx in path:
        k, c = ckd_priv(k, c, idx)
    return k, eth_address_from_priv(k)


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
    salt = meta[pos:pos + 32]; pos += 32
    n, r, p = struct.unpack(">LLL", meta[pos:pos + 12]); pos += 12
    cipher = meta[pos:pos + 32].rstrip(b"\x00").decode("ascii", errors="strict"); pos += 32
    bk_iv = meta[pos:pos + 12]; pos += 12
    bk_tag = meta[pos:pos + 16]; pos += 16
    bk_ciphertext = meta[pos:pos + 32]; pos += 32
    blob_iv = meta[pos:pos + 12]; pos += 12
    blob_tag = meta[pos:pos + 16]; pos += 16

    if cipher != "aes-256-gcm":
        raise ValueError(f"Cifrado SECO no soportado: {cipher}")

    blob_len_pos = meta_start + METADATA_SIZE
    blob_len = struct.unpack(">L", file_bytes[blob_len_pos:blob_len_pos + 4])[0]
    blob = file_bytes[blob_len_pos + 4:blob_len_pos + 4 + blob_len]
    if len(blob) != blob_len:
        raise ValueError("Blob SECO truncado.")

    # Verificar checksum del contenedor.
    digest = hashlib.sha256(meta + struct.pack(">L", blob_len) + blob).digest()
    if digest != checksum:
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


def decrypt_seed_seco(seed_seco: bytes, passphrase_text: str) -> bytes:
    info = parse_seco(seed_seco)

    # Exodus guarda la passphrase de sistema como texto Base64 dentro del JSON.
    # El secure-container recibe la CADENA UTF-8, no los bytes resultantes
    # de decodificar Base64.
    passphrase_bytes = passphrase_text.encode("utf-8")

    kdf_key = hashlib.scrypt(
        passphrase_bytes,
        salt=info["salt"],
        n=info["n"],
        r=info["r"],
        p=info["p"],
        dklen=32,
    )

    blob_key = AESGCM(kdf_key).decrypt(
        info["bk_iv"],
        info["bk_ciphertext"] + info["bk_tag"],
        None,
    )

    plaintext = AESGCM(blob_key).decrypt(
        info["blob_iv"],
        info["blob"] + info["blob_tag"],
        None,
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
    raw = zlib.decompress(compressed, 31)  # gzip wrapper

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
    return calc == stored_seed


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


def extract_eth_addresses_from_csv(csv_path: str):
    counts = Counter()
    with open(csv_path, "r", encoding="utf-8-sig", errors="replace", newline="") as f:
        for row in csv.reader(f):
            for cell in row:
                for addr in ETH_ADDRESS_RE.findall(cell or ""):
                    counts[addr.lower()] += 1
    return counts


class RecoveryApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Exodus BIP39 Recovery Tool — LOCAL")
        self.geometry("980x760")
        self.minsize(850, 650)

        self.source_var = tk.StringVar()
        self.target_var = tk.StringVar()
        self.status_var = tk.StringVar(value="Preparado.")
        self.matches = []

        self._build_ui()

    def _build_ui(self):
        pad = {"padx": 10, "pady": 6}

        title = ttk.Label(
            self,
            text="Recuperación local de frase BIP-39 desde backups propios de Exodus",
            font=("Segoe UI", 15, "bold"),
        )
        title.pack(pady=(14, 4))

        warning = ttk.Label(
            self,
            text=(
                "La blockchain se usa solo como VERIFICADOR. "
                "Nunca subas seed.seco, passphrase.json ni una frase BIP-39 a una web."
            ),
            wraplength=920,
        )
        warning.pack(pady=(0, 10))

        frm = ttk.LabelFrame(self, text="1. Datos de entrada")
        frm.pack(fill="x", padx=14, pady=6)

        ttk.Label(frm, text="ZIP de Exodus o carpeta raíz:").grid(row=0, column=0, sticky="w", **pad)
        ttk.Entry(frm, textvariable=self.source_var, width=85).grid(row=0, column=1, sticky="ew", **pad)
        ttk.Button(frm, text="Seleccionar ZIP", command=self.pick_zip).grid(row=0, column=2, **pad)
        ttk.Button(frm, text="Seleccionar carpeta", command=self.pick_folder).grid(row=0, column=3, **pad)

        ttk.Label(frm, text="Dirección Ethereum objetivo:").grid(row=1, column=0, sticky="w", **pad)
        ttk.Entry(frm, textvariable=self.target_var, width=55).grid(row=1, column=1, sticky="ew", **pad)
        ttk.Button(frm, text="Detectar desde CSV", command=self.pick_csv).grid(row=1, column=2, **pad)

        frm.columnconfigure(1, weight=1)

        controls = ttk.Frame(self)
        controls.pack(fill="x", padx=14, pady=8)

        self.run_btn = ttk.Button(
            controls,
            text="RECUPERAR Y VERIFICAR",
            command=self.run_recovery,
        )
        self.run_btn.pack(side="left")

        ttk.Button(
            controls,
            text="Borrar resultado",
            command=self.clear_result,
        ).pack(side="left", padx=8)

        ttk.Label(controls, textvariable=self.status_var).pack(side="right")

        logfrm = ttk.LabelFrame(self, text="2. Progreso y comprobaciones")
        logfrm.pack(fill="both", expand=True, padx=14, pady=6)
        self.log = tk.Text(logfrm, height=16, wrap="word", font=("Consolas", 10))
        self.log.pack(fill="both", expand=True, padx=6, pady=6)

        resfrm = ttk.LabelFrame(self, text="3. Resultado LOCAL")
        resfrm.pack(fill="x", padx=14, pady=(6, 14))
        self.result = tk.Text(resfrm, height=8, wrap="word", font=("Consolas", 11, "bold"))
        self.result.pack(fill="x", padx=6, pady=6)
        self.result.insert(
            "1.0",
            "La frase solo aparecerá aquí si un backup genera exactamente "
            "la dirección Ethereum objetivo.\n"
        )
        self.result.configure(state="disabled")

    def append_log(self, msg):
        self.log.insert("end", msg + "\n")
        self.log.see("end")
        self.update_idletasks()

    def set_result(self, text):
        self.result.configure(state="normal")
        self.result.delete("1.0", "end")
        self.result.insert("1.0", text)
        self.result.configure(state="disabled")

    def clear_result(self):
        self.matches = []
        self.log.delete("1.0", "end")
        self.set_result(
            "La frase solo aparecerá aquí si un backup genera exactamente "
            "la dirección Ethereum objetivo.\n"
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

    def pick_csv(self):
        p = filedialog.askopenfilename(
            title="Selecciona CSV de Exodus/Etherscan",
            filetypes=[("CSV", "*.csv"), ("Todos", "*.*")],
        )
        if not p:
            return
        try:
            counts = extract_eth_addresses_from_csv(p)
        except Exception as exc:
            messagebox.showerror("CSV", str(exc))
            return

        if not counts:
            messagebox.showwarning("CSV", "No encontré direcciones Ethereum en el CSV.")
            return

        # Mostrar top 10 y permitir seleccionar.
        top = counts.most_common(10)
        win = tk.Toplevel(self)
        win.title("Direcciones encontradas en el CSV")
        win.geometry("760x330")
        ttk.Label(
            win,
            text="Selecciona la dirección propia que quieras usar como verificador:",
        ).pack(pady=8)

        lb = tk.Listbox(win, width=105, height=10, font=("Consolas", 10))
        lb.pack(fill="both", expand=True, padx=10, pady=6)
        for addr, n in top:
            lb.insert("end", f"{addr}    apariciones={n}")

        def choose():
            sel = lb.curselection()
            if not sel:
                return
            addr = top[sel[0]][0]
            self.target_var.set(addr)
            win.destroy()

        ttk.Button(win, text="Usar esta dirección", command=choose).pack(pady=8)

    def run_recovery(self):
        source = self.source_var.get().strip()
        try:
            target = normalize_eth_address(self.target_var.get())
        except Exception as exc:
            messagebox.showerror("Dirección objetivo", str(exc))
            return

        if not source or not os.path.exists(source):
            messagebox.showerror("Fuente", "Selecciona un ZIP o carpeta existente.")
            return

        self.clear_result()
        self.run_btn.configure(state="disabled")
        self.status_var.set("Analizando...")

        try:
            if os.path.isfile(source) and source.lower().endswith(".zip"):
                candidates = list(zip_candidates(source))
            elif os.path.isdir(source):
                candidates = list(folder_candidates(source))
            else:
                raise ValueError("La fuente debe ser un ZIP o una carpeta.")

            if not candidates:
                raise ValueError(
                    "No encontré pares seed.seco + passphrase.json dentro de la fuente."
                )

            self.append_log(f"Backups candidatos encontrados: {len(candidates)}")
            self.append_log(f"Dirección objetivo: {target}")
            self.append_log("Ruta Ethereum de verificación: m/44'/60'/0'/0/0")
            self.append_log("")

            mnemonic_engine = Mnemonic("english")
            matches = []
            errors = 0

            for idx, (label, seed_bytes, pp_bytes) in enumerate(candidates, start=1):
                try:
                    pp = read_passphrase_json(pp_bytes)
                    plain = decrypt_seed_seco(seed_bytes, pp)
                    raw = unpack_exodus_seed_payload(plain)

                    stored_seed = raw[:64]
                    entropy = raw[64:]
                    mnemonic = mnemonic_engine.to_mnemonic(entropy)
                    bip39_ok = verify_mnemonic_seed(mnemonic, stored_seed)

                    child_priv, addr = derive_eth_exodus(stored_seed)
                    ok = (addr.lower() == target)

                    self.append_log(
                        f"[{idx:03d}/{len(candidates):03d}] {label} | "
                        f"{len(entropy)*8} bits | "
                        f"BIP39-seed={'OK' if bip39_ok else 'NO'} | "
                        f"ETH={addr} | {'MATCH' if ok else 'no'}"
                    )

                    if ok:
                        matches.append({
                            "label": label,
                            "mnemonic": mnemonic,
                            "entropy_bits": len(entropy) * 8,
                            "words": len(mnemonic.split()),
                            "address": addr,
                            "bip39_ok": bip39_ok,
                        })
                except Exception as exc:
                    errors += 1
                    self.append_log(f"[{idx:03d}] {label} | ERROR: {exc}")

            self.matches = matches
            self.append_log("")
            self.append_log(f"Finalizado. Coincidencias: {len(matches)} | errores/formatos no compatibles: {errors}")

            if not matches:
                self.set_result(
                    "NO SE ENCONTRÓ UNA COINCIDENCIA.\n\n"
                    "Esto significa que ninguno de los backups descifrables analizados "
                    "generó la dirección objetivo por m/44'/60'/0'/0/0.\n"
                )
                self.status_var.set("Sin coincidencias.")
                return

            # Agrupar por frase, por si varias copias contienen la misma wallet.
            unique = {}
            for m in matches:
                unique.setdefault(m["mnemonic"], []).append(m["label"])

            blocks = []
            for num, (mnemonic, labels) in enumerate(unique.items(), start=1):
                words = mnemonic.split()
                numbered = "\n".join(
                    f"{i:02d}. {w}" for i, w in enumerate(words, start=1)
                )
                blocks.append(
                    f"=== WALLET COINCIDENTE {num} ===\n"
                    f"Dirección verificada: {target}\n"
                    f"Palabras: {len(words)}\n"
                    f"Copias coincidentes: {len(labels)}\n"
                    f"Backup(s):\n  - " + "\n  - ".join(labels) + "\n\n"
                    f"{numbered}\n"
                )

            self.set_result("\n\n".join(blocks))
            self.status_var.set(f"RECUPERADA: {len(unique)} frase(s) única(s).")

            messagebox.showinfo(
                "Recuperación completada",
                "Se encontró al menos una frase cuya derivación Ethereum coincide "
                "exactamente con la dirección objetivo.\n\n"
                "Anótala fuera de línea. No la pegues en webs ni chats."
            )

        except Exception as exc:
            messagebox.showerror("Error", str(exc))
            self.status_var.set("Error.")
        finally:
            self.run_btn.configure(state="normal")


if __name__ == "__main__":
    app = RecoveryApp()
    app.mainloop()

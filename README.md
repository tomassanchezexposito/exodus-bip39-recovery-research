# Exodus BIP-39 Recovery Research

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.22858136.svg)](https://doi.org/10.5281/zenodo.22858136)
[![Release](https://img.shields.io/badge/release-v0.2.0-blue.svg)](https://github.com/tomassanchezexposito/exodus-bip39-recovery-research/releases)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

A reproducible, local-first research tool for **authorized recovery and verification of Exodus BIP-39 wallets**.

The project distinguishes between local encrypted wallet material, which can contain causal secret material sufficient for recovery, and public blockchain data, which is primarily useful for verification rather than inversion of BIP-39.

The current implementation focuses on Exodus Desktop backup material and Ethereum verification.

## v0.2.0 highlights

- BIP-39 recovery for valid entropy sizes, including **256-bit / 24-word mnemonics**.
- Parallel processing of multiple backup candidates with configurable workers.
- Automatic worker reduction for memory-heavy `scrypt` parameters.
- Explicit `hashlib.scrypt(maxmem=...)` handling to avoid OpenSSL's implicit memory ceiling rejecting legitimate high-N Exodus containers.
- Multiple BIP-44 Ethereum verification paths across configurable accounts and address indices, plus optional custom paths.
- In-memory derivation cache to avoid repeating cryptographic work for duplicate/repeated recovered seed material.
- Responsive GUI with background processing and progress reporting.
- Optional bounded/early-exit CSV address discovery mode.
- Local encrypted result export using scrypt and AES-256-GCM.
- Automated validation suite expanded from 31 to **40 passing tests**.

## Research scope

The tool is designed for wallets, backups, keys and transactions that the operator owns or is explicitly authorized to recover. It is not intended for access to third-party funds.

The research separates:

1. BIP-39 entropy, mnemonic and seed construction;
2. BIP-32/BIP-44 HD derivation;
3. Exodus encrypted `seco` containers;
4. Ethereum key/address verification;
5. public transaction/signature analysis;
6. experimental prime/index/coordinate representations, which are not treated as entropy unless an independent reduction can be demonstrated.

## Recovery and verification workflow

Given an authorized Exodus backup containing compatible pairs of:

```text
seed.seco
passphrase.json
```

and a known public Ethereum address, the application follows:

```text
Exodus backup
   ↓
seco parsing and integrity check
   ↓
scrypt key derivation with explicit memory handling
   ↓
AES-256-GCM decryption
   ↓
serialized Exodus seed payload
   ↓
BIP-39 entropy / mnemonic reconstruction
   ↓
BIP-39 seed verification
   ↓
BIP-32 / BIP-44 Ethereum derivation
   ↓
configurable account / address-index paths
   ↓
secp256k1 public key
   ↓
Keccak-256 Ethereum address
   ↓
compare with the operator-supplied public address
```

The mnemonic is displayed only after the recovered mnemonic reproduces the stored BIP-39 seed and at least one derived Ethereum address matches the target supplied by the operator.

## BIP-39 word lengths

The application supports BIP-39 entropy sizes implemented by the standard conversion, including:

- 128 bits → 12 words
- 160 bits → 15 words
- 192 bits → 18 words
- 224 bits → 21 words
- 256 bits → **24 words**

The GUI can filter by expected mnemonic length or accept any supported length.

## Ethereum verification paths

By default, the GUI can generate paths of the form:

```text
m/44'/60'/account'/0/index
```

with configurable maximum account and address index. Additional custom paths can also be supplied.

This extends the original v0.1.0 behavior, which focused on:

```text
m/44'/60'/0'/0/0
```

## scrypt/OpenSSL compatibility

Some Exodus secure containers can use memory-intensive scrypt parameters. Relying on the implicit OpenSSL memory ceiling can cause a legitimate container to fail with a `memory limit exceeded` error.

Version 0.2.0 calculates and supplies an explicit `maxmem` value to `hashlib.scrypt()` within the application's configured safety limit. For memory-heavy parameters, the application also reduces parallel workers automatically to avoid multiplying large RAM requirements.

This is a compatibility/correctness fix, not a weakening of scrypt parameters.

## Performance and interface

Candidate backups can be processed concurrently. A derivation cache avoids repeating downstream derivation work when recovered seed material is duplicated across historical backups.

The GUI performs recovery work outside Tkinter's main UI thread and reports progress while processing.

CSV address discovery retains full processing by default. An optional fast mode can stop after a configured number of unique addresses; results from that mode are explicitly partial and should not be interpreted as a complete frequency ranking.

## Encrypted local export

Recovered results can optionally be exported locally in encrypted form. The export uses password-based scrypt key derivation and AES-256-GCM authenticated encryption.

Recovered mnemonic material should still be treated as highly sensitive.

## What this repository deliberately does not contain

No real recovery phrase, private key, Exodus `seed.seco`, `passphrase.json`, wallet ZIP, or real user transaction dataset is committed to this repository.

`.gitignore` contains defensive patterns to help prevent accidental publication of private wallet material.

## Installation

### Windows

1. Install Python 3.11 or later compatible with the dependencies.
2. During installation, enable **Add Python to PATH**.
3. Clone or download this repository.
4. Run:

```text
run_windows.bat
```

### Manual installation

```bash
python -m pip install -r requirements.txt
python src/exodus_recovery_tool.py
```

Dependencies are listed in `requirements.txt`.

## Input data

The application needs only:

1. an authorized Exodus ZIP/folder containing compatible wallet backups;
2. a public Ethereum address used as the verification target.

Optionally, an Exodus/Etherscan CSV can be used to detect candidate public Ethereum addresses.

It does **not** require private keys, Etherscan API keys, ECDSA signature components, EIP-7702 authorization nonces, token balances, or transfer amounts for the implemented local recovery path.

## Validation

Version 0.2.0 was validated locally on Windows with:

```text
python -m pytest -v
```

Result:

```text
40 passed
```

The suite includes tests covering BIP-39 reconstruction, a public 256-bit/24-word vector, BIP-32, multiple Ethereum derivation paths, Exodus backup discovery, CSV processing, encrypted export, explicit scrypt memory handling, high-N scrypt configuration, and automatic worker reduction for memory-heavy scrypt workloads.

No real mnemonic, private key or wallet backup is included in the public tests.

## Security model

Run recovery on a trusted local computer. Do not upload wallet backups or recovered mnemonics to web services.

A recovered mnemonic or private key should be treated as sensitive. If it belongs to a wallet with funds, migrate funds to a newly generated wallet after recovery.

See [`SECURITY.md`](SECURITY.md).

## Evidence discipline

The broader research uses these labels:

- `DEMONSTRATED_MATHEMATICALLY`
- `FORMALLY_VERIFIED`
- `REPRODUCED_COMPUTATIONALLY`
- `STATISTICAL_EVIDENCE`
- `HEURISTIC`
- `HYPOTHESIS`
- `REFUTED`
- `UNKNOWN`

In particular, the deterministic mapping

```text
BIP-39 index → local position → odd-prime ordinal → odd prime
```

is treated as a change of representation, **not as additional cryptographic entropy**.

## Repository layout

```text
.
├── src/
│   └── exodus_recovery_tool.py
├── docs/
│   ├── RESEARCH_NOTES.md
│   └── EVIDENCE_LEVELS.md
├── tests/
│   ├── README.md
│   └── test_recovery_core.py
├── examples/
│   └── README.md
├── .gitignore
├── CHANGELOG.md
├── CITATION.cff
├── LICENSE
├── README.md
├── README_ES.md
├── SECURITY.md
├── pytest.ini
├── requirements.txt
└── run_windows.bat
```

## Primary technical references

- BIP-39 — https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
- BIP-32 — https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
- BIP-44 — https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
- EIP-20 — https://eips.ethereum.org/EIPS/eip-20
- EIP-7702 — https://eips.ethereum.org/EIPS/eip-7702
- Exodus secure-container — https://github.com/ExodusMovement/secure-container
- ExodusOSS bitcoin-seed — https://github.com/ExodusOSS/bitcoin-seed

## Publication and archival

GitHub is used for the public source repository and development history.

Version **v0.1.0** is permanently archived through Zenodo:

**v0.1.0 DOI:** [10.5281/zenodo.22858136](https://doi.org/10.5281/zenodo.22858136)

Version **v0.2.0** has been permanently archived through Zenodo:

**v0.2.0 DOI:** [10.5281/zenodo.22861160](https://doi.org/10.5281/zenodo.22861160)

Historical release tags are not rewritten.

## Citation

Citation metadata is provided in [`CITATION.cff`](CITATION.cff).

Recommended citation for the current archived release:

> Sánchez Expósito, T. (2026). *Exodus BIP-39 Recovery Research* (Version 0.2.0) [Computer software]. Zenodo. https://doi.org/10.5281/zenodo.22861160

ORCID: [0009-0006-3715-8516](https://orcid.org/0009-0006-3715-8516)

## License

This project is licensed under the **Apache License 2.0**. See [`LICENSE`](LICENSE).

Copyright © 2026 Tomás Sánchez Expósito.

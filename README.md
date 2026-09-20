# Exodus BIP-39 Recovery Research

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.22858136.svg)](https://doi.org/10.5281/zenodo.22858136)
[![Release](https://img.shields.io/badge/release-v0.1.0-blue.svg)](https://github.com/tomassanchezexposito/exodus-bip39-recovery-research/releases/tag/v0.1.0)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

A reproducible, local-first research tool for **authorized recovery and verification of Exodus BIP-39 wallets**.

The project studies a precise distinction that is easy to blur in wallet recovery:

- **local encrypted wallet backups** can contain causal secret material from which a mnemonic may be recovered; while
- **public blockchain data** (addresses, transaction hashes, signatures, token transfers) is usually best used to verify candidates, not to invert BIP-39.

The current implementation focuses on Exodus Desktop backup material and Ethereum verification.

## Research scope

The tool is designed for wallets, backups, keys and transactions that the operator owns or is explicitly authorized to recover. It is not intended for access to third-party funds.

The research separates:

1. BIP-39 entropy, mnemonic and seed construction;
2. BIP-32/BIP-44 HD derivation;
3. Exodus encrypted `seco` containers;
4. Ethereum key/address verification;
5. public transaction/signature analysis;
6. experimental prime/index/coordinate representations, which are not treated as entropy unless an independent reduction can be demonstrated.

## Main result implemented here

Given an authorized Exodus backup containing compatible pairs of:

```text
seed.seco
passphrase.json
```

and a known public Ethereum address, the application:

```text
Exodus backup
   ↓
seco parsing and integrity check
   ↓
scrypt key derivation
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
m/44'/60'/0'/0/0
   ↓
secp256k1 public key
   ↓
Keccak-256 Ethereum address
   ↓
compare with the operator-supplied public address
```

The mnemonic is displayed only after the derived Ethereum address matches the target supplied by the operator.

## What this repository deliberately does not contain

No real recovery phrase, private key, Exodus `seed.seco`, `passphrase.json`, wallet ZIP, or real user transaction dataset is committed to this repository.

`.gitignore` contains defensive patterns to help prevent accidental publication of private wallet material.

## Installation

### Windows

1. Install Python 3.11 or 3.12.
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

It does **not** require:

- private keys;
- Etherscan API keys;
- ECDSA `(r, s, v/yParity)`;
- EIP-7702 authorization nonces;
- token balances or transfer amounts.

Those values may be useful for separate cryptographic research, but they are not required by the local recovery path implemented here.

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
│   └── README.md
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

- BIP-39 — Mnemonic code for generating deterministic keys  
  https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
- BIP-32 — Hierarchical Deterministic Wallets  
  https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
- BIP-44 — Multi-Account Hierarchy for Deterministic Wallets  
  https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
- EIP-20 — ERC-20 Token Standard  
  https://eips.ethereum.org/EIPS/eip-20
- EIP-7702 — Set Code for EOAs  
  https://eips.ethereum.org/EIPS/eip-7702
- Exodus secure-container implementation  
  https://github.com/ExodusMovement/secure-container
- ExodusOSS bitcoin-seed  
  https://github.com/ExodusOSS/bitcoin-seed

## Publication and archival

GitHub is used for the public source repository and development history.

Version **v0.1.0** has been permanently archived through **Zenodo**:

**DOI:** [10.5281/zenodo.22858136](https://doi.org/10.5281/zenodo.22858136)

Future archived versions will be published as new versioned releases without rewriting the historical `v0.1.0` tag.

## Citation

Citation metadata is provided in [`CITATION.cff`](CITATION.cff).

Recommended citation:

> Sánchez Expósito, T. (2026). *Exodus BIP-39 Recovery Research* (Version 0.1.0) [Computer software]. Zenodo. https://doi.org/10.5281/zenodo.22858136

ORCID: [0009-0006-3715-8516](https://orcid.org/0009-0006-3715-8516)

## License

This project is licensed under the **Apache License 2.0**. See [`LICENSE`](LICENSE) for the full license text.

Copyright © 2026 Tomás Sánchez Expósito.

# Changelog

All notable changes to this research repository will be documented in this file.

The project follows semantic versioning for archived research releases where practical.

## [0.1.0] - 2026-09-20

### Initial research release

First reproducible research version of **Exodus BIP-39 Recovery Research**.

### Added

- Local-first workflow for authorized recovery and verification of Exodus BIP-39 wallet material.
- Parsing and integrity checking of supported local Exodus backup material.
- Scrypt-based key derivation and AES-256-GCM decryption support used by the implemented recovery path.
- Reconstruction and validation of BIP-39 mnemonic material from locally recovered entropy.
- BIP-39 seed derivation.
- BIP-32 master-key derivation and hierarchical deterministic derivation support used by the project.
- Ethereum key/address derivation and comparison against an operator-supplied public address.
- Experimental prime/index/coordinate representations for research purposes.
- Documentation describing the security model, evidence discipline, installation and repository structure.
- Apache License 2.0.
- Citation metadata for subsequent archival publication.
- Pytest configuration and reproducible automated test suite.

### Validation

- Automated local test suite: **31 tests passed**.
- Validation environment used during this release preparation:
  - Windows
  - Python 3.14.6
  - pytest 9.1.1
- The tests cover the implemented cryptographic/recovery core, including BIP-39, BIP-32, Ethereum derivation and supporting functions.

### Research status and limitations

- Public blockchain information such as addresses, transaction hashes, signatures, token transfers and authorization data is treated primarily as verification evidence, not as mnemonic entropy.
- Experimental mappings involving prime numbers, indices or coordinate representations are research representations and are **not claimed to reduce BIP-39 cryptographic entropy unless an independent reduction can be formally demonstrated**.
- No claim is made that ordinary public Ethereum transaction data can reconstruct an otherwise unknown BIP-39 mnemonic.
- The implemented recovery path depends on authorized local wallet material containing recoverable causal secret material and on verification against information supplied by the operator.
- This repository is intended only for wallets, backups and keys that the operator owns or is explicitly authorized to recover.
- Private wallet backups, recovered mnemonics, private keys and other secret material must not be committed to the repository.

### Archival status

Version **0.1.0** was archived and published through **Zenodo** on 2026-09-20.

**DOI:** [10.5281/zenodo.22858136](https://doi.org/10.5281/zenodo.22858136)

The archived `v0.1.0` release is preserved as the historical first research release. Subsequent changes on the `main` branch belong to later development and do not rewrite the archived release.

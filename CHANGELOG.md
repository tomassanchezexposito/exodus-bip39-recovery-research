# Changelog

All notable changes to this research repository will be documented in this file.

The project follows semantic versioning for archived research releases where practical.

## [0.2.0] - 2026-09-20

### Recovery engine and compatibility release

Second reproducible research release of **Exodus BIP-39 Recovery Research**.

### Added

- Support and automated validation for 256-bit BIP-39 entropy producing 24-word mnemonics.
- Configurable parallel processing of backup candidates.
- GUI progress reporting with recovery work executed outside Tkinter's main UI thread.
- Multiple Ethereum BIP-44 verification paths using configurable accounts and address indices.
- Optional custom Ethereum derivation paths.
- In-memory derivation caching to avoid repeated downstream work for duplicate recovered seed material.
- Optional bounded/early-exit CSV address discovery mode, explicitly treated as partial.
- Password-protected local result export using scrypt key derivation and AES-256-GCM authenticated encryption.
- Automated tests for 24-word BIP-39 reconstruction, path parsing/building, multiple derivation paths, CSV early exit, encrypted export and scrypt memory handling.

### Fixed

- Explicit `maxmem` handling for `hashlib.scrypt()` to avoid OpenSSL's implicit memory ceiling rejecting legitimate high-memory Exodus secure containers.
- The same explicit scrypt memory handling is applied to encrypted result export.
- Automatic reduction of parallel workers when a candidate's scrypt parameters would otherwise multiply large memory requirements.
- Windows launcher path updated to run `src/exodus_recovery_tool.py` from the repository layout.

### Changed

- Ethereum verification is no longer limited to `m/44'/60'/0'/0/0`; the default GUI can scan configurable account/address-index ranges.
- The mnemonic is accepted only after recovered mnemonic/seed consistency is checked and a configured Ethereum derivation path matches the operator-supplied target.
- GUI can filter expected BIP-39 word length or accept any supported BIP-39 length.

### Validation

- Automated local test suite: **40 tests passed**.
- Validation command:

```text
python -m pytest -v
```

- Tests include:
  - public BIP-39 vectors;
  - 256-bit / 24-word mnemonic reconstruction;
  - BIP-32 vector validation;
  - deterministic and configurable Ethereum derivation;
  - Exodus ZIP/folder candidate discovery;
  - CSV address processing;
  - encrypted export round-trip;
  - explicit scrypt `maxmem` regression coverage;
  - configuration support for Exodus scrypt `N = 2^20, r = 8` within the application's configured memory limit;
  - automatic worker reduction for memory-heavy scrypt workloads.

### Security and research scope

- Recovery remains local-first and limited to wallets, backups and keys owned by the operator or explicitly authorized for recovery.
- No real mnemonic, private key, `seed.seco`, `passphrase.json`, wallet ZIP or private transaction dataset is included in the repository.
- Public blockchain information remains verification evidence rather than a claimed source of BIP-39 entropy.
- Prime/index/coordinate mappings remain deterministic representations and are not claimed to reduce BIP-39 cryptographic entropy.

### Archival status

Version **0.2.0** is being prepared for archival through Zenodo. Its version-specific DOI will be added after the corresponding Zenodo deposit is created.

The historical `v0.1.0` release remains archived at DOI [10.5281/zenodo.22858136](https://doi.org/10.5281/zenodo.22858136).

---

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
- Citation metadata.
- Pytest configuration and reproducible automated test suite.

### Validation

- Automated local test suite: **31 tests passed**.
- Validation environment used during this release preparation:
  - Windows
  - Python 3.14.6
  - pytest 9.1.1

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

The archived `v0.1.0` release is preserved as the historical first research release.

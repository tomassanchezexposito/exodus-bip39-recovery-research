# Tests

This directory contains public reproducibility tests for the recovery tool.

The tests deliberately use only synthetic data and public BIP-39/BIP-32 test
vectors. They do not contain or require a real Exodus backup, mnemonic,
passphrase, private key, wallet address, or transaction history.

## Run

From the repository root:

```bash
python -m pip install -r requirements.txt
python -m pytest
```

The suite checks:

- Ethereum address input validation;
- BIP-39 entropy-to-mnemonic conversion against a public vector;
- BIP-39 seed reconstruction;
- BIP-32 master-key derivation against the official test vector;
- `passphrase.json` parsing;
- defensive rejection of malformed SECO input;
- CSV Ethereum-address extraction;
- pairing of `seed.seco` and `passphrase.json` in folders and ZIP archives;
- deterministic Ethereum derivation for a public BIP-39 vector.

A real Exodus encrypted backup is intentionally not committed as a fixture.
End-to-end SECO decryption with a real wallet remains a local/private validation
step and must not be uploaded to the public repository.

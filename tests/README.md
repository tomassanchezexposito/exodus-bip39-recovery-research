# Tests

Real wallet files must never be used as committed test fixtures.

Planned automated tests should use only public or synthetic material and cover:

1. SECO header parsing and checksum verification;
2. scrypt parameter handling;
3. AES-256-GCM decryption of a synthetic fixture;
4. gzip/seed-payload unpacking;
5. BIP-39 entropy → mnemonic → seed consistency;
6. BIP-32/BIP-44 Ethereum derivation against public test vectors;
7. rejection when the derived address does not equal the target;
8. detection of malformed/truncated containers.

A fully synthetic SECO fixture should be generated during tests rather than committed with anything derived from a real wallet.

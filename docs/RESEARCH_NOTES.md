# Research Notes

## 1. Causal graph

The working cryptographic model is:

```text
BIP-39 entropy
→ mnemonic
→ BIP-39 seed
→ BIP-32 root
→ asset-specific derivation path
→ private/public key
→ address/script
→ transactions/signatures
```

Arrows toward public blockchain data are intentionally treated as one-way for ordinary cryptographic analysis unless a concrete implementation weakness is demonstrated.

## 2. Public transaction data

Ethereum and Bitcoin transactions can provide strong candidate-verification material. Signatures may become key-recovery material only when an actual signing weakness exists (for example, nonce reuse or sufficiently exploitable bias).

The Ethereum account `nonce` is not the secret ECDSA signing nonce `k`.

## 3. ERC-20 assets

USDT, USDC and other ERC-20 balances on Ethereum are associated with the same Ethereum externally owned account. Multiple token-transfer events produced by one transaction must not be counted as independent signatures or independent seed evidence.

## 4. EIP-7702 observation

Authorization nonces observed in the case study formed an odd sequence. This was not treated as BIP-39 or prime leakage once the state-transition behavior supplied a direct protocol explanation. This is an example of a pattern that must be causally explained before it is used as evidence.

## 5. Prime-coordinate research

The broader project studies mappings such as:

```text
BIP-39 index j
↔ local position k = j + 1
↔ k-th odd prime p_k
↔ coordinate (p_k - 3) / 2 in C(n) = 3 + 2n
```

These transformations are deterministic representations. They provide no new entropy unless an external observable imposes an independently demonstrated restriction on them.

## 6. Next experimental stage

A separate experimental application is planned to test whether any public features have genuine predictive value for intentionally hidden BIP-39 positions.

Required controls include:

- hold-out validation;
- random baselines;
- multiple-hypothesis correction;
- synthetic/test wallets;
- explicit false-positive measurement;
- no use of the hidden target during feature construction;
- attempted refutation of every discovered pattern.

This experimental module must remain logically separate from the local Exodus backup recovery tool.

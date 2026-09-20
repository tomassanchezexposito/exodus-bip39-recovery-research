# Security Policy

## Sensitive material

Never commit or upload real wallet secrets to this repository, issues, pull requests, discussions, CI logs, or test fixtures.

This includes, without limitation:

- BIP-39 recovery phrases;
- private keys or xprv values;
- Exodus `seed.seco`;
- Exodus `passphrase.json`;
- Exodus `storage.seco`;
- Exodus wallet folders or private backup ZIPs;
- screenshots containing mnemonic/private-key material;
- real-user datasets when they expose private operational history unnecessarily.

The included `.gitignore` is a defensive aid, not a substitute for manual review.

## Authorized use

Use the tool only with wallets, backups, keys and transactions you own or are explicitly authorized to recover.

## If a secret was committed

Do not assume that deleting the file from the latest commit removes the secret from Git history. Rotate/migrate the affected secret or wallet and rewrite repository history before publication.

## Recovery environment

For real recovery work:

1. use a trusted local machine;
2. keep backups offline;
3. avoid pasting mnemonics or private keys into websites, chats or issue trackers;
4. after recovering a funded wallet, migrate to a fresh seed if the old secret may have been exposed.

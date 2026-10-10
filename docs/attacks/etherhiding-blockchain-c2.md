# EtherHiding — attacker addresses stored on blockchains

Instead of hard-coding a server address that defenders could block, the loaders read their next instructions from
a **blockchain**: a smart contract or a transaction sent from a known wallet (TRON, Aptos, BNB Smart Chain,
Ethereum). The attacker can change where victims connect by writing a new transaction, and the data can't be taken down.
Google's Threat Intelligence Group reported North Korean actors adopting this "EtherHiding" technique.

## How it reaches you

- It's inside the loaders described in [PolinRider](polinrider-worm.md) and the stealers' first stages.

## What it does

- The loader calls public blockchain RPC endpoints, reads a value from a specific wallet or contract, decodes the
  real command-and-control address, and fetches the next stage from it.

## How to spot it

- Code (especially in config files or fonts) that contacts blockchain RPC hosts such as `api.trongrid.io`,
  `fullnode.mainnet.aptoslabs.com`, `bsc-dataseed…`, or public Ethereum RPC nodes. These hosts are legitimate services, so on their own
  they're only a hint — combined with obfuscated code in a config file they're a strong signal.
- The specific wallet addresses used by the campaign are in `checkrepo`'s indicator list.

## How to protect yourself

- Blocking domains isn't enough — stop the loader from running in the first place (the kit's hooks, editor and npm hardening).
- Scan repos before opening them; the daily check flags connections to the campaign's known servers.

## Sources

1. Google Cloud / GTIG — "DPRK Adopts EtherHiding: Nation-State Malware Hiding on Blockchains": https://cloud.google.com/blog/topics/threat-intelligence/dprk-adopts-etherhiding
2. OpenSourceMalware — PolinRider dossier (TRON / Aptos / BSC dead-drops): https://github.com/OpenSourceMalware/PolinRider
3. polinrider-cleaner — wallet and RPC indicators (MIT): https://github.com/meSingh/polinrider-cleaner

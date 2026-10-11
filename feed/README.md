# Detection feed

Ardvane's scanner has indicators built in, but attackers change their code all the time and many people update their
tools rarely. This feed lets every installed Ardvane learn new ones within a day, without an upgrade.

## What can go in it

| List | Entry | Example |
|---|---|---|
| `hashes` | SHA-256 of a known malware file | `ce20d9cf…` (64 hex characters, lower case) |
| `hosts` | an attacker's domain; its subdomains count too | `evil-loader.example` |
| `ips` | an attacker's server (public IPv4 only) | `166.88.4.2` |
| `markers` | a string only the malware contains (8-200 characters, at most 100 in total) | an XOR key |
| `npm` | a malicious npm package | `@evil/pkg`, `bad-pkg` |
| `pypi` | a malicious PyPI package | `bad-pkg` |

The feed can only **add** detections. It can't remove any built in to the scanner, and it can't tell Ardvane to move or
change files.

## Adding indicators

1. Add the entries to `indicators.json` in a pull request, with a link to the public report each one comes from.
   Prefer indicators that can't appear in normal code: a domain everyone uses (github.com, vercel.app, ...) is
   refused, and so are private IPs.
2. CI checks every entry with the same rules the app uses (`python3 .github/scripts/build_feed.py --check`).
3. When it is merged, the `feed` workflow builds the feed, signs it, checks the signature against the public key built
   into Ardvane, and publishes it as `indicators.signed` on the `feed` release. Installed copies pick it up with the
   next daily check or scan.

## Why it can be trusted

The published file is a 64-byte Ed25519 signature followed by the JSON. Ardvane uses it only if the signature matches
the public key in `scanner/feed.py`. The private key is a secret of the `feed` environment, which only workflows on
`main` can use, so a stolen GitHub token can't publish a feed. Each feed has a sequence number, and Ardvane refuses
one older than the copy it already has, so an old feed can't be replayed.

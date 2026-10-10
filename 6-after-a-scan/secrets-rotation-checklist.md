# Secrets rotation checklist

Assume **everything that was on the infected machine** was stolen. The stealers used in this campaign read
environment variables and `.env` files, browser cookies and saved passwords, the macOS Keychain, SSH keys and
crypto wallets.

Do it **from a clean device** if you can (or after reinstalling), otherwise the new secrets can be stolen too.

## 1. Accounts (passwords + sign out all other sessions)

Changing a password doesn't always end existing sessions — stolen browser cookies can keep working. On every
important site, use **"sign out of all other sessions"** as well.

- [ ] Email (every account — personal and work). Also check **forwarding rules, filters, app passwords and connected apps** —
      attackers use them to keep reading your mail.
- [ ] GitHub / GitLab / Bitbucket (every account)
- [ ] Password manager master password
- [ ] Your computer's login password (it protects the Keychain)
- [ ] Slack, Notion, Linear, Jira, Discord…
- [ ] Banking / crypto exchanges — and **move crypto to a new wallet** if any wallet or seed phrase was on the machine
- [ ] Passwords that were **saved in your browser** — change them on the sites themselves

## 2. Developer tokens and keys

- [ ] GitHub personal access tokens, OAuth apps, GitHub CLI (`gh auth logout`, then revoke on github.com)
- [ ] SSH keys (create new ones — ideally in hardware-backed storage, see the hardening checklist)
- [ ] npm tokens (npmjs.com → Access Tokens) and two-factor for publishing
- [ ] PyPI / Docker Hub / other registry tokens
- [ ] Cloud: AWS access keys (IAM → deactivate + create new), GCP service-account keys, Azure secrets
- [ ] Deployment platforms: Vercel / Netlify / Render / Railway tokens — **and the environment variables stored there**
- [ ] CI secrets: GitHub Actions repository/organization secrets

## 3. Your projects' `.env` secrets

List the variable **names** (not values) in every project so you have a checklist:

```bash
find ~/Documents ~/code -name ".env*" -not -path "*/node_modules/*" -not -name "*.example" \
  -exec sh -c 'echo "== $1"; sed -nE "s/^[[:space:]]*(export[[:space:]]+)?([A-Za-z_][A-Za-z0-9_]*)=.*/\2/p" "$1"' _ {} \;
```

Rotate in this order:

1. **Production money and user data** — payment keys (Stripe…), production database passwords, auth provider secrets.
2. **Cloud and storage keys** — AWS/GCP/Azure, S3 buckets.
3. **Paid APIs** that can run up a bill — OpenAI, Anthropic, Gemini, Mistral, etc.
4. **Internal secrets** — JWT signing keys, webhook secrets, cron secrets (generate new random values).
5. **Development / test keys.**

No need to rotate values that are public by design (`NEXT_PUBLIC_*`, `VITE_*` publishable keys) or short-lived tokens that expire on their own.

If these are your company's production secrets, **coordinate with whoever runs deployments** — the live app breaks
until the new values are also updated on the servers.

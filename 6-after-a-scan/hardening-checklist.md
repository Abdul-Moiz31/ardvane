# Hardening checklist — stay safe

No single tool stops everything. These layers together make sure an attack has to beat **all** of them.

## On your computer

- [ ] Install the kit: scanner + git hooks + safe clone (`../3-checkrepo`) and the daily routine (`../4-daily-routine`).
- [ ] VS Code / Cursor: **`"task.allowAutomaticTasks": "off"`** and **Workspace Trust on** (the installer does this).
      When asked "Do you trust the authors?", say yes only for your own and your team's code.
- [ ] npm: **`npm config set ignore-scripts true`** (the installer does this).
- [ ] Keep only editor extensions from verified publishers with a real history; review the list now and then.
- [ ] Keep your OS updated; keep built-in protections on (macOS: SIP, Gatekeeper, FileVault, firewall; Windows: Defender, SmartScreen, BitLocker).
- [ ] **SSH keys in hardware-backed storage** that can't be copied off the machine — e.g. [Secretive](https://github.com/maxgoedjen/secretive)
      on macOS (Secure Enclave, Touch ID per use), or a FIDO2 security key (`ssh-keygen -t ed25519-sk`).
      Use **one key per GitHub account**. **An unexpected Touch ID / security-key prompt = deny it.**
- [ ] No plain-text tokens on disk: avoid `~/.git-credentials`, keep `gh` logged out when you don't need it, use short-lived
      **fine-grained, read-only** tokens when a tool needs one.

## On GitHub (every account you use)

- [ ] Two-factor with a **passkey or authenticator app** (not SMS).
- [ ] **Vigilant mode**: Settings → SSH and GPG keys → "Flag unsigned commits as unverified".
- [ ] **Sign your commits** (SSH signing works with the hardware-backed key above).
- [ ] **Rulesets on your repos**: block force-push on all branches, block deletion and require signed commits on the default branch.
      This is the single strongest protection against this worm — even with a stolen token it can't rewrite your history.
- [ ] **Secret scanning + push protection** and **Dependabot alerts** on (repo Settings → Code security).
- [ ] Remove collaborators you don't actively work with. Ask the ones you keep to protect their machines too.
- [ ] Once a week: Settings → **Security log**, **Personal access tokens**, **Applications**, **SSH and GPG keys**.

## AI coding agents (Claude Code, Cursor, Copilot, Gemini CLI…)

- [ ] Only trust a folder in your AI agent if you'd trust running its code — repo files like `CLAUDE.md`, `AGENTS.md`,
      `.cursor/rules`, `.mcp.json` and `.claude/settings.json` hooks can instruct the agent or run commands.
- [ ] Don't use "auto-approve everything" / bypass modes in repositories you didn't write.
- [ ] `checkrepo` flags agent configs that run loaders, steal keys or hide invisible-Unicode instructions — but read them yourself before trusting a new repo.

## Habits — how these attacks usually start

- [ ] **Never run a recruiter's "take-home test" or "please fix this bug" repo on your main machine.** Use a cloud dev
      environment (e.g. GitHub Codespaces) or a throwaway virtual machine.
- [ ] **Never paste a Terminal / PowerShell command from a website, meeting page or chat** that tells you to "fix" your camera,
      microphone or connection. That is the ClickFix trick.
- [ ] Install SDKs **only by the exact package name in the vendor's official docs** — fake packages impersonating real
      company SDKs are part of this campaign.
- [ ] Before opening any repo you didn't write: `checkrepo <folder>`.
- [ ] If a collaborator's pull request **fails CI**, don't merge it "to fix later" — infected commits often break builds.

# Attacks on AI coding agents

AI coding agents (Claude Code, Cursor, GitHub Copilot, Gemini CLI, Windsurf, Codex…) read instruction and
configuration files from the repository you open. Attackers now plant those files so your **own AI assistant**
runs their commands or leaks your secrets — no "malware file" needed.

## How it reaches you

- A repository (often a coding test or a cloned project) containing:
  - instruction files the agent trusts: `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.cursorrules`, `.cursor/rules/*`, `.github/copilot-instructions.md`;
  - MCP server configuration (`.mcp.json`, `.cursor/mcp.json`) that starts a program;
  - agent settings with **hooks** that run shell commands automatically (e.g. `.claude/settings.json`);
  - settings that redirect the agent's API traffic to another server.

## What it does

- Hidden instructions (sometimes in invisible Unicode) tell the agent to read `.env` files, SSH or cloud keys and send them out.
- MCP servers or hooks run the attacker's code as soon as the agent starts in that folder — researchers documented
  agents with auto-run enabled harvesting cloud credentials within minutes in a "poisoned coding test".

## How to spot it

- Agent config in a repo you didn't write — read it before trusting the folder.
- Hooks / MCP servers that run `curl … | sh`, `node -e`, base64-decoded commands, or touch `~/.ssh` / `~/.aws`.
- Instructions mentioning secrets and an outside URL; invisible characters in instruction files.
- `checkrepo` flags loaders, key theft and hidden instructions in these files, and warns about risky hooks.

## How to protect yourself

- Only trust a folder in your agent if you'd trust running its code. Answer the agent's trust prompt carefully.
- Don't use auto-approve / bypass-permission modes in repositories you didn't write.
- Keep secrets out of the environment the agent runs in where possible; use short-lived tokens.

## Sources

1. Cloud Security Alliance — "MCP Auto-Execution: AI Coding Assistants and Credential Theft": https://labs.cloudsecurityalliance.org/research/csa-research-note-mcp-ai-coding-assistant-credential-theft-2/
2. Mitiga — "How a Poisoned Coding Test Turned an AI Agent Into an Attacker": https://www.mitiga.io/blog/poisoned-coding-test-ai-agent-attack
3. Adversa AI — "TrustFall: 1-click coding agent RCE in Claude, Cursor, Copilot": https://adversa.ai/blog/trustfall-coding-agent-security-flaw-rce-claude-cursor-gemini-cli-copilot/
4. CybeDefend — "Instruction File Injection: AGENTS.md and CLAUDE.md": https://www.cybedefend.com/en/blog/instruction-file-injection-agents-md-claude-md
5. Zylos Research — "When Repository Content Becomes Agent Configuration": https://zylos.ai/research/2026-08-28-repository-borne-prompt-injection-agent-config-files-workspace-trust/

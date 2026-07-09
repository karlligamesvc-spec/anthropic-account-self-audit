# Anthropic Account Self Audit

[中文说明](README.zh-CN.md)

A Codex skill for Claude Code-focused Anthropic account risk self-audits and local environment hygiene checks.

This project is not an "anti-ban" or enforcement-bypass tool. It helps users inspect local Claude Code-related signals, understand what can and cannot be verified locally, apply explicitly authorized low-risk local fixes, and prepare honest remediation or appeal materials when needed.

## What It Checks

- Claude Code-related environment variable names, without printing secret values.
- Claude Code config and state paths, including basic file permission hygiene.
- Secret-shaped strings in the current repository and selected Claude Code local logs.
- Proxy and optional public egress country/cloud hints.
- Optional browser language, timezone, and GeoTime/GeoMirror-style consistency signals.
- Installed Claude Code package string evidence, reported as local evidence only.

The skill does not inspect Claude Desktop/App caches by default.

## What It Cannot Know

This skill cannot see Anthropic's internal enforcement state, server-side risk score, account creation IP, payment history, historical login countries, warnings, appeal outcomes, request-level safety flags, or activity on other devices and remote servers.

It should be used as a local hygiene and workflow audit, not as a guarantee that an account is safe.

## Install

From Codex, ask the skill installer to install this GitHub path:

```text
Use $skill-installer to install https://github.com/karlligamesvc-spec/anthropic-account-self-audit/tree/main/anthropic-account-self-audit
```

Or clone manually and copy the skill folder into your Codex skills directory:

```bash
git clone https://github.com/karlligamesvc-spec/anthropic-account-self-audit.git
mkdir -p "${CODEX_HOME:-$HOME/.codex}/skills"
cp -R anthropic-account-self-audit/anthropic-account-self-audit "${CODEX_HOME:-$HOME/.codex}/skills/"
```

Restart Codex after installation so the new skill can be discovered.

## Usage

Ask Codex:

```text
Use $anthropic-account-self-audit to analyze my Claude Code / Anthropic account risk.
```

For a browser fingerprint consistency pass, mention browser language, timezone, proxy, GeoTime, or GeoMirror in the request.

The skill only applies local fixes after explicit user authorization.

## Safety Boundary

This skill is designed for legitimate policy compliance, account-integrity review, local security hygiene, and honest appeal preparation. Do not use it to bypass regional restrictions, hide prohibited activity, rotate accounts, evade enforcement, or continue unsupported use after enforcement.

## License

Add a license before broader redistribution.

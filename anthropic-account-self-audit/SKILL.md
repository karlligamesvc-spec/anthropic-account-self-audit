---
name: anthropic-account-self-audit
description: Run a Claude Code-focused local self-audit for Anthropic account suspension risk, optionally include GeoTime-Spoofer/GeoMirror-style browser fingerprint consistency checks, score the user's machine and workflow, ask for missing account/use-case facts, apply explicitly authorized low-risk local hygiene fixes, then produce compliant remediation or appeal materials. Use when the user mentions Anthropic account bans, Claude Code bans, suspended/disabled accounts, safeguard warnings, appeals, unsupported regions, policy compliance, API key/account sharing risk, Claude Code automation risk, local Claude Code environment risk scans, direct risk optimization, GeoTime-Spoofer, GeoMirror, browser timezone/locale/geolocation/language spoofing, or wants a checklist before using Claude Code at scale.
---

# Anthropic Account Self Audit

## Operating Stance

Help the user reduce legitimate policy and account-integrity risk. Do not provide tactics for evading enforcement, hiding location, bypassing regional restrictions, rotating accounts, defeating abuse detection, or continuing prohibited use after enforcement.

Treat official Anthropic pages as the source of truth. Because enforcement posture changes, verify current official policy pages before giving high-confidence advice when the task depends on "recent" or "latest" actions.

Never print secrets. When inspecting the local machine, report variable names, Claude Code file paths, permissions, counts, and shape hints only. Do not scan Claude Desktop/App caches or generic Claude CLI locations unless the user explicitly expands scope.

## Quick Workflow

1. Run the local scanner first unless the user explicitly asks to skip local inspection:

   ```bash
   python3 scripts/local_risk_scan.py --cwd "$PWD" --format json
   ```

   Use `--network` only when public egress/IP-region signals are relevant and acceptable for the task:

   ```bash
   python3 scripts/local_risk_scan.py --cwd "$PWD" --network --format json
   ```

   Use the optional browser fingerprint module when the user mentions GeoTime-Spoofer, GeoMirror, browser spoofing, timezone/locale/geolocation/language mismatches, Chrome extensions, VPN consistency, or account-region inconsistency:

   ```bash
   python3 scripts/local_risk_scan.py --cwd "$PWD" --network --browser-fingerprint --format json
   ```

   If the user explicitly authorizes direct low-risk remediation, run the fixer and then rescan:

   ```bash
   python3 scripts/local_risk_scan.py --cwd "$PWD" --network --browser-fingerprint --apply-low-risk-fixes --format markdown
   ```

   If the user also authorizes closing affected browsers before browser-language edits, add `--quit-browsers-for-fixes`. To update non-Chrome Chromium-family browsers such as Edge, Brave, Arc, or detected 360 profiles, add `--fix-all-chromium-languages`. To update Safari on macOS, add `--fix-safari-language`. On Windows, use the installed skill path, for example:

   ```powershell
   python "%USERPROFILE%\.codex\skills\anthropic-account-self-audit\scripts\local_risk_scan.py" --cwd "%CD%" --network --browser-fingerprint --apply-low-risk-fixes --format markdown
   ```

2. Confirm the case type:
   - `preflight`: user has not been warned or banned and wants a risk check.
   - `warning`: user received a safeguard warning or usage warning.
   - `suspension`: user was suspended, disabled, or banned.
   - `appeal`: user wants a concise appeal packet.

3. Gather only the facts the machine cannot know:
   - Product/auth path: Claude Code subscription login, Claude Code with API key, team/enterprise, reseller, or cloud marketplace.
   - Account region, billing country, usual login country, travel/VPN/proxy facts, and whether account creation occurred from a supported region.
   - Use cases, customer/user-facing status, minors/health/legal/finance/employment/government involvement, and whether the system is agentic or has tools/MCP/server access.
   - Automation pattern: request volume, concurrency, scraping/bulk workflows, account/key sharing, credential storage, and who can submit inputs.
   - Warning/ban text, timestamps, request IDs, relevant logs, and recent usage changes.

4. Check the latest official sources:
   - Anthropic Usage Policy.
   - Consumer or Commercial Terms of Service, depending on the product.
   - Safeguards warnings and appeals support page.
   - Transparency/System Trust page for current enforcement context.
   - Supported Region Policy or current support page for availability.
   Read `references/current-policy-signals.md` for known source links and risk categories.
   Read `references/browser-fingerprint-consistency.md` when interpreting the optional browser module. Treat community claims about language-based or nationality-based mass bans as unverified unless backed by official or independently verifiable sources.
   Treat claims about Claude Code hidden Unicode prompt markers, XOR-obfuscated domain lists, or China-specific local classifiers as unverified unless verified from the local package or strong independent sources; even local string matches prove presence of strings/patterns, not server-side use or intent.

5. Classify risk per category:
   - `critical`: likely policy violation, unsupported-region account creation/use, credential sharing, fraud indicators, or prohibited high-harm content.
   - `high`: unclear but plausible violation; missing controls for high-risk, agentic, consumer-facing, or tool-enabled use.
   - `medium`: compliance gaps that should be fixed before scaling.
   - `low`: no obvious issue, but document assumptions and monitoring.

6. Produce an output with:
   - A plain-language one-line conclusion first.
   - A simple score explanation, not just a numeric score.
   - A "what this skill can and cannot see" note before conclusions that depend on account history.
   - The top 3-5 things that matter, written for non-technical users.
   - Clear fixes the user can do now.
   - A "user-side self-check map" listing account, payment, login, device, request, warning, and appeal facts the agent cannot verify locally.
   - Questions for missing off-machine facts.
   - A complete optimization plan after combining local signals and user answers.
   - A compact technical appendix only after the plain-language report.
   - Appeal packet if relevant.

## Local Scan Interpretation

Use the scanner output as evidence, not as a final verdict. It checks local signals such as:

- Anthropic/Claude-related environment variable names without values.
- Claude Code config/state paths and file permissions.
- Installed Claude Code package paths/version and selected region/domain-check string patterns.
- Current repository and selected Claude Code local logs for Anthropic key-shaped strings.
- Proxy configuration and optional public egress region/cloud hints.
- Mixed-provider setup, such as Anthropic variable names pointed at non-Anthropic endpoints.
- macOS, Linux, and Windows Chromium-family profile language and extension metadata where available.
- Safari app-specific language on macOS, when Safari is present.

The default local scanner intentionally excludes Claude Desktop/App state such as `~/Library/Application Support/Claude` and generic `.config/claude` locations. The optional browser fingerprint module scans Chromium-family browser profiles and Safari language preferences only for metadata and consistency signals; it does not open the browser, attach a debugger, read browsing history, or reveal extension secrets.

When installed Claude Code package scanning is present, interpret:

- `ANTHROPIC_BASE_URL`, official API host strings, domain-check endpoint strings, `Asia/Shanghai`, `Asia/Urumqi`, short classifier labels, or date-prompt strings as local forensic evidence only.
- Do not claim these prove hidden transmission, steganography, account targeting, spyware behavior, or server-side enforcement. State exactly what was found and what remains unverified.
- If the user wants deeper reverse engineering, keep the task defensive: preserve version/path/hash evidence, compare against official packages, and avoid instructions for bypassing enforcement or removing signals to continue unsupported access.

When browser fingerprint scanning is enabled, interpret:

- `debugger` permission plus timezone/geolocation/locale/CDP override code as high-risk for account-environment consistency.
- `declarativeNetRequest` plus MAIN-world `document_start` scripts that patch `Date`, `Intl`, `navigator.geolocation`, `navigator.language`, or `Accept-Language` as GeoMirror-style browser environment rewriting.
- GeoTime-style storage keys such as `targetTimezone` and `isActive` as evidence that a browser environment spoofer may be configured.
- GeoMirror-style storage keys such as `tzEnabled`, `langEnabled`, `fontEnabled`, `acceptLanguage`, `ipTimezone`, or override coordinates as evidence that a browser environment spoofer may be configured.
- IP country vs system timezone or browser language mismatches as account-integrity questions, not proof of wrongdoing.

Score bands:

- `85-100`: low local-environment risk.
- `70-84`: medium local-environment risk.
- `50-69`: high local-environment risk.
- `<50`: critical local-environment risk.

Do not overstate local scan results. A clean local scan cannot prove account safety, and a risky local signal may be benign if the user can explain it.

## Capability Boundary

Frame the skill as a local environment and workflow hygiene audit, not a ban predictor or account-safety guarantee.

The skill can help with:

- Local Claude Code config hygiene, file permissions, and third-party env separation.
- Local secret-shape detection without printing secrets.
- Browser/profile language consistency, extension metadata, and GeoTime/GeoMirror-style signals.
- Public egress country/cloud hints when `--network` is authorized.
- Claude Code package string evidence, reported as observed local facts only.
- Plain-language remediation, evidence collection, and honest appeal preparation.

The skill cannot see:

- Anthropic's server-side risk score, enforcement model, or internal reason codes.
- Full account history: creation IP, historical login countries, device history, OAuth events, password resets, or failed logins.
- Payment and billing trust signals: card BIN/country, billing address validation, chargebacks, payment declines, tax/VAT details, or subscription history.
- Request-level server logs: prompt content, model routes, safety flags, rate-limit history, retries, concurrency, abuse classifier hits, or request IDs unless the user provides them.
- Organization/team state: workspace members, seat sharing, enterprise policy, admin audit logs, SCIM/SSO history, or API project access.
- Email and support state: warning emails, hidden images/tracking in emails, support ticket history, appeal outcomes, or trust-and-safety notes.
- Other devices and clients: mobile apps, browser profiles not present on this machine, remote servers, CI jobs, MCP servers, gateways, or shared scripts.

Always label these as "需要用户自己确认" rather than treating missing information as safe.

## Authorized Low-Risk Fixes

Only apply local changes after the user explicitly agrees. Before applying, say what will change and what will not change.

The script's `--apply-low-risk-fixes` may:

- Move known third-party env files such as `~/.claude/deepseek.env` out of Claude Code state into a separate `third-party-models` directory.
- Set Unix/macOS file modes for Claude Code settings and third-party env files to current-user-only access.
- Back up Chrome `Preferences` files and set Chrome language preference to `en-US,en` by default.
- On macOS, set Chrome's app-specific language defaults for `com.google.Chrome`.
- If `--fix-all-chromium-languages` is present, apply the same Chromium profile language edit to detected Edge, Brave, Arc, 360, and other Chromium-family profiles.
- If `--fix-safari-language` is present on macOS, set Safari's app-specific language defaults for `com.apple.Safari`.
- On Windows, scan and edit Chrome profile preferences under `%LOCALAPPDATA%\Google\Chrome\User Data`, and detected Chromium-family paths such as Edge/Brave/360 when `--fix-all-chromium-languages` is present; Windows ACL tightening is reported but not automatically changed.

The fixer must not:

- Modify Claude Code official binaries or package code.
- Change system timezone, proxy/VPN, account region, billing details, or unsupported-region access.
- Print API keys, OAuth tokens, cookies, or extension secrets.
- Force-close Chrome, Safari, or other browsers unless the user also authorizes `--quit-browsers-for-fixes`.

If Chrome language reverts after restart, explain that Chrome Sync or an active browser session may have rewritten the preference. Ask the user to close Chrome or authorize `--quit-browsers-for-fixes`, then rerun the fixer, and tell them to confirm the language in `chrome://settings/languages`.

Do not tell users to change every installed browser by default. Ask which browser/profile is used to sign in to Claude/Anthropic. Browsers never used for Anthropic account access are lower priority; report them as consistency context rather than urgent fixes.

Safari note: Safari is not Chromium and usually follows macOS global or app-specific language preferences. Use `--fix-safari-language` only after the user confirms Safari is used for Claude/Anthropic access. On newer macOS versions, Safari's container preference plist may be protected by privacy controls; if the fixer reports `PermissionError`, tell the user to set Safari's language in System Settings or grant the required local access, and verify in Safari Web Inspector with `navigator.language` and `navigator.languages` if needed.

360 note: 360 browsers are generally Chromium-family, but profile paths vary by edition and locale. The scanner detects common 360 paths on Windows/macOS when present. If not detected, ask the user for the browser's user-data/profile path instead of guessing.

## Plain-Language Reporting

Write for a user who is not a security engineer. Do not lead with raw audit jargon. Use this translation style:

- Say "你的网络看起来像从美国的云服务器出去" instead of "public egress is US cloud/datacenter".
- Say "电脑时区和浏览器语言像中国，但网络出口像美国" instead of "IP/browser locale mismatch".
- Say "这些 Claude Code 配置文件其他本机用户也可能读到" instead of "group/other readable".
- Say "这里有一个像 API key 的字符串，但不像 Anthropic 官方 key" instead of "generic sk-* shape".
- Say "第三方模型配置用了 Anthropic 变量名，容易混淆" instead of "provider variable namespace collision".

Required report shape:

1. `一句话结论`: one sentence with the practical meaning of the score.
2. `分数怎么理解`: explain the score as local environment risk, not an official ban probability.
3. `这个报告看不到什么`: concise list of server-side/account-side facts the scanner cannot verify.
4. `我看到的主要问题`: 3-5 numbered items, each with "发生了什么" and "为什么要紧".
5. `现在可以做的优化`: concrete actions; include commands only after explaining what they do.
6. `用户自己要查的清单`: grouped account/payment/login/device/request/warning checks.
7. `我还需要确认`: ask the minimum account/workflow questions needed to move from local risk to account risk.
8. `完整方案`: immediate fixes, account habits, monitoring/evidence, appeal prep if relevant.
9. `技术附录`: optional; include raw paths, permissions, and scanner details for advanced users.

Avoid fearmongering. If the score is `critical`, explain whether that means "local environment has several fixable risk signals" rather than implying the account is definitely unsafe.

## Risk Checklist

Review these areas directly, in this order:

1. Region and identity integrity:
   - Account created and used from supported locations.
   - Billing, phone, login, organization, and expected travel/VPN behavior are explainable.
   - No attempt to bypass unsupported-region restrictions.

2. Account and credential handling:
   - No account sharing, API key sharing, resale, credential pooling, or "many accounts for one workload" pattern.
   - Keys are stored securely, scoped where possible, rotated after exposure, and not embedded in client apps.
   - OAuth tokens, browser sessions, and Claude Code login state are not copied between machines.

3. Usage Policy fit:
   - No illegal activity, cyber abuse, fraud, impersonation, child safety violations, extremist content, unsafe weapons instructions, or other prohibited use.
   - High-risk use cases have required safeguards, human oversight, and legal/domain review.

4. Automation and traffic integrity:
   - No scraping, spam, abusive bulk generation, synthetic account creation, rate-limit bypass, or unattended harmful agent behavior.
   - Request spikes, parallelism, and retry loops are intentional and observable.
   - The user can explain recent request volume, concurrency, retry loops, agent tool use, MCP servers, and CI/remote jobs.

5. User-facing deployment:
   - End users cannot freely drive the model into prohibited workflows.
   - The app has abuse monitoring, escalation paths, content filters where appropriate, and logs sufficient for review.

6. Warnings and enforcement history:
   - Prior warnings were acknowledged and corrected.
   - Recent usage changes line up with the warning/ban timeline.
   - The user can provide concrete remediation, not only denial.

7. Account-side blind spots to ask about:
   - Account creation date, creation country/IP if known, product path, plan changes, failed payment attempts, chargebacks, card/billing country, and tax/billing profile.
   - Recent login countries, new devices, browser profiles, mobile app use, VPN/proxy changes, password resets, 2FA changes, OAuth re-logins, and suspicious-login emails.
   - Warnings, disabled notices, appeal tickets, email headers/screenshots, request IDs, and exact timestamps.
   - Prompt/use-case categories, sensitive domains, user-facing exposure, uploaded files, codebase access, tool permissions, and whether outputs go to third parties.
   - Sharing and delegation: family/team use, contractors, rented accounts, shared machines, copied tokens, API gateways, reverse proxies, MCP tools, CI jobs, and scheduled agents.

## Appeal Packet

For suspensions or bans, prepare a concise, factual packet:

- Account identifiers: email, organization ID, workspace, API project, approximate creation date.
- Enforcement details: suspension date, warning text, ticket ID, request IDs, affected product.
- Good-faith explanation: what likely triggered the action, or why it appears mistaken.
- Evidence: supported-region proof, billing consistency, logs showing benign use, abuse controls, key custody, remediation already completed.
- Remediation: disabled risky workflow, rotated keys, removed shared credentials, added rate limits, added human review, blocked unsupported users/use cases.
- Request: ask for review or reinstatement, and offer to provide additional logs.

Do not invent facts. If the user lacks evidence, say what evidence would help and keep the appeal honest.

## Output Template

```markdown
一句话结论：
<用一句人话说明现在最大的风险是什么，以及是否马上能修。>

分数怎么理解：
<score>/100，<低|中|高|严重>。这是本机环境风险分，不是 Anthropic 官方封号概率。

这个报告看不到什么：
- <账号历史、支付、登录、服务端请求、风控记录等需要用户自己确认。>

我看到的主要问题：
1. <问题名>
   发生了什么：...
   为什么要紧：...

现在可以做的优化：
- <先解释，再给命令或操作。>

用户自己要查的清单：
- 账号/支付：
- 登录/设备：
- 请求/自动化：
- 警告/申诉：

我还需要确认：
- ...

完整方案：
- 立刻修：
- 使用习惯：
- 证据留存：
- 如果已经被封/警告：

技术附录：
- 扫描范围：
- 关键路径：
- 原始风险信号：
```

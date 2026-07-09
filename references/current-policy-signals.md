# Current Policy Signals

Use this reference for source selection and risk framing. Re-check the live pages when the user asks about recent or latest enforcement.

## Official Sources To Check

- Anthropic Usage Policy: https://www.anthropic.com/legal/aup
- Anthropic Transparency Hub / System Trust and Reporting: https://www.anthropic.com/transparency/system-trust-reporting
- Claude Help Center safeguards warnings and appeals: https://support.claude.com/en/articles/8241253-safeguards-warnings-and-appeals
- Consumer Terms of Service: https://www.anthropic.com/legal/consumer-terms
- Commercial Terms of Service: https://www.anthropic.com/legal/commercial-terms
- Anthropic support center: https://support.claude.com/

## Enforcement Context Verified July 2026

- The Usage Policy page states that Anthropic may throttle, suspend, or terminate access when it learns a user violated its Usage Policy. It also says Anthropic's Safeguards Team uses detection and monitoring to enforce the policy.
- The Transparency Hub's System Trust and Reporting page, last updated January 29, 2026, reports 1.45 million banned accounts, 52k appeals, and 1.7k appeal overturns for July-December 2025.
- The safeguards warnings and appeals support page, updated June 12, 2026, lists example ban reasons including repeated Usage Policy violations, account creation from an unsupported location, Terms of Service violations, and detected suspicious or fraudulent activity.
- Consumer Terms state that users must provide correct, current, and complete account information; must not share login information, API keys, or account credentials; and are responsible for activity under the account.

## High-Signal Risk Categories

1. Unsupported-region risk:
   - Account created from or routinely operated from an unsupported location.
   - Billing, phone, login country, or organization geography conflicts with supported-region rules.
   - User asks how to bypass regional restrictions, mask location, or keep access after an unsupported-region warning.

2. Account-integrity risk:
   - Shared Claude account, shared API key, pooled credentials, resale, account farming, or multiple accounts used to distribute one workload.
   - API keys embedded in public repos, client apps, browser extensions, or third-party services without custody controls.

3. Usage Policy risk:
   - Illegal activity, cyber abuse, fraud, impersonation, evasion, child safety, extremist, weapons, or other prohibited domains.
   - High-risk consumer-facing use without required safeguards and oversight.

4. Automation and abuse risk:
   - Unbounded agents, tool-enabled workflows, mass messaging, scraping, spam, or suspicious traffic spikes.
   - Retrying around rate limits, using multiple accounts to increase throughput, or ignoring warnings.

5. Appeal-quality risk:
   - Vague denial without evidence.
   - No remediation plan.
   - Contradictory facts about region, billing, identity, or key custody.

## Unverified Community Claims

Users may cite community reports that Anthropic is banning accounts based on Simplified Chinese usage, language volume, nationality, hidden Claude Code prompt markers, XOR-obfuscated proxy/domain lists, China-specific timezone checks, or similar inferred traits. Do not repeat these as fact unless confirmed by official Anthropic sources or strong independent evidence.

For local Claude Code package inspection, distinguish three levels:

- `observed`: exact local package version, file path, hash prefix, and string/pattern categories found on disk.
- `inferred`: a plausible purpose, such as domain classification or environment consistency checking.
- `unverified`: claims about hidden transmission, steganography, account targeting, spyware behavior, or server-side enforcement.

Keep the audit focused on observable, remediable signals: account region, billing country, network consistency, credential sharing, Usage Policy fit, warning history, local environment consistency, and local package evidence that can be preserved for review.

## Refusal Boundary

Refuse or redirect requests for bypasses, evasion, fake documents, unsupported-region access, account rotation, ban evasion, abuse at scale, or hiding prohibited use. Offer compliant alternatives: stop the risky workflow, use officially supported regions/products, appeal honestly, or redesign the use case with safeguards.

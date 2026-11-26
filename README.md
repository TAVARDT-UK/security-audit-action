<p align="center">
  <a href="https://ag.tavardt.com/uk/">
    <img src="https://ag.tavardt.com/img/tavardt-banner.png" alt="TAVARDT" width="1024" />
  </a>
</p>

# Security & Perimeter Audit Action

[![Verification Suite](https://img.shields.io/badge/Diagnostic%20Suite-TAVARDT%20Tools-5b3cf5.svg)](https://tools.tavardt.com/uk/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

An automated continuous security verification Action for GitHub workflows. Tests web perimeters against misconfigured HTTP security headers (CSP, HSTS), missing email spoofing records (DMARC), and critical `.env` credential leaks.

Engineered and maintained by the DevSecOps and cyber defence practice at **TAVARDT**.

***

## 1. Automated Quality Gate Architecture

The Action provides automated security testing directly within GitHub Actions pipelines. It evaluates public perimeters across three critical defensive dimensions without requiring third-party runtime dependencies:

* **HTTP Security Headers Inspection**: Probes the target web application to verify the presence of essential security directives. It scores implementations of `Strict-Transport-Security` (HSTS), `Content-Security-Policy` (CSP), `X-Frame-Options`, `X-Content-Type-Options`, and `Referrer-Policy`.
* **Domain Authentication and Email Anti-Spoofing**: Resolves DNS records asynchronously to verify that a valid `v=DMARC1` record protects the domain. This check ensures that adversaries cannot impersonate your organisation in phishing or invoice fraud attacks.
* **Perimeter Secret Exposure Detection**: Requests root configuration paths to verify that sensitive environment files remain protected. Detecting an accessible `.env` file triggers an immediate critical alert and resets the security score to zero.

***

## 2. Threat Vectors and Operational Risk Mitigation

Deploying web applications with misconfigured headers or exposed credentials introduces catastrophic risks into production environments. The Action defends against four critical attack vectors:

* **Session Interception and Protocol Downgrades**: Missing HSTS headers enable adversaries to perform SSL stripping and intercept plaintext traffic. Enforcing strict transport rules ensures all user sessions remain securely encrypted over TLS channels.
* **Clickjacking and Cross-Site Script Injection**: Inadequate CSP and missing frame options permit UI redressing and malicious script execution. Hardened headers instruct browsers to isolate application rendering and prevent unauthorized data exfiltration.
* **Domain Brand Impersonation and Email Spoofing**: Missing DMARC records allow malicious actors to forge emails originating from your domain. Deploying DMARC policies ensures fraudulent messages are rejected by recipient mail servers.
* **Credential and Environment Key Exfiltration**: Publicly readable `.env` files expose database credentials, encryption salts, and private API keys. The Action validates file isolation to prevent unauthorized access to backend cloud infrastructure.

***

## 3. Workflow Integration and Configuration

Incorporate the security verification step into your deployment workflows or scheduled monitoring pipelines:

```yaml
name: Security Audit

on:
  push:
    branches: [main]
  schedule:
    - cron: '0 8 * * 1'

jobs:
  perimeter-audit:
    runs-on: ubuntu-latest
    steps:
      - name: Run TAVARDT Security Verification
        uses: TAVARDT-UK/security-audit-action@main
        with:
          target-url: 'example.com'
          fail-on-critical: 'false'
```

### Action Inputs and Execution Parameters

Configure the audit step using the following input parameters:

* **`target-url` (Required)**: The target domain or web application URL to inspect, accepted with or without protocol prefixes.
* **`fail-on-critical` (Optional)**: Set to `'true'` to terminate the workflow job with exit code 1 whenever critical vulnerabilities or exposed secrets are discovered. Defaults to `'false'`.

### Action Outputs and Summary Reporting

The Action provides structured outputs and automatic reporting for automated pipelines:

* **`audit-score`**: Numerical score from 0 to 100 representing the overall security posture of the audited domain.
* **`critical-alerts`**: Integer count of detected high-severity issues, including missing DMARC records or exposed `.env` files.
* **Workflow Step Summary**: Emits a formatted markdown breakdown directly into the GitHub Actions run summary view.

***

## 4. Frequently Asked Technical Questions (FAQ)

### How does the Action calculate the overall security score and assess perimeter posture?
The Action evaluates the target domain across security header presence, DMARC record configuration, and sensitive environment file exposure starting from a baseline score of 100. Points are deducted based on missing defensive headers and lack of email authentication, while an exposed .env file immediately resets the score to zero.

### How does the fail-on-critical configuration parameter enforce quality gates in CI/CD pipelines?
When fail-on-critical is set to true, the Action inspects the tally of discovered critical vulnerabilities upon completing the audit. If a missing DMARC record or exposed .env configuration is detected, the process terminates with exit code 1 to halt downstream deployment jobs.

### What specific security risks does the automated DMARC DNS inspection mitigate?
The Action performs asynchronous DNS resolution against the target domain to verify the existence of an active v=DMARC1 policy record. Enforcing DMARC prevents cyber adversaries from sending spoofed emails under your corporate domain, mitigating phishing campaigns and business email compromise.

### Why does an exposed .env file trigger an immediate critical alert and zero score?
Publicly accessible .env files contain database connection strings, API tokens, and cryptographic secrets that allow adversaries to compromise backend systems directly. Because this exposure represents an imminent high-severity data breach, the Action categorises it as a critical failure requiring immediate remediation.

### How does the Action communicate inspection results directly within GitHub workflow runs?
The Action formats an audit report and appends it to the workflow step summary file referenced by the GITHUB_STEP_SUMMARY environment variable. This integration allows engineering teams and pull request reviewers to inspect security scores and header statuses directly in the GitHub Actions UI.

***

## Useful Links

* **Corporate Portal:** https://ag.tavardt.com/uk/
* **Diagnostic Suite:** https://tools.tavardt.com/uk/
* **Technical Contact:** https://ag.tavardt.com/uk/contact/

***

## License

Released under the MIT License.

***

© 2026 TAVARDT. All rights reserved.

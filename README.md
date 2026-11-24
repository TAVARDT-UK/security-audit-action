# Security & Perimeter Audit Action

[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-TAVARDT%20Security%20Action-blueviolet.svg)](https://github.com/marketplace)
[![Verification Suite](https://img.shields.io/badge/Diagnostic%20Suite-TAVARDT%20Tools-5b3cf5.svg)](https://tools.tavardt.com/uk/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

An automated continuous security verification Action for GitHub workflows. Tests web perimeters against misconfigured HTTP security headers (CSP, HSTS), missing email spoofing records (DMARC), and critical `.env` credential leaks.

Maintained by **TAVARDT**.

***

## 1. Quick Usage

Add this step to any GitHub workflow (e.g., `.github/workflows/deploy.yml` or a scheduled health check):

```yaml
name: Security & Health Check

on:
  push:
    branches: [main]
  schedule:
    - cron: '0 8 * * 1' # Weekly on Monday

jobs:
  perimeter-audit:
    runs-on: ubuntu-latest
    steps:
      - name: Run TAVARDT Security Verification
        uses: TAVARDT/security-audit-action@main
        with:
          target-url: 'example.com'
          fail-on-critical: 'false'
```

***

## 2. Inputs & Configuration

| Parameter | Required | Default | Description |
|-|-|-|-|
| `target-url` | Yes | N/A | Target domain or web application URL to audit. |
| `fail-on-critical` | No | `'false'` | Whether to fail the workflow build if a critical vulnerability is detected. |

***

## 3. What the Action Validates

1. **HTTP Security Headers:** Validates presence and strictness of HSTS, Content Security Policy (CSP), X-Frame-Options, X-Content-Type-Options, and Referrer-Policy.
2. **Email Brand Protection (DMARC):** Checks DNS zone records to ensure adversaries cannot forge emails from your company domain.
3. **Sensitive Credential Exposure:** Verifies that public root paths do not expose `.env` files or database configuration backups.
4. **GitHub Step Summary:** Emits a formatted markdown table directly into your workflow execution report.

***

## 4. Online Diagnostic Suite & Enterprise Engineering

To run an interactive manual audit or access the 20 specialized tools:

* **TAVARDT Online Diagnostic Suite**: 20 free technical tools.
* [DMARC & Spoofing Validator](https://tools.tavardt.com/uk/dmarc-checker/): In-depth DNS and deliverability diagnostics.
* [Security Headers Analyzer](https://tools.tavardt.com/uk/security-headers-check/): Instant header remediation code generator.
* **TAVARDT Corporate Cyber Defence**: Enterprise hardening, pentesting, and incident response.

***

## License

Released under the MIT License. Copyright

***

© 2026 TAVARDT. All rights reserved.

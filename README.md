HTTP Security Header Analyzer

A lightweight Python CLI tool that fetches HTTP response headers from any URL and audits them against a checklist of essential security headers. Get a security score, see what's missing, and know what to fix.

---

## Features

- Fetches all HTTP response headers from a target URL
- Checks for 8 critical security headers
- Shows recommended values for any missing headers
- Displays a security score (e.g. `62% — 5/8 headers present`)
- Verbose mode to dump all response headers
- Handles redirects and SSL fallback automatically
- Color-coded terminal output (✓ green / ✗ red)

---

## Security Headers Checked

| Header | Purpose |
|---|---|
| `Strict-Transport-Security` | Enforces HTTPS connections |
| `Content-Security-Policy` | Prevents XSS and injection attacks |
| `X-Content-Type-Options` | Prevents MIME-type sniffing |
| `X-Frame-Options` | Prevents clickjacking |
| `X-XSS-Protection` | Enables browser XSS filtering |
| `Referrer-Policy` | Controls referrer information leakage |
| `Permissions-Policy` | Restricts access to browser APIs |
| `Cache-Control` | Controls caching of sensitive responses |

---

## Requirements

- Python 3.7+
- `requests` library

---


---

## Usage

```bash
python security_headers.py <url> [options]
```

### Arguments

| Argument | Description |
|---|---|
| `url` | Target URL to check (e.g. `https://example.com`) |
| `-v`, `--verbose` | Print all response headers, not just security-related ones |
| `-t`, `--timeout` | Request timeout in seconds (default: `10`) |

### Examples

```bash
# Basic check
python security_headers.py https://example.com

# Show all response headers
python security_headers.py https://example.com --verbose

# Custom timeout
python security_headers.py https://example.com --timeout 5

# URL without scheme (auto-prepends https://)
python security_headers.py example.com
```

---

## Sample Output

```
Checking headers for: https://example.com
============================================================
  Security Header Check
============================================================
  URL       : https://example.com
  Status    : 200
  Server    : ECS (dcb/7F84)
============================================================

[ ✓ Present Security Headers (3) ]
  ✓ X-Content-Type-Options
      Value : nosniff
      Info  : Prevents MIME-type sniffing

  ✓ Cache-Control
      Value : max-age=604800
      Info  : Controls caching behavior

  ✓ X-XSS-Protection
      Value : 1; mode=block
      Info  : Enables browser XSS filtering

[ ✗ Missing Security Headers (5) ]
  ✗ Strict-Transport-Security
      Info       : Enforces HTTPS connections
      Recommended: max-age=31536000; includeSubDomains

  ✗ Content-Security-Policy
      Info       : Prevents XSS and injection attacks
      Recommended: default-src 'self'

  ✗ X-Frame-Options
      Info       : Prevents clickjacking
      Recommended: DENY or SAMEORIGIN

  ✗ Referrer-Policy
      Info       : Controls referrer information
      Recommended: strict-origin-when-cross-origin

  ✗ Permissions-Policy
      Info       : Controls browser features/APIs
      Recommended: geolocation=(), microphone=(), camera=()

  Security Score: 38% (3/8 headers present)
============================================================
```

---

## Project Structure

```
seccheck/
├── security_headers.py   # Main CLI script
├── requirements.txt      # Python dependencies
└── README.md             # This file
```

---

---

## Disclaimer

This tool checks publicly visible HTTP response headers only. It does not perform penetration testing, vulnerability scanning, or any intrusive analysis. Always ensure you have permission before scanning any URLs you do not own.

---

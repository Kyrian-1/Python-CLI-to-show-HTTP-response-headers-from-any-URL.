#!/usr/bin/env python3
"""
Security Headers Checker
A CLI tool that fetches server headers and audits for missing security headers.
"""

import sys
import argparse
import urllib.request
import urllib.error
import json
from datetime import datetime

# ANSI color codes
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "description": "Enforces HTTPS connections (HSTS)",
        "severity": "HIGH",
        "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    },
    "Content-Security-Policy": {
        "description": "Prevents XSS and data injection attacks",
        "severity": "HIGH",
        "recommendation": "Add a CSP policy, e.g.: Content-Security-Policy: default-src 'self'",
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME-type sniffing",
        "severity": "MEDIUM",
        "recommendation": "Add: X-Content-Type-Options: nosniff",
    },
    "X-Frame-Options": {
        "description": "Protects against clickjacking attacks",
        "severity": "MEDIUM",
        "recommendation": "Add: X-Frame-Options: DENY  or  SAMEORIGIN",
    },
    "X-XSS-Protection": {
        "description": "Enables browser XSS filtering (legacy)",
        "severity": "LOW",
        "recommendation": "Add: X-XSS-Protection: 1; mode=block",
    },
    "Referrer-Policy": {
        "description": "Controls referrer information sent with requests",
        "severity": "MEDIUM",
        "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "description": "Controls browser feature permissions",
        "severity": "MEDIUM",
        "recommendation": "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()",
    },
    "Cross-Origin-Opener-Policy": {
        "description": "Isolates browsing context to prevent cross-origin attacks",
        "severity": "MEDIUM",
        "recommendation": "Add: Cross-Origin-Opener-Policy: same-origin",
    },
    "Cross-Origin-Resource-Policy": {
        "description": "Prevents cross-origin resource loading",
        "severity": "LOW",
        "recommendation": "Add: Cross-Origin-Resource-Policy: same-origin",
    },
    "Cross-Origin-Embedder-Policy": {
        "description": "Controls cross-origin resource embedding",
        "severity": "LOW",
        "recommendation": "Add: Cross-Origin-Embedder-Policy: require-corp",
    },
}

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
SEVERITY_COLORS = {"HIGH": RED, "MEDIUM": YELLOW, "LOW": CYAN}


def normalize_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def fetch_headers(url: str, timeout: int = 10) -> tuple[dict, int, str]:
    req = urllib.request.Request(url, method="HEAD")
    req.add_header("User-Agent", "SecurityHeadersChecker/1.0")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            headers = dict(response.headers)
            status = response.status
            final_url = response.url
    except urllib.error.HTTPError as e:
        headers = dict(e.headers)
        status = e.code
        final_url = url
    return headers, status, final_url


def audit_headers(headers: dict) -> tuple[list, list]:
    headers_lower = {k.lower(): v for k, v in headers.items()}
    present = []
    missing = []

    for header, info in SECURITY_HEADERS.items():
        if header.lower() in headers_lower:
            present.append((header, headers_lower[header.lower()], info))
        else:
            missing.append((header, info))

    missing.sort(key=lambda x: SEVERITY_ORDER[x[1]["severity"]])
    return present, missing


def print_banner():
    print(f"\n{BOLD}{CYAN}{'═' * 60}{RESET}")
    print(f"{BOLD}{CYAN}   🔒 Security Headers Checker{RESET}")
    print(f"{BOLD}{CYAN}{'═' * 60}{RESET}\n")


def print_section(title: str):
    print(f"\n{BOLD}{title}{RESET}")
    print(f"{DIM}{'─' * 50}{RESET}")


def severity_badge(severity: str) -> str:
    color = SEVERITY_COLORS.get(severity, RESET)
    return f"{color}[{severity}]{RESET}"


def run_check(url: str, output_json: bool = False, timeout: int = 10):
    url = normalize_url(url)

    if not output_json:
        print_banner()
        print(f"  {BOLD}Target:{RESET} {url}")
        print(f"  {BOLD}Time:  {RESET} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    try:
        headers, status, final_url = fetch_headers(url, timeout)
    except urllib.error.URLError as e:
        msg = f"Failed to connect to {url}: {e.reason}"
        if output_json:
            print(json.dumps({"error": msg}))
        else:
            print(f"\n{RED}✗ Error: {msg}{RESET}\n")
        sys.exit(1)
    except Exception as e:
        msg = f"Unexpected error: {e}"
        if output_json:
            print(json.dumps({"error": msg}))
        else:
            print(f"\n{RED}✗ Error: {msg}{RESET}\n")
        sys.exit(1)

    present, missing = audit_headers(headers)
    score = int((len(present) / len(SECURITY_HEADERS)) * 100)

    if output_json:
        result = {
            "url": final_url,
            "status_code": status,
            "score": score,
            "present_headers": [
                {"header": h, "value": v, "description": i["description"]}
                for h, v, i in present
            ],
            "missing_headers": [
                {
                    "header": h,
                    "severity": i["severity"],
                    "description": i["description"],
                    "recommendation": i["recommendation"],
                }
                for h, i in missing
            ],
        }
        print(json.dumps(result, indent=2))
        return

    # Status line
    status_color = GREEN if 200 <= status < 300 else YELLOW if status < 500 else RED
    print(f"  {BOLD}Status:{RESET} {status_color}{status}{RESET}")
    if final_url != url:
        print(f"  {BOLD}Redirected to:{RESET} {final_url}")

    # Security score
    score_color = GREEN if score >= 70 else YELLOW if score >= 40 else RED
    print(f"  {BOLD}Security Score:{RESET} {score_color}{score}/100{RESET}")

    # All response headers
    print_section("📋 All Response Headers")
    for k, v in sorted(headers.items()):
        print(f"  {DIM}{k}:{RESET} {v}")

    # Present security headers
    print_section(f"✅ Present Security Headers ({len(present)}/{len(SECURITY_HEADERS)})")
    if present:
        for header, value, info in present:
            print(f"  {GREEN}✓{RESET} {BOLD}{header}{RESET}")
            print(f"    {DIM}Value:{RESET} {value}")
    else:
        print(f"  {RED}None found.{RESET}")

    # Missing security headers
    print_section(f"❌ Missing Security Headers ({len(missing)}/{len(SECURITY_HEADERS)})")
    if missing:
        for header, info in missing:
            badge = severity_badge(info["severity"])
            print(f"  {RED}✗{RESET} {BOLD}{header}{RESET}  {badge}")
            print(f"    {DIM}Why:{RESET} {info['description']}")
            print(f"    {DIM}Fix:{RESET} {info['recommendation']}")
            print()
    else:
        print(f"  {GREEN}All security headers are present! 🎉{RESET}")

    # Summary
    print(f"{BOLD}{CYAN}{'═' * 60}{RESET}")
    high   = sum(1 for _, i in missing if i["severity"] == "HIGH")
    medium = sum(1 for _, i in missing if i["severity"] == "MEDIUM")
    low    = sum(1 for _, i in missing if i["severity"] == "LOW")
    print(
        f"  Missing: {RED}{high} HIGH{RESET}  "
        f"{YELLOW}{medium} MEDIUM{RESET}  "
        f"{CYAN}{low} LOW{RESET}"
    )
    print(f"{BOLD}{CYAN}{'═' * 60}{RESET}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Check a URL for missing HTTP security headers.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python security_headers.py https://example.com
  python security_headers.py example.com
  python security_headers.py https://example.com --json
  python security_headers.py https://example.com --timeout 5
        """,
    )
    parser.add_argument("url", help="Target URL to check (e.g. https://example.com)")
    parser.add_argument(
        "--json", dest="output_json", action="store_true", help="Output results as JSON"
    )
    parser.add_argument(
        "--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)"
    )

    args = parser.parse_args()
    run_check(args.url, output_json=args.output_json, timeout=args.timeout)


if __name__ == "__main__":
    main()

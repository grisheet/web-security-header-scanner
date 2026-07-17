#!/usr/bin/env python3
"""
Web Security Header Scanner
===========================

A defensive security tool that inspects the HTTP response headers of one or more
URLs and reports on the site's security-header posture: which recommended headers
are missing, which are present but weak/misconfigured, a per-issue severity, a
letter grade (A-F), and concrete fix recommendations.

Usage
-----
    # Single URL
    python header_scanner.py --url https://example.com

    # Multiple URLs from a file (one per line, '#' comments allowed)
    python header_scanner.py --input urls.txt

    # JSON output
    python header_scanner.py --url https://example.com --format json

    # Tune concurrency / timeout
    python header_scanner.py --input urls.txt --concurrency 20 --timeout 15

Only standard, read-only HTTP GET requests are made. No payloads, no
exploitation, no auth bypass — this simply reads what a server voluntarily
returns and grades it against public best-practice guidance (OWASP / MDN).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Callable, Optional

import httpx


# --------------------------------------------------------------------------- #
# Severity + grading primitives
# --------------------------------------------------------------------------- #

class Severity(str, Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"

    @property
    def penalty(self) -> int:
        """Points deducted from a 100-point score when this issue is present."""
        return {"High": 25, "Medium": 12, "Low": 5}[self.value]


@dataclass
class Finding:
    header: str
    status: str                 # "missing" | "weak" | "ok"
    severity: Optional[str]     # None when status == "ok"
    detail: str
    recommendation: str
    observed: Optional[str] = None


@dataclass
class ScanResult:
    url: str
    final_url: Optional[str] = None
    status_code: Optional[int] = None
    reachable: bool = True
    error: Optional[str] = None
    redirected: bool = False
    score: int = 100
    grade: str = "A"
    findings: list = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        return d


# --------------------------------------------------------------------------- #
# Header check definitions
#
# Each checker receives the (case-insensitively) fetched header value or None
# and returns a Finding. Keeping every header's logic in its own small function
# makes the rules easy to audit and extend.
# --------------------------------------------------------------------------- #

def _check_hsts(value: Optional[str]) -> Finding:
    name = "Strict-Transport-Security"
    if value is None:
        return Finding(name, "missing", Severity.HIGH.value,
                       "HSTS not set; connection can be downgraded to HTTP (MITM risk).",
                       "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload")
    max_age = _extract_max_age(value)
    if max_age is None:
        return Finding(name, "weak", Severity.MEDIUM.value,
                       "HSTS present but no valid max-age directive.",
                       "Set a max-age of at least 15552000 (180 days).", observed=value)
    if max_age < 15552000:
        return Finding(name, "weak", Severity.MEDIUM.value,
                       f"HSTS max-age={max_age} is below the recommended 15552000 (180 days).",
                       "Increase max-age to >= 31536000 and add includeSubDomains; preload.",
                       observed=value)
    return Finding(name, "ok", None, "HSTS configured with a strong max-age.",
                   "No change needed.", observed=value)


def _check_csp(value: Optional[str]) -> Finding:
    name = "Content-Security-Policy"
    if value is None:
        return Finding(name, "missing", Severity.HIGH.value,
                       "No CSP; page has no first line of defense against XSS/data injection.",
                       "Define a CSP starting from default-src 'self' and tighten from there.")
    lowered = value.lower()
    weaknesses = []
    if "unsafe-inline" in lowered:
        weaknesses.append("allows 'unsafe-inline'")
    if "unsafe-eval" in lowered:
        weaknesses.append("allows 'unsafe-eval'")
    if "default-src *" in lowered or " src *" in lowered or lowered.strip().endswith("*"):
        weaknesses.append("uses a wildcard '*' source")
    if "default-src" not in lowered and "script-src" not in lowered:
        weaknesses.append("no default-src or script-src directive")
    if weaknesses:
        return Finding(name, "weak", Severity.MEDIUM.value,
                       "CSP present but " + "; ".join(weaknesses) + ".",
                       "Remove unsafe-inline/unsafe-eval and wildcards; prefer nonces or hashes.",
                       observed=value)
    return Finding(name, "ok", None, "CSP present with no obvious wildcard/unsafe directives.",
                   "No change needed.", observed=value)


def _check_x_frame_options(value: Optional[str]) -> Finding:
    name = "X-Frame-Options"
    if value is None:
        return Finding(name, "missing", Severity.MEDIUM.value,
                       "Clickjacking protection absent (no X-Frame-Options).",
                       "Add X-Frame-Options: DENY (or SAMEORIGIN), or use CSP frame-ancestors.")
    v = value.strip().upper()
    if v in {"DENY", "SAMEORIGIN"}:
        return Finding(name, "ok", None, f"Frame embedding restricted ({v}).",
                       "No change needed.", observed=value)
    if v.startswith("ALLOW-FROM"):
        return Finding(name, "weak", Severity.LOW.value,
                       "ALLOW-FROM is deprecated and ignored by modern browsers.",
                       "Switch to CSP frame-ancestors, or use DENY/SAMEORIGIN.", observed=value)
    return Finding(name, "weak", Severity.LOW.value,
                   f"Unrecognized X-Frame-Options value '{value}'.",
                   "Use DENY or SAMEORIGIN.", observed=value)


def _check_x_xss_protection(value: Optional[str]) -> Finding:
    name = "X-XSS-Protection"
    # Note: this header is deprecated. Best practice today is to set it to "0"
    # (disable the buggy legacy auditor) and rely on CSP instead.
    if value is None:
        return Finding(name, "missing", Severity.LOW.value,
                       "Legacy header absent. Modern guidance is to disable the auditor via '0' "
                       "and rely on CSP.",
                       "Optionally add X-XSS-Protection: 0 and ensure a strong CSP is present.")
    v = value.strip()
    if v == "0" or v.startswith("1; mode=block"):
        return Finding(name, "ok", None, "Configured per current guidance.",
                       "No change needed.", observed=value)
    return Finding(name, "weak", Severity.LOW.value,
                   "Enabled without mode=block; the legacy auditor can introduce issues.",
                   "Set to '0' and rely on CSP, or use '1; mode=block'.", observed=value)


def _check_x_content_type_options(value: Optional[str]) -> Finding:
    name = "X-Content-Type-Options"
    if value is None:
        return Finding(name, "missing", Severity.MEDIUM.value,
                       "MIME-sniffing not disabled; browsers may misinterpret content types.",
                       "Add X-Content-Type-Options: nosniff")
    if value.strip().lower() == "nosniff":
        return Finding(name, "ok", None, "MIME sniffing disabled.", "No change needed.",
                       observed=value)
    return Finding(name, "weak", Severity.LOW.value,
                   f"Unexpected value '{value}'.", "Set exactly to 'nosniff'.", observed=value)


def _check_referrer_policy(value: Optional[str]) -> Finding:
    name = "Referrer-Policy"
    strong = {
        "no-referrer", "no-referrer-when-downgrade", "same-origin",
        "strict-origin", "strict-origin-when-cross-origin",
    }
    if value is None:
        return Finding(name, "missing", Severity.LOW.value,
                       "No Referrer-Policy; full URLs may leak to third parties.",
                       "Add Referrer-Policy: strict-origin-when-cross-origin")
    # A Referrer-Policy may list several tokens; browsers apply the last one
    # they recognize, so evaluate against that effective value.
    tokens = [t.strip().lower() for t in value.split(",") if t.strip()]
    known = strong | {"unsafe-url", "origin-when-cross-origin", "origin", "no-referrer-when-downgrade"}
    effective = next((t for t in reversed(tokens) if t in known), tokens[-1] if tokens else "")
    v = effective
    if v in {"unsafe-url", "origin-when-cross-origin"}:
        return Finding(name, "weak", Severity.LOW.value,
                       f"'{v}' can leak referrer data across origins.",
                       "Use strict-origin-when-cross-origin or no-referrer.", observed=value)
    if v in strong:
        return Finding(name, "ok", None, "Sensible referrer policy set.",
                       "No change needed.", observed=value)
    return Finding(name, "weak", Severity.LOW.value,
                   f"Unrecognized policy '{value}'.",
                   "Use strict-origin-when-cross-origin.", observed=value)


def _check_permissions_policy(value: Optional[str]) -> Finding:
    name = "Permissions-Policy"
    if value is None:
        return Finding(name, "missing", Severity.LOW.value,
                       "No Permissions-Policy; powerful browser features are not restricted.",
                       "Add a policy disabling unused features, e.g. "
                       "Permissions-Policy: geolocation=(), camera=(), microphone=()")
    return Finding(name, "ok", None, "Permissions-Policy present.",
                   "Review that it restricts the features you actually don't use.",
                   observed=value)


# Ordered registry of all checks. Header name -> checker function.
CHECKS: dict[str, Callable[[Optional[str]], Finding]] = {
    "Strict-Transport-Security": _check_hsts,
    "Content-Security-Policy": _check_csp,
    "X-Frame-Options": _check_x_frame_options,
    "X-XSS-Protection": _check_x_xss_protection,
    "X-Content-Type-Options": _check_x_content_type_options,
    "Referrer-Policy": _check_referrer_policy,
    "Permissions-Policy": _check_permissions_policy,
}


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _extract_max_age(value: str) -> Optional[int]:
    for part in value.split(";"):
        part = part.strip().lower()
        if part.startswith("max-age"):
            try:
                return int(part.split("=", 1)[1].strip())
            except (IndexError, ValueError):
                return None
    return None


def _grade_from_score(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def _evaluate(headers: httpx.Headers) -> tuple[list[Finding], int, str]:
    """Run every check, compute the score, derive a grade."""
    findings: list[Finding] = []
    score = 100
    for header_name, checker in CHECKS.items():
        # httpx.Headers lookup is case-insensitive.
        value = headers.get(header_name)
        finding = checker(value)
        findings.append(finding)
        if finding.severity is not None:
            score -= Severity(finding.severity).penalty
    score = max(0, score)
    return findings, score, _grade_from_score(score)


# --------------------------------------------------------------------------- #
# Scanning
# --------------------------------------------------------------------------- #

async def scan_url(client: httpx.AsyncClient, url: str) -> ScanResult:
    """Fetch a single URL and evaluate its headers. Never raises."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    try:
        resp = await client.get(url)
    except httpx.HTTPError as exc:
        return ScanResult(url=url, reachable=False, error=f"{type(exc).__name__}: {exc}",
                          score=0, grade="F")

    findings, score, grade = _evaluate(resp.headers)
    final_url = str(resp.url)
    return ScanResult(
        url=url,
        final_url=final_url,
        status_code=resp.status_code,
        reachable=True,
        redirected=(final_url != url),
        score=score,
        grade=grade,
        findings=[asdict(f) for f in findings],
    )


async def scan_all(urls: list[str], concurrency: int, timeout: float) -> list[ScanResult]:
    """Scan many URLs concurrently, capping in-flight requests with a semaphore."""
    limits = httpx.Limits(max_connections=concurrency)
    sem = asyncio.Semaphore(concurrency)
    headers = {"User-Agent": "SecurityHeaderScanner/1.0 (+defensive-recon)"}

    async with httpx.AsyncClient(
        follow_redirects=True,
        timeout=timeout,
        limits=limits,
        headers=headers,
    ) as client:
        async def _guarded(u: str) -> ScanResult:
            async with sem:
                return await scan_url(client, u)

        return await asyncio.gather(*[_guarded(u) for u in urls])


# --------------------------------------------------------------------------- #
# Output rendering
# --------------------------------------------------------------------------- #

# ANSI colors (auto-disabled when not writing to a TTY).
class _C:
    RESET = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"
    RED = "\033[31m"; GREEN = "\033[32m"; YELLOW = "\033[33m"
    BLUE = "\033[34m"; CYAN = "\033[36m"


def _color_enabled() -> bool:
    return sys.stdout.isatty()


def _c(text: str, color: str) -> str:
    return f"{color}{text}{_C.RESET}" if _color_enabled() else text


def _grade_color(grade: str) -> str:
    return {"A": _C.GREEN, "B": _C.GREEN, "C": _C.YELLOW,
            "D": _C.YELLOW, "F": _C.RED}.get(grade, _C.RESET)


def _severity_color(sev: Optional[str]) -> str:
    return {"High": _C.RED, "Medium": _C.YELLOW, "Low": _C.CYAN}.get(sev or "", _C.DIM)


def render_human(results: list[ScanResult]) -> str:
    lines: list[str] = []
    for r in results:
        lines.append("=" * 70)
        header = f"  {r.url}"
        lines.append(_c(header, _C.BOLD))
        if not r.reachable:
            lines.append(_c(f"  UNREACHABLE: {r.error}", _C.RED))
            lines.append("")
            continue

        grade_str = _c(f" {r.grade} ", _C.BOLD + _grade_color(r.grade))
        lines.append(f"  Status: {r.status_code}   Score: {r.score}/100   Grade: {grade_str}")
        if r.redirected:
            lines.append(_c(f"  Redirected -> {r.final_url}", _C.DIM))
        lines.append("-" * 70)

        missing = [f for f in r.findings if f["status"] == "missing"]
        weak = [f for f in r.findings if f["status"] == "weak"]
        ok = [f for f in r.findings if f["status"] == "ok"]

        if missing:
            lines.append(_c("  MISSING HEADERS", _C.BOLD))
            for f in missing:
                sev = _c(f"[{f['severity']}]", _severity_color(f["severity"]))
                lines.append(f"    {sev} {f['header']}")
                lines.append(_c(f"        fix: {f['recommendation']}", _C.DIM))

        if weak:
            lines.append(_c("  WEAK / MISCONFIGURED", _C.BOLD))
            for f in weak:
                sev = _c(f"[{f['severity']}]", _severity_color(f["severity"]))
                lines.append(f"    {sev} {f['header']} — {f['detail']}")
                if f.get("observed"):
                    lines.append(_c(f"        observed: {f['observed']}", _C.DIM))
                lines.append(_c(f"        fix: {f['recommendation']}", _C.DIM))

        if ok:
            names = ", ".join(f["header"] for f in ok)
            lines.append(_c(f"  OK: {names}", _C.GREEN))
        lines.append("")
    return "\n".join(lines)


def render_json(results: list[ScanResult]) -> str:
    return json.dumps([r.to_dict() for r in results], indent=2)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def read_url_file(path: str) -> list[str]:
    urls: list[str] = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            urls.append(line)
    return urls


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Scan URLs for HTTP security-header posture and grade them A-F.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--url", help="A single URL to scan.")
    src.add_argument("--input", help="Path to a file of URLs (one per line).")
    p.add_argument("--format", choices=["human", "json"], default="human",
                   help="Output format (default: human).")
    p.add_argument("--concurrency", type=int, default=10,
                   help="Max concurrent requests (default: 10).")
    p.add_argument("--timeout", type=float, default=10.0,
                   help="Per-request timeout in seconds (default: 10).")
    p.add_argument("--fail-under", type=int, default=None, metavar="SCORE",
                   help="Exit non-zero if any URL scores below SCORE (for CI).")
    return p


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    if args.url:
        urls = [args.url]
    else:
        try:
            urls = read_url_file(args.input)
        except OSError as exc:
            print(f"Could not read input file: {exc}", file=sys.stderr)
            return 2
    if not urls:
        print("No URLs to scan.", file=sys.stderr)
        return 2

    results = asyncio.run(scan_all(urls, args.concurrency, args.timeout))

    if args.format == "json":
        print(render_json(results))
    else:
        print(render_human(results))

    if args.fail_under is not None:
        worst = min((r.score for r in results), default=0)
        if worst < args.fail_under:
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

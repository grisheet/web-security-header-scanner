# Web Security Header Scanner

A Python CLI tool that scans HTTP security headers and grades websites on their security posture. It inspects response headers, identifies missing or misconfigured settings, assigns severity levels, and provides a letter grade (A–F) with concrete fix recommendations — all using read-only GET requests with no payloads or exploitation.

## Features

- Scans HTTP response headers for security posture
- Reports missing, weak, or misconfigured headers with severity levels (High / Medium / Low)
- Provides concrete fix recommendations for each finding
- Calculates a security score (0–100) and assigns a letter grade (A–F)
- Supports scanning a single URL or bulk lists from a file
- Configurable concurrency and timeouts for high-performance batch scanning
- CI/CD integration via non-zero exit codes when scores fall below a threshold
- Human-readable color-coded output or machine-readable JSON

## Security Headers Checked

| Header | Purpose |
|--------|---------|
| `Strict-Transport-Security` | Enforces HTTPS connections (HSTS) |
| `Content-Security-Policy` | Controls allowed content sources (CSP) |
| `X-Frame-Options` | Prevents clickjacking attacks |
| `X-XSS-Protection` | Legacy XSS filter directive |
| `X-Content-Type-Options` | Prevents MIME-type sniffing |
| `Referrer-Policy` | Controls referrer information in requests |
| `Permissions-Policy` | Restricts access to browser features |

## Grading System

The scanner starts at 100 points and deducts based on finding severity:

| Severity | Deduction |
|----------|-----------|
| High | 25 points |
| Medium | 12 points |
| Low | 5 points |

| Grade | Score |
|-------|-------|
| A | 90+ |
| B | 80–89 |
| C | 70–79 |
| D | 60–69 |
| F | < 60 |

## Installation

```bash
git clone https://github.com/grisheet/web-security-header-scanner.git
cd web-security-header-scanner
pip install aiohttp
```

No additional dependencies beyond the Python standard library and `aiohttp`.

## Usage

### Scan a single URL

```bash
python header_scanner.py --url https://example.com
```

### Scan multiple URLs from a file

```bash
python header_scanner.py --input urls.txt
```

> Lines starting with `#` in the input file are treated as comments and skipped.

### JSON output

```bash
python header_scanner.py --url https://example.com --format json
```

### Tune concurrency and timeout

```bash
python header_scanner.py --input urls.txt --concurrency 20 --timeout 15
```

### CI/CD — fail if score is below a threshold

```bash
python header_scanner.py --url https://example.com --fail-under 80
```

Exits with a non-zero code if the site scores below 80, making it easy to integrate into pipelines.

## CLI Reference

| Argument | Default | Description |
|----------|---------|-------------|
| `--url` | — | Single URL to scan |
| `--input` | — | Path to a file of URLs (one per line) |
| `--format` | `human` | Output format: `human` or `json` |
| `--concurrency` | `10` | Max concurrent requests |
| `--timeout` | `10.0` | Per-request timeout in seconds |
| `--fail-under` | — | Exit non-zero if any URL scores below this value |

## Output

**Human mode** — color-coded terminal output showing the score, grade, all findings (missing / weak / ok), and specific fix recommendations per header.

**JSON mode** — machine-readable list of scan results with full evaluation details, suitable for piping into other tools or storing reports.

> Color output is automatically disabled when not writing to a TTY (e.g., when piping to a file).

## Ethics & Safety

This tool only makes standard, read-only HTTP GET requests. No payloads, no authentication bypass, no exploitation — it simply reads what a server voluntarily returns and grades it against public best-practice guidance (OWASP / MDN).

## License

MIT

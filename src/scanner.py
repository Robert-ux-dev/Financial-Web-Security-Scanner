#!/usr/bin/env python3
"""
Automated Web Application Security Assessment for Financial Platforms
Starter scanner — passive/low-impact checks for an authorised local lab.

Features:
- Same-origin crawling with a page limit
- Link, form, input-point, and API-candidate discovery
- HTTP security-header checks
- Cookie attribute checks
- JSON report output
- Localhost-only target restriction by default
- GET-only behavior: never submits forms or sends exploit payloads
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
import time
from collections import deque
from datetime import datetime, timezone
from html import unescape
from urllib.parse import (
    urljoin,
    urlparse,
    urldefrag,
    parse_qsl,
    urlencode,
    urlunparse,
)

import requests
from bs4 import BeautifulSoup


DEFAULT_TARGET = "http://127.0.0.1:3000"
USER_AGENT = "FinancialWebSecurityScanner/0.1 (authorised lab assessment)"

SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "severity": "medium",
        "purpose": "Helps restrict which resources a browser may load.",
    },
    "X-Content-Type-Options": {
        "severity": "low",
        "purpose": "Helps prevent MIME-type sniffing.",
    },
    "X-Frame-Options": {
        "severity": "low",
        "purpose": "Can help reduce clickjacking risk; CSP frame-ancestors is a modern alternative.",
    },
    "Referrer-Policy": {
        "severity": "low",
        "purpose": "Controls how much referrer information browsers send.",
    },
}

SENSITIVE_INPUT_TYPES = {"password", "email", "text", "search", "tel", "number", "url"}
API_PATH_HINTS = (
    "/api/", "/rest/", "/graphql", "/v1/", "/v2/", "/auth/", "/login",
    "/users", "/accounts", "/transactions", "/payments",
)


def normalise_url(url: str) -> str:
    """Remove fragments and normalise the URL for deduplication."""
    return urldefrag(url.strip())[0]


def is_localhost_host(host: str | None) -> bool:
    """Allow only loopback targets for this starter version."""
    if not host:
        return False
    host = host.lower().strip("[]")
    return host in {"localhost", "127.0.0.1", "::1"}


def validate_target(target: str) -> str:
    parsed = urlparse(target)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Target must begin with http:// or https://")
    if not is_localhost_host(parsed.hostname):
        raise ValueError(
            "This starter version is restricted to localhost for safety. "
            "Use http://localhost:3000 for your Juice Shop lab."
        )
    if parsed.username or parsed.password:
        raise ValueError("Do not put credentials in the target URL.")
    return target.rstrip("/")


def same_origin(url: str, base: str) -> bool:
    a, b = urlparse(url), urlparse(base)
    return (
        a.scheme.lower() == b.scheme.lower()
        and (a.hostname or "").lower() == (b.hostname or "").lower()
        and (a.port or default_port(a.scheme)) == (b.port or default_port(b.scheme))
    )


def default_port(scheme: str) -> int:
    return 443 if scheme.lower() == "https" else 80


def add_finding(report: dict, category: str, title: str, severity: str,
                url: str, evidence: str, recommendation: str,
                confidence: str = "medium") -> None:
    report["findings"].append({
        "id": f"F{len(report['findings']) + 1:03d}",
        "category": category,
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "url": url,
        "evidence": evidence,
        "recommendation": recommendation,
        "verified_vulnerability": False,
    })


def looks_like_api(url: str) -> bool:
    path = urlparse(url).path.lower()
    return any(hint in path for hint in API_PATH_HINTS) or path.endswith(".json")


def inspect_security_headers(response: requests.Response, report: dict) -> None:
    headers = response.headers
    for header, info in SECURITY_HEADERS.items():
        if header not in headers:
            add_finding(
                report,
                "Security Misconfiguration",
                f"Missing {header} response header",
                info["severity"],
                response.url,
                f"The response did not include the {header} header.",
                f"Review whether {header} is appropriate for this application. {info['purpose']}",
                "low",
            )

    # HSTS only has meaning for HTTPS sites.
    if urlparse(response.url).scheme == "https" and "Strict-Transport-Security" not in headers:
        add_finding(
            report,
            "Cryptographic Failures / Security Configuration",
            "Missing Strict-Transport-Security header",
            "low",
            response.url,
            "The HTTPS response did not include Strict-Transport-Security.",
            "Consider configuring HSTS after confirming HTTPS is correctly deployed across the intended domain.",
            "low",
        )


def inspect_cookies(response: requests.Response, report: dict) -> list[dict]:
    cookie_observations = []
    # Requests' cookie jar exposes received cookie attributes.
    for cookie in response.cookies:
        item = {
            "name": cookie.name,
            "domain": cookie.domain,
            "path": cookie.path,
            "secure": bool(cookie.secure),
            "http_only": bool(cookie.has_nonstandard_attr("HttpOnly")),
            "same_site": None,
        }
        # Requests does not expose SameSite consistently across versions.
        rest = getattr(cookie, "_rest", {}) or {}
        for key, value in rest.items():
            if key.lower() == "samesite":
                item["same_site"] = str(value)
        cookie_observations.append(item)

        if urlparse(response.url).scheme == "https" and not item["secure"]:
            add_finding(
                report, "Identification and Authentication Failures",
                f"Cookie '{cookie.name}' lacks Secure attribute", "low",
                response.url,
                f"Cookie '{cookie.name}' was received without the Secure attribute.",
                "If the cookie contains session or sensitive state, configure it with Secure and review its scope.",
                "low",
            )
        if not item["http_only"]:
            add_finding(
                report, "Identification and Authentication Failures",
                f"Cookie '{cookie.name}' lacks HttpOnly attribute", "low",
                response.url,
                f"Cookie '{cookie.name}' was received without an HttpOnly attribute detectable by this scanner.",
                "If the cookie is not intended for JavaScript access, consider setting HttpOnly. Verify the actual Set-Cookie header manually.",
                "low",
            )
    return cookie_observations


def parse_page(html: str, page_url: str, base_url: str) -> dict:
    soup = BeautifulSoup(html, "html.parser")
    links = set()
    forms = []
    input_points = []
    api_candidates = set()

    for tag in soup.find_all(["a", "area"], href=True):
        href = unescape(tag.get("href", "")).strip()
        if not href or href.startswith(("javascript:", "mailto:", "tel:", "#")):
            continue
        absolute = normalise_url(urljoin(page_url, href))
        if same_origin(absolute, base_url):
            links.add(absolute)
            if looks_like_api(absolute):
                api_candidates.add(absolute)

    for form_index, form in enumerate(soup.find_all("form"), start=1):
        action_raw = form.get("action", "").strip()
        action = normalise_url(urljoin(page_url, action_raw or page_url))
        method = (form.get("method") or "GET").strip().upper()
        form_record = {
            "form_index": form_index,
            "page_url": page_url,
            "action": action,
            "method": method,
            "inputs": [],
        }
        for field in form.find_all(["input", "textarea", "select", "button"]):
            name = field.get("name")
            field_type = (field.get("type") or field.name).lower()
            record = {
                "name": name,
                "type": field_type,
                "id": field.get("id"),
                "required": field.has_attr("required"),
                "autocomplete": field.get("autocomplete"),
            }
            form_record["inputs"].append(record)
            if field_type in SENSITIVE_INPUT_TYPES or field.name in {"textarea", "select"}:
                input_points.append({
                    "page_url": page_url,
                    "form_action": action,
                    "form_method": method,
                    **record,
                })
        forms.append(form_record)
        if looks_like_api(action):
            api_candidates.add(action)

    # Collect same-origin API-looking URLs referenced in script source attributes.
    for script in soup.find_all("script", src=True):
        script_url = normalise_url(urljoin(page_url, script.get("src", "")))
        if same_origin(script_url, base_url) and looks_like_api(script_url):
            api_candidates.add(script_url)

    # Light heuristic for API routes mentioned in inline JavaScript.
    for script in soup.find_all("script"):
        body = script.string or script.get_text(" ", strip=True)
        if not body:
            continue
        for match in re.findall(r"""["'`]((?:/api/|/rest/|/graphql|/auth/)[^"'`\s]*)["'`]""", body):
            candidate = normalise_url(urljoin(page_url, match))
            if same_origin(candidate, base_url):
                api_candidates.add(candidate)

    return {
        "title": soup.title.get_text(" ", strip=True) if soup.title else None,
        "links": sorted(links),
        "forms": forms,
        "input_points": input_points,
        "api_candidates": sorted(api_candidates),
    }


def scan(target: str, max_pages: int = 20, delay: float = 0.2, timeout: float = 8.0) -> dict:
    target = validate_target(target)
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    report = {
        "project": "Automated Web Application Security Assessment for Financial Platforms",
        "scanner_version": "0.1",
        "scan_started_utc": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "scan_mode": "passive discovery and low-impact checks; GET requests only; no form submissions",
        "pages": [],
        "forms": [],
        "links": [],
        "input_points": [],
        "api_candidates": [],
        "cookie_observations": [],
        "findings": [],
        "errors": [],
        "summary": {},
    }

    queue = deque([target + "/"])
    visited = set()
    all_links, all_api, all_inputs = set(), set(), []

    while queue and len(visited) < max_pages:
        url = normalise_url(queue.popleft())
        if url in visited or not same_origin(url, target):
            continue
        visited.add(url)

        try:
            response = session.get(url, timeout=timeout, allow_redirects=True)
        except requests.RequestException as exc:
            report["errors"].append({"url": url, "error": str(exc)})
            continue

        final_url = normalise_url(response.url)
        if not same_origin(final_url, target):
            report["errors"].append({
                "url": url,
                "error": "Redirected outside the authorised localhost origin; response not crawled."
            })
            continue

        inspect_security_headers(response, report)
        report["cookie_observations"].extend(inspect_cookies(response, report))

        page_record = {
            "url": final_url,
            "status_code": response.status_code,
            "content_type": response.headers.get("Content-Type"),
            "title": None,
            "links_found": [],
            "forms_found": 0,
            "input_points_found": 0,
        }

        content_type = response.headers.get("Content-Type", "").lower()
        if "text/html" in content_type:
            parsed = parse_page(response.text, final_url, target)
            page_record["title"] = parsed["title"]
            page_record["links_found"] = parsed["links"]
            page_record["forms_found"] = len(parsed["forms"])
            page_record["input_points_found"] = len(parsed["input_points"])
            report["forms"].extend(parsed["forms"])
            all_inputs.extend(parsed["input_points"])
            all_links.update(parsed["links"])
            all_api.update(parsed["api_candidates"])

            for link in parsed["links"]:
                if link not in visited and len(visited) + len(queue) < max_pages:
                    queue.append(link)

        report["pages"].append(page_record)
        if delay:
            time.sleep(delay)

    report["links"] = sorted(all_links)
    report["input_points"] = all_inputs
    report["api_candidates"] = sorted(all_api)
    report["scan_finished_utc"] = datetime.now(timezone.utc).isoformat()
    report["summary"] = {
        "pages_visited": len(report["pages"]),
        "links_discovered": len(report["links"]),
        "forms_discovered": len(report["forms"]),
        "input_points_discovered": len(report["input_points"]),
        "api_candidates_discovered": len(report["api_candidates"]),
        "findings_count": len(report["findings"]),
        "errors_count": len(report["errors"]),
        "note": "Findings are indicators requiring validation, not proof of exploitable vulnerabilities.",
    }
    return report


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Low-impact web security scanner for your authorised localhost lab."
    )
    parser.add_argument("--target", default=DEFAULT_TARGET, help="Target URL (localhost only in this starter version).")
    parser.add_argument("--max-pages", type=int, default=20, help="Maximum same-origin pages to visit (default: 20).")
    parser.add_argument("--delay", type=float, default=0.2, help="Delay between requests in seconds (default: 0.2).")
    parser.add_argument("--timeout", type=float, default=8.0, help="HTTP timeout in seconds (default: 8).")
    project_root = Path(__file__).resolve().parent.parent
    default_report = project_root / "reports" / "report.json"
    parser.add_argument(
        "--output",
        default=str(default_report),
        help="JSON report path (default: reports/report.json).",
    )
    args = parser.parse_args()

    if args.max_pages < 1 or args.max_pages > 100:
        parser.error("--max-pages must be between 1 and 100.")
    if args.delay < 0:
        parser.error("--delay cannot be negative.")

    try:
        report = scan(args.target, args.max_pages, args.delay, args.timeout)
    except ValueError as exc:
        print(f"[!] Target rejected: {exc}", file=sys.stderr)
        return 2

    report_path = Path(args.output).expanduser()
    report_path.parent.mkdir(parents=True, exist_ok=True)

    with report_path.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=2, ensure_ascii=False)

    print("[+] Scan complete")
    print(f"    Target: {report['target']}")
    print(f"    Pages visited: {report['summary']['pages_visited']}")
    print(f"    Forms found: {report['summary']['forms_discovered']}")
    print(f"    Input points found: {report['summary']['input_points_discovered']}")
    print(f"    API candidates: {report['summary']['api_candidates_discovered']}")
    print(f"    Findings: {report['summary']['findings_count']}")
    print(f"    JSON report: {report_path.resolve()}")
    print("    Reminder: review findings manually; missing headers are not automatically exploitable vulnerabilities.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

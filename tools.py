"""
ApexNexus AI — Defensive Security Tools.

These tools perform lightweight, defensive checks. They do not perform
destructive exploitation or claim external threat-intelligence results.
"""

from __future__ import annotations

import json
import re
import socket
import ssl
import urllib.request
import urllib.parse
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Any


@dataclass
class ToolResult:
    tool: str
    success: bool
    summary: str
    evidence: list[str]
    data: dict[str, Any]
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _result(
    tool: str,
    success: bool,
    summary: str,
    evidence: list[str] | None = None,
    data: dict[str, Any] | None = None,
    error: str | None = None,
) -> ToolResult:
    return ToolResult(
        tool=tool,
        success=success,
        summary=summary,
        evidence=evidence or [],
        data=data or {},
        error=error,
    )


def normalize_url(value: str) -> str:
    """Add HTTPS when a URL is supplied without a scheme."""
    value = value.strip()

    if not re.match(r"^https?://", value, re.I):
        value = "https://" + value

    return value


def scan_website(url: str, timeout: int = 8) -> ToolResult:
    """
    Passively inspect a website's HTTP response, selected headers,
    and TLS metadata. This is not a full penetration test.
    """
    url = normalize_url(url)
    parsed = urllib.parse.urlparse(url)

    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return _result(
            "website_security",
            False,
            "That does not look like a valid website URL.",
            error="Invalid URL",
        )

    # Avoid accidentally treating a URL with embedded credentials as normal.
    if parsed.username or parsed.password:
        return _result(
            "website_security",
            False,
            "The URL contains embedded credentials. Remove them before retrying.",
            error="Credentials in URL are not accepted",
        )

    evidence: list[str] = []
    data: dict[str, Any] = {
        "url": url,
        "final_url": None,
        "status": None,
        "headers": {},
        "redirects": [],
        "tls": {},
        "checks": [],
    }

    try:
        request = urllib.request.Request(
            url,
            headers={
                "User-Agent": "ApexNexus-Security-Assessment/1.0",
            },
        )

        opener = urllib.request.build_opener(
            urllib.request.HTTPRedirectHandler()
        )

        with opener.open(request, timeout=timeout) as response:
            data["status"] = response.status
            data["final_url"] = response.geturl()

            headers = {
                key.lower(): value
                for key, value in response.headers.items()
            }
            data["headers"] = headers

        checks = [
            ("strict-transport-security", "HSTS"),
            ("content-security-policy", "Content Security Policy"),
            ("x-content-type-options", "X-Content-Type-Options"),
            ("x-frame-options", "X-Frame-Options"),
            ("referrer-policy", "Referrer-Policy"),
            ("permissions-policy", "Permissions-Policy"),
        ]

        for header, label in checks:
            present = bool(data["headers"].get(header))

            data["checks"].append({
                "name": label,
                "present": present,
            })

            evidence.append(
                f"{label}: {'present' if present else 'missing'}"
            )

        if data["headers"].get("server"):
            evidence.append("Server header is exposed.")

        if data["headers"].get("x-powered-by"):
            evidence.append("X-Powered-By header is exposed.")

        # Check TLS metadata only for HTTPS URLs.
        if parsed.scheme == "https":
            try:
                context = ssl.create_default_context()

                with socket.create_connection(
                    (parsed.hostname, parsed.port or 443),
                    timeout=timeout,
                ) as sock:
                    with context.wrap_socket(
                        sock,
                        server_hostname=parsed.hostname,
                    ) as secure_socket:
                        certificate = secure_socket.getpeercert()
                        cipher_info = secure_socket.cipher()

                        data["tls"] = {
                            "version": secure_socket.version(),
                            "cipher": (
                                cipher_info[0]
                                if cipher_info
                                else None
                            ),
                            "subject": str(
                                certificate.get("subject", "")
                            ),
                            "issuer": str(
                                certificate.get("issuer", "")
                            ),
                        }

            except Exception as exc:
                data["tls"] = {
                    "error": str(exc),
                }

        missing = [
            check["name"]
            for check in data["checks"]
            if not check["present"]
        ]

        summary = (
            f"Reached {data['final_url'] or url} with HTTP status "
            f"{data['status']}."
        )

        if missing:
            summary += (
                " Several common security headers were not observed. "
                "Whether they are required depends on the application."
            )
        else:
            summary += " The checked security headers were observed."

        return _result(
            "website_security",
            True,
            summary,
            evidence,
            data,
        )

    except Exception as exc:
        return _result(
            "website_security",
            False,
            "I could not complete the passive website check.",
            evidence,
            data,
            str(exc),
        )


def analyze_code(code: str) -> ToolResult:
    """
    Lightweight static analysis for common security warning signs.
    The supplied code is inspected as text and never executed.
    """
    findings: list[dict[str, Any]] = []
    lines = code.splitlines()

    patterns = [
        (
            "CRITICAL",
            r"""(password|passwd|secret|api[_-]?key|token)\s*=\s*['"][^'"]{6,}['"]""",
            "Possible hardcoded secret or credential.",
        ),
        (
            "HIGH",
            r"""(SELECT|UPDATE|DELETE|INSERT).*(\+|f['"]|format\(|%s)""",
            "Possible SQL query construction using interpolation or concatenation.",
        ),
        (
            "HIGH",
            r"\beval\s*\(",
            "Use of eval() can execute dynamically supplied code.",
        ),
        (
            "HIGH",
            r"\bexec\s*\(",
            "Use of exec() can execute dynamically supplied code.",
        ),
        (
            "MEDIUM",
            r"verify\s*=\s*False",
            "TLS certificate verification appears to be disabled.",
        ),
        (
            "MEDIUM",
            r"debug\s*=\s*True",
            "Debug mode appears to be enabled.",
        ),
        (
            "MEDIUM",
            r"innerHTML\s*=",
            "Direct innerHTML assignment can create XSS risk with untrusted input.",
        ),
        (
            "LOW",
            r"print\s*\(.*(password|token|secret)",
            "Sensitive-looking data may be written to logs.",
        ),
    ]

    for line_number, line in enumerate(lines, start=1):
        for severity, pattern, message in patterns:
            if re.search(pattern, line, re.I):
                findings.append({
                    "severity": severity,
                    "line": line_number,
                    "message": message,
                    "evidence": line.strip()[:300],
                })

    counts: dict[str, int] = {}

    for finding in findings:
        severity = finding["severity"]
        counts[severity] = counts.get(severity, 0) + 1

    summary = (
        f"Static analysis reviewed {len(lines)} lines and found "
        f"{len(findings)} potential security issue(s)."
    )

    return _result(
        "code_security",
        True,
        summary,
        [
            f"Line {finding['line']}: {finding['message']}"
            for finding in findings[:20]
        ],
        {
            "findings": findings,
            "counts": counts,
        },
    )


def analyze_logs(log_text: str) -> ToolResult:
    """Triage supplied logs for authentication failures and suspicious patterns."""
    lines = log_text.splitlines()
    failed: list[str] = []
    ips: dict[str, int] = {}
    suspicious: list[str] = []

    for line in lines:
        if re.search(
            r"(failed login|authentication failure|invalid password|login failed)",
            line,
            re.I,
        ):
            failed.append(line[:500])

        for ip in re.findall(
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            line,
        ):
            ips[ip] = ips.get(ip, 0) + 1

        if re.search(
            r"(sqlmap|union\s+select|<script|\.\./|/etc/passwd|powershell\s+-enc|cmd\.exe)",
            line,
            re.I,
        ):
            suspicious.append(line[:500])

    top_ips = sorted(
        ips.items(),
        key=lambda item: item[1],
        reverse=True,
    )[:10]

    summary = (
        f"Reviewed {len(lines)} log line(s). "
        f"Found {len(failed)} authentication-failure line(s) and "
        f"{len(suspicious)} line(s) containing high-signal suspicious patterns."
    )

    return _result(
        "log_analysis",
        True,
        summary,
        [
            f"Failed authentication events: {len(failed)}",
            f"Unique IP addresses observed: {len(ips)}",
            f"High-signal suspicious lines: {len(suspicious)}",
        ],
        {
            "line_count": len(lines),
            "failed_authentication": failed[:25],
            "top_ips": top_ips,
            "suspicious": suspicious[:25],
        },
    )


def analyze_cloud_policy(policy_text: str) -> ToolResult:
    """Review common AWS-style IAM least-privilege warning signs."""
    try:
        policy = json.loads(policy_text)

    except json.JSONDecodeError:
        return _result(
            "cloud_iam",
            False,
            "I could not parse that as JSON. Please provide a valid cloud policy.",
            error="Invalid JSON",
        )

    if isinstance(policy, list):
        statements = policy

    elif isinstance(policy, dict):
        statements = policy.get("Statement", [])

    else:
        return _result(
            "cloud_iam",
            False,
            "The policy must be a JSON object or a list of policy statements.",
            error="Unexpected JSON type",
        )

    if isinstance(statements, dict):
        statements = [statements]

    if not isinstance(statements, list):
        return _result(
            "cloud_iam",
            False,
            "The policy's Statement field must be an object or list.",
            error="Invalid Statement field",
        )

    findings: list[dict[str, Any]] = []

    for number, statement in enumerate(statements, start=1):
        if not isinstance(statement, dict):
            continue

        action = statement.get("Action")
        resource = statement.get("Resource")

        actions = action if isinstance(action, list) else [action]
        resources = (
            resource
            if isinstance(resource, list)
            else [resource]
        )

        if "*" in actions:
            findings.append({
                "severity": "HIGH",
                "statement": number,
                "message": "Action '*' grants all actions in this statement.",
            })

        if "*" in resources:
            findings.append({
                "severity": "HIGH",
                "statement": number,
                "message": "Resource '*' applies the statement to all resources.",
            })

        if (
            statement.get("Effect") == "Allow"
            and "*" in actions
            and "*" in resources
        ):
            findings.append({
                "severity": "CRITICAL",
                "statement": number,
                "message": (
                    "Allow + Action '*' + Resource '*' creates an "
                    "extremely broad permission."
                ),
            })

    return _result(
        "cloud_iam",
        True,
        (
            f"Reviewed {len(statements)} policy statement(s) and found "
            f"{len(findings)} least-privilege concern(s)."
        ),
        [finding["message"] for finding in findings],
        {
            "findings": findings,
        },
    )


def inspect_indicator(indicator: str) -> ToolResult:
    """
    Classify an IP, domain, or hash by format.
    This tool does not claim a live external reputation result.
    """
    value = indicator.strip()
    kind = "unknown"

    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", value):
        try:
            import ipaddress

            ipaddress.IPv4Address(value)
            kind = "IPv4 address"
        except ValueError:
            kind = "invalid IPv4-like string"

    elif re.fullmatch(r"[A-Fa-f0-9]{32}", value):
        kind = "MD5 hash"

    elif re.fullmatch(r"[A-Fa-f0-9]{40}", value):
        kind = "SHA-1 hash"

    elif re.fullmatch(r"[A-Fa-f0-9]{64}", value):
        kind = "SHA-256 hash"

    elif re.fullmatch(
        r"(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}",
        value,
    ):
        kind = "domain"

    return _result(
        "indicator_triage",
        True,
        f"I identified the indicator as a possible {kind}.",
        [
            "No external reputation verdict was claimed.",
            "Use a configured threat-intelligence provider for live reputation data.",
        ],
        {
            "indicator": value,
            "type": kind,
        },
    )


def generate_security_report(result: dict[str, Any]) -> str:
    """Create a Markdown report from an ApexNexus assessment."""
    lines = [
        "# ApexNexus Security Assessment",
        "",
        f"Generated: {datetime.now().astimezone().isoformat(timespec='seconds')}",
        "",
        "## Summary",
        result.get("summary", "No summary available."),
        "",
        f"**Risk:** {result.get('risk', 'UNKNOWN')}",
        "",
        "## Findings",
    ]

    findings = result.get("findings", [])

    for finding in findings:
        if isinstance(finding, dict):
            lines.append(
                f"- **{finding.get('severity', 'INFO')}** — "
                f"{finding.get('title', 'Finding')}"
            )
            lines.append(
                f"  - {finding.get('description', '')}"
            )
            lines.append(
                "  - Recommendation: "
                f"{finding.get('recommendation', '')}"
            )
        else:
            lines.append(f"- {finding}")

    if not findings:
        lines.append(
            "- No structured findings were recorded for this assessment."
        )

    lines.extend([
        "",
        "## Important note",
        (
            "This report contains only evidence available to ApexNexus "
            "during the assessment. It does not claim actions or scans "
            "that were not actually performed."
        ),
    ])

    return "\n".join(lines)
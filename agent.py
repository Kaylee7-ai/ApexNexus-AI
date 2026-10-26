"""
ApexNexus AI — Conversational Defensive Cybersecurity Agent

Works with the project's tools.py and Streamlit app.py.
Supports local defensive analysis, optional Gemini fallback,
and the OpenAI-compatible Meterless Nightshift Runtime.
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request

from dataclasses import asdict, dataclass
from typing import Any

from tools import (
    analyze_cloud_policy,
    analyze_code,
    analyze_logs,
    inspect_indicator,
    scan_website,
)


# =========================================================
# AGENT INSTRUCTIONS
# =========================================================

SYSTEM_PROMPT = """
You are ApexNexus, a calm, intelligent, professional defensive
cybersecurity assistant.

Write in clear, natural English. Do not sound like a terminal,
code compiler, raw JSON API, or robotic scanner.

Explain what was observed, what it may mean, and practical
defensive next steps.

Distinguish evidence from possibilities. Never invent findings,
scans, lookups, fixes, verification, or external threat-intelligence
results.

A missing security header is an observation, not proof of compromise.
A log pattern is an investigation lead, not proof of an attack.

Only assess systems the user owns or is authorized to assess.

Provide source code when the user asks for it, when the user provides
code for fixing, or when code is needed for secure remediation.

Focus on defensive cybersecurity, detection, secure configuration,
incident response, and authorized assessment.

Do not provide instructions for credential theft, malware deployment,
destructive exploitation, evasion, or unauthorized access.

Keep greetings and basic questions friendly and concise.
""".strip()


# =========================================================
# ASSESSMENT RESULT
# =========================================================

@dataclass
class Assessment:
    status: str
    request_type: str
    risk: str
    summary: str
    findings: list[dict[str, Any]]
    recommendations: list[str]
    evidence: list[str]
    tool_results: list[dict[str, Any]]
    response: str
    secure_code: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert the assessment into a dictionary for reports."""
        return asdict(self)


# =========================================================
# MAIN AGENT
# =========================================================

class ApexNexusAgent:
    """A session-scoped defensive cybersecurity assistant."""

    def __init__(self) -> None:
        self.provider = self._detect_provider()
        self.history: list[dict[str, str]] = []

    @staticmethod
    def _detect_provider() -> str:
        """Describe configured providers without claiming a live connection."""
        runtime_url = os.getenv("METERLESS_BASE_URL", "").strip()
        runtime_token = os.getenv(
            "METERLESS_RUNTIME_TOKEN", ""
        ).strip()

        if runtime_url and runtime_token:
            return "Meterless Nightshift (configured; not yet verified)"

        if os.getenv("GEMINI_API_KEY", "").strip():
            return "Google Gemini (Meterless pending)"

        return "Local Defensive Engine (Meterless pending)"

    # -----------------------------------------------------
    # Create consistent assessment objects
    # -----------------------------------------------------

    @staticmethod
    def _assessment(
        request_type: str,
        response: str,
        summary: str = "",
        risk: str = "INFO",
        findings: list[dict[str, Any]] | None = None,
        recommendations: list[str] | None = None,
        evidence: list[str] | None = None,
        tool_results: list[dict[str, Any]] | None = None,
        status: str = "success",
    ) -> Assessment:

        return Assessment(
            status=status,
            request_type=request_type,
            risk=risk,
            summary=summary or response[:240],
            findings=findings or [],
            recommendations=recommendations or [],
            evidence=evidence or [],
            tool_results=tool_results or [],
            response=response,
        )

    # -----------------------------------------------------
    # Input recognition helpers
    # -----------------------------------------------------

    @staticmethod
    def _extract_url(text: str) -> str | None:
        """Extract a website address from the user's message."""

        match = re.search(
            r"https?://[^\s<>'\"]+|"
            r"(?:www\.)?(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}"
            r"(?:/[^\s<>'\"]*)?",
            text,
            re.I,
        )

        if not match:
            return None

        return match.group(0).rstrip(".,;:!?)\"]}")

    @staticmethod
    def _extract_indicator(text: str) -> str | None:
        """Extract a possible IP address, file hash, or domain."""

        ip_match = re.search(
            r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])",
            text,
        )

        if ip_match:
            return ip_match.group(0)

        hash_match = re.search(
            r"(?<![A-Fa-f0-9])"
            r"(?:[A-Fa-f0-9]{64}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{32})"
            r"(?![A-Fa-f0-9])",
            text,
        )

        if hash_match:
            return hash_match.group(0)

        domain_match = re.search(
            r"(?<![@\w-])"
            r"(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}"
            r"(?![\w-])",
            text,
        )

        if domain_match:
            return domain_match.group(0)

        return None

    @staticmethod
    def _intent(text: str) -> str:
        """Classify the user's request before choosing a tool."""

        t = text.lower().strip()

        # Greetings
        if re.fullmatch(
            r"(hi|hello|hey|hiya|good morning|good afternoon|good evening)[!. ]*",
            t,
        ):
            return "greeting"

        # Asking about capabilities
        if any(
            phrase in t
            for phrase in (
                "what can you help",
                "what can you do",
                "your capabilities",
                "what do you do",
            )
        ):
            return "capabilities"

        # Recognize website-compromise questions before generic questions.
        # This prevents "Is my website hacked?" from getting a vague reply.
        if (
            re.search(
                r"\b(website|web\s?page|web\s?app|online\s?store|"
                r"my\s?site|site)\b",
                t,
            )
            and re.search(
                r"\b(hacked|hack|compromised|defaced|infected|malicious|"
                r"redirected|redirect|breached|suspicious changes|taken over)\b",
                t,
            )
        ):
            return "website_concern"

        # Simple educational questions
        if re.search(
            r"\b(explain|what is|what are|meaning of|define)\b",
            t,
        ):
            return "question"

        # Website URLs
        if re.search(
            r"https?://|www\.|\b[a-z0-9-]+\."
            r"(?:com|org|net|io|gh|dev|app|edu|gov|co\.uk)\b",
            t,
        ):
            return "website"

        # Cloud and IAM policies
        if (
            '"effect"' in t
            or '"action"' in t
            or '"resource"' in t
            or ("iam" in t and "policy" in t)
        ):
            return "cloud"

        # Treat text as logs only when it resembles actual log records.
        looks_like_logs = (
            "\n" in text
            and re.search(
                r"failed login|authentication failure|invalid password|"
                r"login failed|status=|GET /|POST /|\b20\d\d[-/]\d\d",
                t,
            )
        )

        if looks_like_logs or re.search(
            r"\b(status=\d{3}|GET /\S* HTTP/|POST /\S* HTTP/|"
            r"authentication failure at|failed login from)\b",
            t,
        ):
            return "logs"

        # A standalone IP or hash is an indicator.
        if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", t):
            return "indicator"

        if re.fullmatch(
            r"[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}",
            t,
        ):
            return "indicator"

        # Code blocks or code-like input
        if "```" in text or re.search(
            r"^\s*(def |class |import |from \w+ import |"
            r"function\s+|const\s+|let\s+|var\s+|"
            r"password\s*=|api[_-]?key\s*=)",
            text,
            re.I | re.M,
        ):
            return "code"

        if re.search(
            r"\b(code|python|javascript|sql|java|php|source code|query|function)\b",
            t,
        ):
            return "code"

        # General security concerns
        if re.search(
            r"\b(scan|analy[sz]e|investigate|check|audit|secure|security|"
            r"vulnerability|incident|attack|threat|breach|suspicious|malware)\b",
            t,
        ):
            return "security"

        return "general"

    # -----------------------------------------------------
    # Educational security answers
    # -----------------------------------------------------

    def _local_question(self, text: str) -> Assessment:
        t = text.lower()

        if "sql injection" in t:
            answer = (
                "SQL injection is a vulnerability that can happen when "
                "an application places untrusted input directly into a "
                "database query. That input may alter what the query does "
                "and could expose or change data.\n\n"
                "The main defense is to use parameterized queries or "
                "prepared statements, keep database permissions limited, "
                "and avoid building SQL by joining user-controlled input "
                "into a query.\n\n"
                "Share the relevant code when you're ready, and I can "
                "review it and suggest a safer implementation."
            )

        elif "phishing" in t:
            answer = (
                "Phishing is a social-engineering attempt to trick someone "
                "into sharing information, opening a harmful attachment, "
                "or visiting a deceptive website.\n\n"
                "Helpful defenses include multi-factor authentication, "
                "email filtering, careful link checking, and reporting "
                "suspicious messages."
            )

        elif "firewall" in t:
            answer = (
                "A firewall controls network traffic using rules. A sensible "
                "baseline is to allow only traffic that is needed, restrict "
                "administrative access, log important decisions, and review "
                "rules regularly."
            )

        elif "zero trust" in t:
            answer = (
                "Zero Trust is a security approach where access is not "
                "trusted automatically just because a user or device is "
                "inside a network. Identity, device health, context, and "
                "least privilege are considered before access is granted."
            )

        else:
            answer = (
                "I can explain that topic in plain English. Tell me which "
                "part you want to understand, or share relevant code, logs, "
                "a website, or configuration for an evidence-based review."
            )

        return self._assessment(
            "question",
            answer,
            "General cybersecurity explanation.",
        )

    # -----------------------------------------------------
    # Capabilities
    # -----------------------------------------------------

    def _capabilities(self) -> Assessment:
        response = (
            "Here is how I can help:\n\n"
            "- **Website security:** passively review response headers "
            "and basic reachability.\n"
            "- **Code security:** identify common risky patterns without "
            "executing code.\n"
            "- **Log analysis:** triage authentication failures and "
            "suspicious patterns.\n"
            "- **Cloud and IAM:** review JSON policies for overly broad "
            "permissions.\n"
            "- **Threat indicators:** classify IP, domain, and hash "
            "formats; live reputation requires a configured provider.\n"
            "- **Incident response:** organize evidence, containment, "
            "and recovery priorities.\n\n"
            "I explain findings in normal English and distinguish evidence "
            "from assumptions. I only assess websites you are authorized "
            "to check."
        )

        return self._assessment(
            "capabilities",
            response,
            "Available defensive capabilities.",
        )

    # -----------------------------------------------------
    # Website-compromise questions
    # -----------------------------------------------------

    def _website_concern(self, text: str) -> Assessment:
        response = (
            "## Let's investigate your website 🛡️\n\n"
            "A website can be compromised, but I can't confirm that from "
            "the question alone. We need evidence before drawing a conclusion.\n\n"
            "### Signs worth checking\n"
            "- Unexpected redirects or unfamiliar pages.\n"
            "- Unknown administrator accounts or suspicious login activity.\n"
            "- Website files or settings changed unexpectedly.\n"
            "- Security alerts from your hosting provider.\n"
            "- Unfamiliar plugins, scripts, or outgoing emails.\n\n"
            "### What to do now\n"
            "1. Access your hosting dashboard through its official website.\n"
            "2. Review administrator logins, account changes, and security alerts.\n"
            "3. Preserve relevant logs before making major changes.\n"
            "4. From a trusted device, secure administrator accounts and enable MFA.\n"
            "5. If you suspect compromise, contact your hosting provider and "
            "check your backups.\n\n"
            "### Let's narrow it down\n"
            "Tell me the website address and what made you suspicious, such as "
            "a browser warning, unexpected redirect, unfamiliar account, or "
            "unusual activity. Remove passwords and API keys first.\n\n"
            "A basic header check alone cannot prove whether a website has "
            "been compromised."
        )

        return self._assessment(
            "website_incident",
            response,
            "Website compromise suspected; investigation is needed.",
            "UNKNOWN",
            recommendations=[
                "Review hosting and administrator logs.",
                "Preserve evidence before making major changes.",
                "Secure administrator accounts and enable MFA.",
                "Consult the hosting provider if compromise is suspected.",
            ],
        )

    # -----------------------------------------------------
    # Convert tool results into readable findings
    # -----------------------------------------------------

    def _tool_assessment(
        self,
        kind: str,
        tool_result: Any,
    ) -> Assessment:

        data = (
            tool_result.data
            if isinstance(getattr(tool_result, "data", None), dict)
            else {}
        )

        evidence = list(getattr(tool_result, "evidence", []) or [])

        summary = str(
            getattr(tool_result, "summary", "The tool returned no summary.")
        )

        success = bool(getattr(tool_result, "success", False))

        tool_results = (
            [tool_result.to_dict()]
            if hasattr(tool_result, "to_dict")
            else []
        )

        if not success:
            response = (
                f"I couldn't complete the {kind.replace('_', ' ')} check.\n\n"
                f"{summary}\n\n"
                "Please verify the input and try again. I won't claim a "
                "successful check when it did not complete."
            )

            return self._assessment(
                kind,
                response,
                summary,
                "UNKNOWN",
                [],
                [
                    "Verify the input and try again.",
                    "Only assess systems you are authorized to check.",
                ],
                evidence,
                tool_results,
                "error",
            )

        findings: list[dict[str, Any]] = []
        recommendations: list[str] = []
        risk = "LOW"

        # Website findings
        if kind == "website":
            checks = data.get("checks", [])

            missing = [
                item.get("name", "Security header")
                for item in checks
                if isinstance(item, dict)
                and not item.get("present", False)
            ]

            if missing:
                risk = "MEDIUM"

            for name in missing:
                recommendation = (
                    f"Review and configure {name} where appropriate."
                )

                findings.append({
                    "severity": "MEDIUM",
                    "title": f"{name} was not observed",
                    "description": (
                        f"The passive HTTP check did not observe the {name} "
                        "response header. Whether it is appropriate depends "
                        "on the application."
                    ),
                    "recommendation": recommendation,
                })

                recommendations.append(recommendation)

            headers = data.get("headers", {})

            if isinstance(headers, dict) and headers.get("x-powered-by"):
                findings.append({
                    "severity": "LOW",
                    "title": "Technology disclosure header",
                    "description": (
                        "The response includes an X-Powered-By header."
                    ),
                    "recommendation": (
                        "Remove unnecessary technology-identifying headers "
                        "if practical."
                    ),
                })

            if isinstance(headers, dict) and headers.get("server"):
                findings.append({
                    "severity": "INFO",
                    "title": "Server header observed",
                    "description": "The response exposes a Server header.",
                    "recommendation": (
                        "Consider minimizing unnecessary server "
                        "fingerprinting information."
                    ),
                })

            response = (
                "## Website security assessment\n\n"
                f"I completed a **passive** check of "
                f"`{data.get('final_url') or data.get('url')}` and observed "
                f"HTTP status **{data.get('status')}**.\n\n"
                f"**Risk:** {risk}\n\n"
                f"I found **{len(findings)} item(s)** worth reviewing. A "
                "header check is not a full penetration test and does not "
                "prove that a site is secure or hacked."
            )

        # Code findings
        elif kind == "code":
            raw_findings = data.get("findings", [])

            severity_order = {
                "INFO": 0,
                "LOW": 1,
                "MEDIUM": 2,
                "HIGH": 3,
                "CRITICAL": 4,
            }

            for item in raw_findings:
                severity = str(item.get("severity", "LOW")).upper()

                if (
                    severity_order.get(severity, 0)
                    > severity_order.get(risk, 0)
                ):
                    risk = severity

                message = str(
                    item.get("message", "Potential security pattern.")
                )

                line = item.get("line", "unknown")

                findings.append({
                    "severity": severity,
                    "title": message,
                    "description": (
                        f"Potential issue observed on line {line}. "
                        "The code was not executed."
                    ),
                    "recommendation": self._code_recommendation(message),
                })

            recommendations = list(dict.fromkeys(
                item["recommendation"] for item in findings
            ))

            if not recommendations:
                recommendations = [
                    "No obvious match was found by these basic checks. "
                    "Consider broader testing and dependency review."
                ]

            response = (
                "## Code security assessment\n\n"
                "I reviewed the supplied text using lightweight static "
                "checks without executing it. The checks flagged "
                f"**{len(findings)} potential issue(s)**.\n\n"
                f"**Risk:** {risk}\n\n"
                "These are signals to review in context, not proof that "
                "the application is exploitable or secure."
            )

        # Security log findings
        elif kind == "logs":
            failed = data.get("failed_authentication", [])
            suspicious = data.get("suspicious", [])

            if suspicious or len(failed) >= 10:
                risk = "HIGH"
            elif failed:
                risk = "MEDIUM"
            else:
                risk = "LOW"

            if failed:
                findings.append({
                    "severity": risk,
                    "title": "Authentication failures observed",
                    "description": (
                        f"{len(failed)} supplied log line(s) indicate "
                        "failed authentication."
                    ),
                    "recommendation": (
                        "Review source addresses, targeted accounts, "
                        "timestamps, and whether a successful login followed. "
                        "Consider rate limiting and MFA."
                    ),
                })

                recommendations.extend([
                    "Review repeated source addresses and targeted accounts.",
                    "Enable rate limiting or adaptive controls where appropriate.",
                    "Use multi-factor authentication for sensitive accounts.",
                ])

            if suspicious:
                findings.append({
                    "severity": "HIGH",
                    "title": "Suspicious patterns observed",
                    "description": (
                        f"{len(suspicious)} supplied line(s) matched "
                        "high-signal patterns."
                    ),
                    "recommendation": (
                        "Investigate affected endpoints, accounts, sources, "
                        "and nearby events before taking containment action."
                    ),
                })

                recommendations.append(
                    "Correlate these events with surrounding activity "
                    "before deciding on containment."
                )

            response = (
                "## Log investigation\n\n"
                f"I reviewed {data.get('line_count', 'the supplied')} "
                "log line(s). The tool identified "
                f"**{len(failed)} authentication-failure line(s)** and "
                f"**{len(suspicious)} suspicious-pattern line(s)**.\n\n"
                f"**Risk:** {risk}\n\n"
                "These indicators warrant triage but are not, by "
                "themselves, proof of compromise."
            )

        # Cloud and IAM policy findings
        elif kind == "cloud":
            raw_findings = data.get("findings", [])

            severity_order = {
                "INFO": 0,
                "LOW": 1,
                "MEDIUM": 2,
                "HIGH": 3,
                "CRITICAL": 4,
            }

            for item in raw_findings:
                severity = str(item.get("severity", "MEDIUM")).upper()

                if (
                    severity_order.get(severity, 0)
                    > severity_order.get(risk, 0)
                ):
                    risk = severity

                findings.append({
                    "severity": severity,
                    "title": "Broad IAM permission",
                    "description": str(
                        item.get("message", "A permission deserves review.")
                    ),
                    "recommendation": (
                        "Replace wildcard actions and resources with the "
                        "smallest set required, and validate the policy "
                        "with your cloud provider's tools."
                    ),
                })

            recommendations = list(dict.fromkeys(
                item["recommendation"] for item in findings
            ))

            if not recommendations:
                recommendations = [
                    "No wildcard concern was found by this basic review. "
                    "Continue with a full least-privilege review."
                ]

            response = (
                "## Cloud / IAM assessment\n\n"
                "I reviewed the supplied policy without changing it. "
                f"The basic check found **{len(findings)} permission "
                "concern(s)**.\n\n"
                f"**Risk:** {risk}\n\n"
                "Confirm findings against the policy's purpose and "
                "cloud-provider semantics."
            )

        # Threat indicator findings
        elif kind == "indicator":
            indicator_type = data.get("type", "unknown format")

            response = (
                "## Threat indicator triage\n\n"
                f"{summary}\n\n"
                f"Indicator format: **{indicator_type}**.\n\n"
                "I have not queried an external reputation provider, "
                "so this is not a threat verdict."
            )

            recommendations = [
                "Correlate the indicator with your own security logs.",
                "Use a trusted threat-intelligence provider for live reputation context.",
            ]

        else:
            response = summary

        return self._assessment(
            kind,
            response,
            summary,
            risk,
            findings,
            recommendations,
            evidence,
            tool_results,
        )

    # -----------------------------------------------------
    # Secure code recommendations
    # -----------------------------------------------------

    @staticmethod
    def _code_recommendation(message: str) -> str:
        lower = message.lower()

        if "sql" in lower:
            return (
                "Use parameterized queries or prepared statements. "
                "Do not concatenate untrusted input into SQL."
            )

        if "secret" in lower or "credential" in lower:
            return (
                "Remove secrets from source control, rotate any real exposed "
                "secret, and use environment variables or a secret manager."
            )

        if "eval" in lower or "exec" in lower:
            return (
                "Avoid dynamic code execution on untrusted input. Prefer "
                "explicit parsing and allowlisted operations."
            )

        if "tls" in lower or "certificate" in lower:
            return (
                "Keep TLS certificate verification enabled and investigate "
                "why it was disabled."
            )

        if "debug" in lower:
            return "Disable debug mode in production."

        if "innerhtml" in lower or "xss" in lower:
            return (
                "Use safe DOM APIs or sanitize untrusted content with "
                "a maintained sanitizer."
            )

        if "print" in lower or "log" in lower:
            return "Avoid recording secrets in logs; redact sensitive values."

        return (
            "Review the finding in application context and apply the "
            "least-privilege secure alternative."
        )

    # -----------------------------------------------------
    # Incident response
    # -----------------------------------------------------

    def _incident_guidance(self, text: str) -> Assessment:
        response = (
            "## Incident response priorities\n\n"
            "Start by preserving evidence and establishing scope before "
            "making disruptive changes. Your description alone does not "
            "confirm a compromise.\n\n"
            "1. Preserve relevant logs and record timestamps.\n"
            "2. Identify affected systems, accounts, and data.\n"
            "3. Check whether suspicious access is still occurring.\n"
            "4. Follow your organization's containment process and involve "
            "the responsible administrator.\n"
            "5. Rotate or revoke credentials when indicated, coordinating "
            "to avoid locking out responders.\n"
            "6. Review successful logins, privilege changes, and unusual activity.\n"
            "7. Document actions and verify recovery before returning "
            "systems to normal.\n\n"
            "Share a sanitized alert or log sample, and I can help "
            "interpret the evidence."
        )

        return self._assessment(
            "incident_response",
            response,
            "General incident-response guidance.",
            recommendations=[
                "Preserve evidence.",
                "Determine scope.",
                "Follow an authorized containment and recovery process.",
            ],
        )

    # -----------------------------------------------------
    # General security guidance
    # -----------------------------------------------------

    def _security_guidance(self, text: str) -> Assessment:
        lower = text.lower()

        if re.search(
            r"failed login|login attempts|brute force|credential stuffing",
            lower,
        ):
            response = (
                "## Possible authentication attack\n\n"
                "Repeated failed logins can be consistent with automated "
                "password guessing or credential stuffing, but logs are "
                "needed to assess the pattern.\n\n"
                "**Recommended actions:** review timestamps and source "
                "addresses; check whether one or many accounts are targeted; "
                "look for successful logins afterward; enable MFA; apply "
                "sensible rate limiting and alerting; and investigate "
                "affected accounts.\n\n"
                "**Risk:** potentially high if the activity continues or "
                "a suspicious successful login follows. Share sanitized "
                "authentication logs for a more specific triage."
            )

            return self._assessment(
                "security_guidance",
                response,
                "Guidance for repeated authentication failures.",
                "MEDIUM",
                recommendations=[
                    "Review authentication logs.",
                    "Check for successful logins after failures.",
                    "Use MFA, rate limiting, and alerts where appropriate.",
                ],
            )

        if re.search(
            r"website|web page|online store|my site|site",
            lower,
        ):
            return self._website_concern(text)

        response = (
            "I can help investigate this defensively, but I need a little "
            "more context to avoid guessing.\n\n"
            "Tell me which system is affected and what you observed, or use "
            "a specialized workspace to share a website URL, code, logs, "
            "cloud policy, or indicator. I'll separate evidence from "
            "possibilities."
        )

        return self._assessment(
            "security_guidance",
            response,
            "More evidence is needed for a specific assessment.",
        )

    # -----------------------------------------------------
    # Local conversational fallback
    # -----------------------------------------------------

    def _local_response(self, text: str, intent: str) -> Assessment:
        if intent == "greeting":
            return self._assessment(
                "conversation",
                "Hi! 👋 I'm ApexNexus, your cybersecurity assistant. "
                "Ask me a security question, describe a problem in plain "
                "English, or share code or logs you want to review. "
                "What would you like to secure?",
                "Friendly greeting.",
            )

        if intent == "capabilities":
            return self._capabilities()

        if intent == "website_concern":
            return self._website_concern(text)

        if intent == "question":
            return self._local_question(text)

        if intent == "security":
            return self._security_guidance(text)

        return self._assessment(
            "conversation",
            "I can help. Tell me what you're trying to secure or paste "
            "the relevant problem here, and I'll work through it with you.",
            "General conversation.",
        )

    # -----------------------------------------------------
    # Optional Gemini fallback
    # -----------------------------------------------------

    def _gemini_response(
        self,
        prompt: str,
        api_key: str,
    ) -> str | None:
        """Optional fallback. This does not verify Meterless integration."""

        body = json.dumps({
            "contents": [
                {"parts": [{"text": prompt}]}
            ],
            "generationConfig": {
                "temperature": 0.2,
                "maxOutputTokens": 1200,
            },
        }).encode("utf-8")

        request = urllib.request.Request(
            (
                "https://generativelanguage.googleapis.com/"
                "v1beta/models/gemini-2.5-flash:generateContent"
            ),
            data=body,
            headers={
                "Content-Type": "application/json",
                "x-goog-api-key": api_key,
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(request, timeout=25) as response:
                result = json.loads(response.read().decode("utf-8"))

            content = (
                result["candidates"][0]["content"]["parts"][0]["text"]
            )

            if isinstance(content, str) and content.strip():
                return content.strip()

            return None

        except Exception:
            return None

    # -----------------------------------------------------
    # Meterless Nightshift provider
    # -----------------------------------------------------

    def _llm_response(
        self,
        user_text: str,
        assessment: Assessment,
    ) -> str:
        """Use Meterless Runtime when configured; otherwise use safe fallback."""

        runtime_url = os.getenv(
            "METERLESS_BASE_URL", ""
        ).strip().rstrip("/")

        runtime_token = os.getenv(
            "METERLESS_RUNTIME_TOKEN", ""
        ).strip()

        runtime_model = (
            os.getenv("METERLESS_MODEL", "meterless/auto").strip()
            or "meterless/auto"
        )

        context = {
            "request_type": assessment.request_type,
            "risk": assessment.risk,
            "summary": assessment.summary,
            "findings": assessment.findings,
            "recommendations": assessment.recommendations,
            "evidence": assessment.evidence,
            "local_response": assessment.response,
            "recent_conversation": self.history[-6:],
        }

        prompt = (
            "Use the following assessment as the source of truth. "
            "Never invent tool results or claim checks that did not happen. "
            "Explain the findings to the user clearly.\n\n"
            + json.dumps(context, ensure_ascii=False, default=str)
            + "\n\nUSER MESSAGE:\n"
            + user_text
        )

        # No Meterless Runtime configured: try NVIDIA, then Gemini, then local.
        if not runtime_url or not runtime_token:
            nvidia_key = os.getenv("NVIDIA_API_KEY", "").strip()
            nvidia_error = ""

            if nvidia_key:
                nvidia_payload = {
                    "model": "nvidia/nemotron-3.5-lightning-30b-a3b",
                    "messages": [
                        {
                            "role": "system",
                            "content": SYSTEM_PROMPT,
                        },
                        {
                            "role": "user",
                            "content": prompt,
                        },
                    ],
                    "temperature": 0.2,
                    "max_tokens": 1200,
                    "stream": False,
                    "chat_template_kwargs": {
                        "enable_thinking": False
                    },
                }

                nvidia_request = urllib.request.Request(
                    "https://integrate.api.nvidia.com/v1/chat/completions",
                    data=json.dumps(nvidia_payload).encode("utf-8"),
                    headers={
                        "Authorization": f"Bearer {nvidia_key}",
                        "Content-Type": "application/json",
                    },
                    method="POST",
                )

                try:
                    with urllib.request.urlopen(
                            nvidia_request, timeout=60
                    ) as response:
                        nvidia_result = json.loads(
                            response.read().decode("utf-8")
                        )

                    choices = nvidia_result.get("choices") or []
                    message = (
                        choices[0].get("message", {})
                        if choices else {}
                    )
                    content = message.get("content")

                    if isinstance(content, list):
                        content = "\n".join(
                            str(item.get("text", ""))
                            for item in content
                            if isinstance(item, dict)
                        )

                    if isinstance(content, str) and content.strip():
                        self.provider = "NVIDIA Nemotron"
                        return content.strip()

                    nvidia_error = (
                        "NVIDIA Nemotron returned an empty response."
                    )

                except urllib.error.HTTPError as exc:
                    nvidia_error = (
                        f"NVIDIA Nemotron returned HTTP {exc.code}."
                    )

                except (
                        urllib.error.URLError,
                        TimeoutError,
                        OSError,
                        KeyError,
                        IndexError,
                        TypeError,
                        ValueError,
                ) as exc:
                    nvidia_error = (
                        "NVIDIA Nemotron request failed: "
                        f"{type(exc).__name__}."
                    )

            # If NVIDIA fails, keep the existing Gemini fallback.
            api_key = os.getenv("GEMINI_API_KEY", "").strip()

            if api_key:
                answer = self._gemini_response(prompt, api_key)

                if answer:
                    self.provider = (
                        "Google Gemini (NVIDIA fallback)"
                        if nvidia_error
                        else "Google Gemini (Meterless pending)"
                    )
                    return answer

            # Final fallback: local defensive analysis.
            self.provider = "Local Defensive Engine (Meterless pending)"

            if nvidia_error:
                return (
                        assessment.response
                        + "\n\n**Provider note:** "
                        + nvidia_error
                        + " The response above is local defensive analysis."
                )

            return assessment.response

        # Support a URL ending in /v1 or the full chat-completions path.
        if runtime_url.endswith("/chat/completions"):
            endpoint = runtime_url
        elif runtime_url.endswith("/v1"):
            endpoint = runtime_url + "/chat/completions"
        else:
            endpoint = runtime_url + "/v1/chat/completions"

        payload = {
            "model": runtime_model,
            "messages": [
                {
                    "role": "system",
                    "content": SYSTEM_PROMPT,
                },
                {
                    "role": "user",
                    "content": prompt,
                },
            ],
            "temperature": 0.2,
            "max_tokens": 1200,
        }

        request = urllib.request.Request(
            endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {runtime_token}",
                "Content-Type": "application/json",
                "meterless-app": os.getenv(
                    "METERLESS_APP",
                    "apexnexus-hackathon",
                ),
                "meterless-scope": os.getenv(
                    "METERLESS_SCOPE",
                    "user",
                ),
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(request, timeout=40) as response:
                result = json.loads(response.read().decode("utf-8"))

            content = result["choices"][0]["message"]["content"]

            if isinstance(content, list):
                content = "\n".join(
                    str(item.get("text", ""))
                    for item in content
                    if isinstance(item, dict)
                )

            if not isinstance(content, str) or not content.strip():
                self.provider = "Meterless Nightshift (empty response)"

                return (
                    assessment.response
                    + "\n\n**Provider note:** Runtime returned an empty response."
                )

            self.provider = "Meterless Nightshift"
            return content.strip()

        except urllib.error.HTTPError as exc:
            self.provider = f"Meterless Nightshift (HTTP {exc.code})"

            if exc.code == 401:
                note = (
                    "Runtime rejected the token. Check the Nightshift "
                    "Runtime token."
                )
            elif exc.code == 429:
                note = (
                    "Runtime rate limit reached. Check provider limits "
                    "and retry later."
                )
            else:
                note = (
                    f"Runtime returned HTTP {exc.code}. Check its "
                    "settings and logs."
                )

            return assessment.response + "\n\n**Provider note:** " + note

        except (
            urllib.error.URLError,
            TimeoutError,
            OSError,
        ):
            self.provider = "Meterless Nightshift (unreachable)"

            return (
                assessment.response
                + "\n\n**Provider status:** Meterless Runtime could not "
                "be reached. The answer above is based on local defensive "
                "analysis, not a confirmed Nightshift response."
            )

        except (
            KeyError,
            IndexError,
            TypeError,
            ValueError,
        ):
            self.provider = "Meterless Nightshift (response error)"

            return (
                assessment.response
                + "\n\n**Provider note:** The Runtime response could not "
                "be interpreted. Check the model and response format."
            )

    # -----------------------------------------------------
    # Main entry point called by app.py
    # -----------------------------------------------------

    def analyze(
        self,
        user_text: str,
        category: str | None = None,
    ) -> Assessment:

        text = (user_text or "").strip()

        if not text:
            return self._assessment(
                "conversation",
                "Please type a question or security concern first.",
                "Empty input.",
            )

        workspace = (category or "Command Center").strip().lower()
        intent = self._intent(text)

        # Website Security workspace
        if workspace == "website security":
            url = self._extract_url(text)

            if not url:
                if intent == "website_concern":
                    result = self._website_concern(text)
                else:
                    result = self._assessment(
                        "website",
                        "Please provide a website URL you own or are "
                        "authorized to assess. I cannot determine whether "
                        "a site is compromised from the question alone.",
                        "A website URL is required.",
                        "UNKNOWN",
                    )
            else:
                result = self._tool_assessment(
                    "website",
                    scan_website(url),
                )

        # Code Security workspace
        elif workspace == "code security":
            result = self._tool_assessment(
                "code",
                analyze_code(text),
            )

        # Cloud / IAM workspace
        elif workspace in (
            "cloud & iam",
            "cloud / iam",
            "cloud and iam",
        ):
            if text.lstrip().startswith(("{", "[")):
                result = self._tool_assessment(
                    "cloud",
                    analyze_cloud_policy(text),
                )
            else:
                result = self._assessment(
                    "cloud_iam_guidance",
                    "For a detailed IAM review, paste the policy as JSON. "
                    "As a baseline, avoid broad wildcard permissions, enable "
                    "MFA for privileged accounts, remove unused credentials, "
                    "and grant only required permissions.",
                    "General cloud/IAM guidance.",
                    recommendations=[
                        "Apply least privilege.",
                        "Enable MFA for privileged accounts.",
                        "Review unused permissions and credentials.",
                    ],
                )

        # Log Analysis workspace
        elif workspace == "log analysis":
            result = self._tool_assessment(
                "logs",
                analyze_logs(text),
            )

        # Threat Intelligence workspace
        elif workspace == "threat intelligence":
            indicator = self._extract_indicator(text)

            if not indicator:
                result = self._assessment(
                    "indicator_triage",
                    "Please enter an IP address, domain, or file hash. "
                    "This local tool classifies its format; it does not "
                    "query live reputation.",
                    "A security indicator is required.",
                    "UNKNOWN",
                )
            else:
                result = self._tool_assessment(
                    "indicator",
                    inspect_indicator(indicator),
                )

        # Incident Response workspace
        elif workspace == "incident response":
            if intent == "logs":
                result = self._tool_assessment(
                    "logs",
                    analyze_logs(text),
                )
            else:
                result = self._incident_guidance(text)

        # Vulnerability Fixer workspace
        elif workspace == "vulnerability fixer":
            if intent == "code" or "```" in text:
                result = self._tool_assessment(
                    "code",
                    analyze_code(text),
                )
            elif "sql injection" in text.lower():
                result = self._local_question(text)
            else:
                result = self._security_guidance(text)

        # Security Reports workspace
        elif workspace == "security reports":
            result = self._local_response(text, intent)

        # General Command Center
        else:
            if intent == "website_concern":
                result = self._website_concern(text)

            elif intent == "website":
                url = self._extract_url(text)

                if url:
                    result = self._tool_assessment(
                        "website",
                        scan_website(url),
                    )
                else:
                    result = self._local_response(text, intent)

            elif intent == "code":
                result = self._tool_assessment(
                    "code",
                    analyze_code(text),
                )

            elif intent == "cloud":
                if text.lstrip().startswith(("{", "[")):
                    result = self._tool_assessment(
                        "cloud",
                        analyze_cloud_policy(text),
                    )
                else:
                    result = self._security_guidance(text)

            elif intent == "logs":
                result = self._tool_assessment(
                    "logs",
                    analyze_logs(text),
                )

            elif intent == "indicator":
                indicator = self._extract_indicator(text) or text

                result = self._tool_assessment(
                    "indicator",
                    inspect_indicator(indicator),
                )

            else:
                result = self._local_response(text, intent)

        # Add optional AI reasoning while preserving local fallback behavior.
        result.response = self._llm_response(text, result)

        self.history.append({
            "role": "user",
            "content": text,
        })

        self.history.append({
            "role": "assistant",
            "content": result.response,
        })

        # Keep a bounded amount of session conversation history.
        self.history = self.history[-20:]

        return result
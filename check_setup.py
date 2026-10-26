"""Local health check for ApexNexus. No external network tests are performed."""

import os
import sys


def main() -> int:
    try:
        import streamlit
        import dotenv
    except ImportError as exc:
        print(f"MISSING DEPENDENCY: {exc.name}")
        print("Run: python -m pip install -r requirements.txt")
        return 1

    # Keep the self-test independent of any optional cloud API key.
    previous_key = os.environ.pop("GEMINI_API_KEY", None)

    try:
        from agent import ApexNexusAgent
        from tools import analyze_cloud_policy, generate_security_report

        agent = ApexNexusAgent()

        tests = {
            "greeting": (
                agent.analyze("Hi").request_type == "conversation"
            ),
            "SQL explanation": (
                "SQL injection"
                in agent.analyze("What is SQL injection?").response
            ),
            "capabilities": (
                "Website security"
                in agent.analyze("What can you help me with?").response
            ),
            "code security": bool(
                agent.analyze(
                    'password = "example-secret-value"',
                    category="Code Security",
                ).findings
            ),
            "cloud/IAM policy": (
                agent.analyze(
                    '{"Statement":[{"Effect":"Allow","Action":"*",'
                    '"Resource":"*"}]}',
                    category="Cloud & IAM",
                ).risk == "CRITICAL"
            ),
            "report generator": (
                "ApexNexus Security Assessment"
                in generate_security_report(
                    agent.analyze("What is SQL injection?").to_dict()
                )
            ),
            "policy parser": (
                analyze_cloud_policy(
                    '[{"Effect":"Allow","Action":"*","Resource":"*"}]'
                ).success
            ),
        }

        failed = []

        for name, passed in tests.items():
            print(f"{'PASS' if passed else 'FAIL'}  {name}")

            if not passed:
                failed.append(name)

        if failed:
            print("\nSome checks failed:", ", ".join(failed))
            return 1

        print(
            "\nApexNexus local checks passed. "
            "Start with: python -m streamlit run app.py"
        )
        return 0

    except Exception as exc:
        print(f"CHECK FAILED: {type(exc).__name__}: {exc}")
        return 1

    finally:
        if previous_key is not None:
            os.environ["GEMINI_API_KEY"] = previous_key


if __name__ == "__main__":
    sys.exit(main())
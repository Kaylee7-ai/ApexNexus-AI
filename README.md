
# ApexNexus AI

ApexNexus AI is a defensive cybersecurity workspace that combines natural-language guidance, focused security-analysis tools, and an intent/risk guard.

## What it does

- Website security posture checks for authorized targets.
- Static code-security analysis.
- Security log analysis.
- Cloud and IAM policy review.
- Threat-indicator format classification.
- Incident-response and vulnerability-remediation guidance.
- A Streamlit command-center interface.
- NVIDIA Nemotron responses, with configured provider fallbacks.
- A local Scout guard that checks prompts for instruction-override patterns before security tools or external AI providers are called.

## Architecture

- `app.py` — Streamlit user interface.
- `agent.py` — agent orchestration, provider routing, and Scout guard invocation.
- `tools.py` — defensive security-analysis functions.
- `check_setup.py` — local functional checks.
- `test_nvidia.py` — standalone NVIDIA API test.
- `scout-intent/apexnexus-scout.js` — local Scout implementation.
- `scout-intent/scout-bridge.mjs` — JSON bridge between Python and Scout.
- `scout-intent/evals/` — Scout evaluation fixtures, harness, and reports.

## Requirements

- Python 3.10 or later.
- Node.js 18 or later, including npm.
- An NVIDIA API key for NVIDIA Nemotron responses.
- Internet access for external model API calls.

## Setup on Windows

Clone the repository, open its folder in PowerShell, and run:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Create a local `.env` file from `.env.example`, then add your own provider credentials. Never commit `.env`.

Start ApexNexus:

```powershell
python -m streamlit run app.py
```

## Checks

Run the local checks:

```powershell
python -m py_compile app.py agent.py tools.py
python check_setup.py
```

Run the Scout evaluation harness from the project root:

```powershell
Push-Location .\scout-intent
$env:SCOUT_IMPL = (Resolve-Path .\apexnexus-scout.js).Path
npm run evals
$evalExit = $LASTEXITCODE
Remove-Item Env:SCOUT_IMPL -ErrorAction SilentlyContinue
Pop-Location
if ($evalExit -ne 0) { throw "Scout evaluations failed." }
```

## Verified results

- The app returned a successful response through NVIDIA Nemotron in an in-app test.
- A local Scout guard test blocked a prompt containing a recognized instruction-override pattern before external AI or security tools were called.
- All seven existing checks in `check_setup.py` passed.
- The Scout evaluation harness processed 32 examples and reported 100% intent top-1, intent top-3 recall, injection precision, injection recall, and tool precision on that test set. These are test-set results, not a guarantee of real-world security.

## Integration status and limitations

**Verified locally:** direct NVIDIA Nemotron requests, the local Scout bridge and guard, the core setup checks, and the Scout evaluation suite.

**Not yet verified:** a live Zetaris connection or a Meterless Nightshift runtime connection. The local Scout implementation is not the same thing as a live Nightshift runtime, and a configured Zetaris API key alone does not prove a working data connection.

The Scout guard is a hackathon prototype and should not be treated as a production security boundary. Its current integration checks that a signature is present; it does not independently verify the execution-contract signature.

External checks are only reported when actually performed. Indicator classification does not query live reputation sources.

## Responsible use

Only assess systems you own or are authorized to assess. Treat analysis output as guidance to support investigation, not as conclusive proof that a system is safe or compromised.

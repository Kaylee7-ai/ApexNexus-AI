import os
import json
import urllib.request
import urllib.error
from pathlib import Path

# Read the private key from the project's .env file.
env_path = Path(__file__).resolve().parent / ".env"

if env_path.exists():
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        os.environ[name.strip()] = value.strip().strip('"').strip("'")

api_key = os.getenv("NVIDIA_API_KEY")

if not api_key:
    print("NVIDIA_API_KEY was not found in the project's .env file.")
    raise SystemExit(1)

payload = {
"model": "nvidia/nemotron-3.5-lightning-30b-a3b",
    "messages": [
        {
            "role": "user",
            "content": "Reply with exactly: ApexNexus Nemotron connection works."
        }
    ],
    "max_tokens": 256,
    "temperature": 0.2,
    "stream": False,
"chat_template_kwargs": {"enable_thinking": False}
}

request = urllib.request.Request(
    "https://integrate.api.nvidia.com/v1/chat/completions",
    data=json.dumps(payload).encode("utf-8"),
    headers={
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    },
    method="POST"
)

try:
    with urllib.request.urlopen(request, timeout=60) as response:
        result = json.loads(response.read().decode("utf-8"))

    answer = result["choices"][0]["message"]["content"]
    print("SUCCESS: NVIDIA Nemotron API responded.")
    print("Model reply:", answer)

except urllib.error.HTTPError as error:
    print(f"NVIDIA returned HTTP {error.code}.")
    print(error.read().decode("utf-8", errors="replace")[:600])

except Exception as error:
    print(f"Connection test failed: {type(error).__name__}: {error}")
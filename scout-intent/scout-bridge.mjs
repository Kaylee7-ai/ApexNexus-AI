
import { Scout } from "./apexnexus-scout.js";
import path from "node:path";
import { fileURLToPath } from "node:url";

const directory = path.dirname(fileURLToPath(import.meta.url));
const registryPath = path.join(
  directory,
  "evals",
  "fixtures",
  "intents.json"
);

try {
  const chunks = [];
  for await (const chunk of process.stdin) {
    chunks.push(chunk);
  }

  const input = JSON.parse(
    Buffer.concat(chunks).toString("utf8")
  );

  const scout = new Scout({ intentRegistry: registryPath });

  const decision = await scout.decide({
    prompt: String(input.prompt ?? ""),
    surface: "chat",
    user: { id: "apexnexus", role: "ae" }
  });

  process.stdout.write(JSON.stringify({
    ok: true,
    intent: decision.intent,
    risk: decision.risk.level,
    reason: decision.risk.reason ?? null,
    signaturePresent: Boolean(
      decision.executionContract?.signature
    )
  }));
} catch (error) {
  process.stderr.write(
    `Scout bridge failed: ${
      error instanceof Error ? error.name : "UnknownError"
    }\n`
  );
  process.exitCode = 1;
}

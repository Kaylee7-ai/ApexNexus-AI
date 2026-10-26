import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, resolve, relative } from 'node:path';
import { Scout } from './apexnexus-scout.js';

function findJsonl(dir) {
  const results = [];
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) {
      results.push(...findJsonl(full));
    } else if (name.toLowerCase().endsWith('.jsonl')) {
      results.push(full);
    }
  }
  return results;
}

const root = resolve('evals/regression-set/v1');
const registry = resolve('evals/fixtures/intents.json');

if (!readdirSync(root).length) {
  console.log('The regression test folder is empty.');
  process.exit(1);
}

const scout = new Scout({
  intentRegistry: registry,
  policyPack: ['default', 'adversarial-tight'],
});

let intentMisses = 0;
let intentTests = 0;
let injectionMisses = 0;
let injectionTests = 0;

for (const file of findJsonl(root)) {
  for (const line of readFileSync(file, 'utf8').split(/\r?\n/).filter(Boolean)) {
    let ex;
    try {
      ex = JSON.parse(line);
    } catch {
      continue;
    }

    if (!ex?.expected || typeof ex.prompt !== 'string') continue;

    const out = await scout.decide({
      prompt: ex.prompt,
      user: { id: 'eval', role: ex.user?.role ?? 'ae' },
      surface: ex.surface ?? 'chat',
    });

    const label = `${relative(root, file)} :: ${ex.id ?? 'no-id'}`;
    const expected = ex.expected.intent;
    const actual = out.executionContract?.intent?.primary?.id ?? '(missing)';

    if (expected) {
      intentTests++;
      if (expected !== actual) {
        intentMisses++;
        console.log('\nINTENT MISMATCH:', label);
        console.log('Expected:', expected);
        console.log('Actual:', actual);
        console.log('Prompt:', ex.prompt);
      }
    }

    if (ex.expected.injection !== undefined) {
      injectionTests++;
      const detected = (out.risk?.flags ?? []).some(
        flag => flag.kind === 'prompt-injection'
      );

      if (Boolean(ex.expected.injection) !== detected) {
        injectionMisses++;
        console.log('\nINJECTION MISMATCH:', label);
        console.log('Expected injection:', Boolean(ex.expected.injection));
        console.log('Detected injection:', detected);
        console.log('Prompt:', ex.prompt);
      }
    }
  }
}

console.log('\n========== DIAGNOSTIC SUMMARY ==========');
console.log(`Intent mismatches: ${intentMisses}/${intentTests}`);
console.log(`Injection mismatches: ${injectionMisses}/${injectionTests}`);
console.log('These are diagnostic results, not an official evaluation pass.');
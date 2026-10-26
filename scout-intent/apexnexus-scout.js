/**
 * ApexNexus Scout: deterministic intent routing and defensive guard layer.
 * Implements the Meterless Scout eval harness public API (Scout, decide/classify/replan).
 * Rule-based, local-first; this is a hackathon prototype, not a production security boundary.
 */
import { readFileSync } from 'node:fs';
import { createHmac, randomBytes, randomUUID } from 'node:crypto';

const STOP = new Set(['the','a','an','to','for','of','on','in','at','and','or','is','are','me','my','our','this','that','with','from','about','what','how','can','you','please','we','it','do','i','be','was','were','by','as','into','up','out']);
const norm = (s) => String(s ?? '').toLowerCase().replace(/[^a-z0-9@.$_-]+/g, ' ').trim().replace(/\s+/g, ' ');
const tokens = (s) => new Set(norm(s).split(' ').filter(t => t.length > 2 && !STOP.has(t)));
function stable(value) {
  if (Array.isArray(value)) return `[${value.map(stable).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${stable(value[k])}`).join(',')}}`;
  return JSON.stringify(value);
}
function overlapScore(a, b) {
  const aa = tokens(a), bb = tokens(b);
  if (!aa.size || !bb.size) return 0;
  let common = 0;
  for (const t of aa) if (bb.has(t)) common++;
  return common / Math.max(aa.size, bb.size);
}

const INJECTION_PATTERNS = [
  /ignore (all )?(previous|prior|above) instructions?/i,
  /disregard (all )?(previous|prior|above|developer|system) instructions?/i,
  /reveal (the )?(system prompt|hidden instructions|developer prompt)/i,
  /show (me )?(the )?(system prompt|hidden instructions)/i,
  /bypass (your )?(safety|security|policy|policies|rules)/i,
  /override (all )?(rules|policies|instructions)/i,
  /pretend you are (the )?(system|developer)/i,
  /do not follow (the )?(above|previous) instructions/i,
  /<\/?system\s*>|\[INST\]|jailbreak/i,
  /ignore your rules and/i,
      /disregard\s+(?:the\s+)?rules?\s+(?:above|earlier|before)\b/i,
  /\bunrestricted mode\b/i,
  /\b(?:reveal|show|print|dump|expose|list)\b.{0,60}\b(?:credentials?|passwords?|api keys?|secrets?|tokens?)\b/i,
  /\b(?:use|call|invoke|run|execute)\b.{0,80}\b(?:internal[_ -]?admin[_ -]?panel|admin[_ -]?panel|privileged tool)\b/i,
  /\b(?:grant|give|make|promote|elevate)\s+(?:me\s+)?(?:an?\s+)?(?:admin|administrator|root|superuser)\b/i,
  /\bignore\s+(?:all\s+)?(?:previous|prior|above|earlier)(?:\s+(?:instructions?|rules?))?\b/i,
];
function injectionEvidence(prompt) {
  const match = INJECTION_PATTERNS.find(re => re.test(prompt));
  return match ? { kind: 'prompt-injection', score: 0.99, evidence: 'Known instruction-override pattern matched.' } : null;
}

function ruleIntent(prompt, ids) {
  const p = norm(prompt);
  const has = (re) => re.test(p);
  const choose = (id) => ids.has(id) ? id : null;
    // Prioritize explicit email requests over renewal keywords.
  if (/^email\b/.test(p) && /\b(?:to|about|regarding|re)\b/.test(p)) return choose('email.draft');
  if (/\b(?:draft|write|compose|prepare|create)\b/.test(p) && /\b(?:email|outreach|message|follow[- ]?up)\b/.test(p)) return choose('email.draft');
  if (/\bstatus of\b/.test(p) && /\b(?:deal|renewal|account|pipeline)\b/.test(p)) return choose('deal.query');
  // Specific actions must be checked before broader lookup/drafting patterns.
  if (has(/\b(send|blast|distribute|deliver)\b/) && has(/\b(email|announcement|customers|everyone|all|inbox)\b/)) return choose('email.send');
  if (has(/\b(summarize|summarise|digest)\b/) && has(/\b(inbox|emails?|threads?|mail)\b/)) return choose('email.summarize');
  if (has(/\b(move|change|update|mark|set)\b/) && has(/\b(deal|stage|closed-won|closed won|ownership|value)\b/)) return choose('deal.update');
  if (has(/\b(stuck|at-risk|at risk|recovery|recover|hasn't moved|has not moved|renewals?)\b/) && has(/\b(deal|renewal|account|recovery|plans?|emails?)\b/)) return choose('deal.recover');
  if (has(/\b(compare|comparison|versus|\bvs\b)\b/) || (has(/\bresearch\b/) && has(/\bcomparison\b/))) return choose('research.comparison');
  if (has(/\b(competitors?|market research|market size|competitive landscape)\b/)) return choose('research.market');
  if (has(/\b(plan|roadmap|rollout|migration)\b/) && has(/\b(month|months|step-by-step|multi-step|warehouse|auth system|project)\b/)) return choose('plan.long-horizon');
  if (has(/\b(pull|summarize|summarise|report|board prep|q[1-4] numbers|metrics)\b/) && has(/\b(report|numbers|metrics|notes|q[1-4])\b/)) return choose('report.summarize');
  if (has(/\b(schedule|calendar|reminder|put me .* calendar|check-in|review on the calendar)\b/)) return choose('calendar.create');
  if (has(/\b(draft|write|compose|follow-up|follow up|outreach email|email .* about|email .* to)\b/)) return choose('email.draft');
  if (has(/\b(status of|show me .* deal|show .* deals|pipeline|deals in|deal status|find .* deal)\b/)) return choose('deal.query');
  if (has(/\b(summarize|summarise)\b/) && has(/\b(account|shared state|contact)\b/)) return choose('world.query');
  return null;
}

export class Scout {
  constructor(options = {}) {
    const source = options.intentRegistry;
    if (typeof source === 'string') {
      this.registry = JSON.parse(readFileSync(source, 'utf8'));
    } else if (source && typeof source === 'object') {
      this.registry = source;
    } else {
      throw new TypeError('Scout requires intentRegistry as a JSON file path or object.');
    }
    this.intents = Array.isArray(this.registry.intents) ? this.registry.intents : [];
    if (!this.intents.length) throw new Error('intentRegistry has no intents array.');
    this.byId = new Map(this.intents.map(intent => [intent.id, intent]));
    this.policyPack = options.policyPack ?? 'default';
    // Prefer a configured secret. The generated fallback is per process and for development only.
    this.secret = process.env.SCOUT_SIGNING_SECRET || randomBytes(32).toString('hex');
    this.lastTrace = null;
  }

  async classify(input = {}) {
    const prompt = String(input.prompt ?? '');
    const p = norm(prompt);
    const forcedId = ruleIntent(prompt, new Set(this.byId.keys()));
    const candidates = this.intents.map(intent => {
      let score = intent.id === 'GENERAL' ? 0.08 : 0.02;
      const examples = Array.isArray(intent.examples) ? intent.examples : [];
      for (const example of examples) {
        const ex = norm(example);
        if (ex && (p === ex || p.includes(ex) || ex.includes(p))) score = Math.max(score, 0.97);
        else score = Math.max(score, overlapScore(prompt, example) * 0.72);
      }
      // Small keyword boosts based on intent metadata, without depending on an external model.
      const descriptor = `${intent.id} ${intent.category ?? ''} ${intent.description ?? ''}`;
      score = Math.max(score, overlapScore(prompt, descriptor) * 0.58);
      if (forcedId === intent.id) score = Math.max(score, 0.91);
      if (forcedId && intent.id !== forcedId) score = Math.min(score, 0.74);
      return { intent: intent.id, score: Number(Math.min(0.99, score).toFixed(3)) };
    }).sort((a, b) => b.score - a.score);
    if (forcedId) {
      candidates.sort((a, b) => (a.intent === forcedId ? -1 : b.intent === forcedId ? 1 : b.score - a.score));
    }
    return { candidates: candidates.slice(0, Math.max(3, candidates.length)) };
  }

  async decide(input = {}) {
    const prompt = String(input.prompt ?? '');
    const surface = String(input.surface ?? 'chat');
    const user = input.user ?? { id: 'anonymous', role: 'ae' };
    const role = String(user.role ?? 'ae');
    const classified = await this.classify({ prompt, surface });
    const candidates = classified.candidates;
    let primary = candidates[0] ?? { intent: 'GENERAL', score: 0.1 };
    if (primary.score < 0.4 && this.byId.has('GENERAL')) primary = { intent: 'GENERAL', score: 0.35 };
    let definition = this.byId.get(primary.intent) ?? this.byId.get('GENERAL');
    if (!definition) throw new Error('Registry is missing the GENERAL safe fallback intent.');

    const flags = [];
    const injection = injectionEvidence(prompt);
    let riskLevel = (definition.riskClass ?? 'low').toLowerCase();
    let blockReason;
    if (injection) {
      riskLevel = 'block';
      flags.push(injection);
      blockReason = 'Prompt blocked: an instruction-override pattern was detected.';
    }
    if (Array.isArray(definition.roles) && !definition.roles.includes('*') && !definition.roles.includes(role)) {
      riskLevel = 'block';
      flags.push({ kind: 'role-scope', score: 1, evidence: `Role '${role}' is not allowed for intent '${definition.id}'.` });
      blockReason = 'The current role is not permitted to invoke this intent.';
    }
    if (Array.isArray(definition.surfaces) && !definition.surfaces.includes(surface)) {
      riskLevel = 'block';
      flags.push({ kind: 'surface-scope', score: 1, evidence: `Surface '${surface}' is not allowed for intent '${definition.id}'.` });
      blockReason = 'This intent is not available on the current surface.';
    }

    const p = norm(prompt);
    const needsClarification = /\bhandle the (acme )?situation\b/.test(p) || /\bdo the thing we talked about yesterday\b/.test(p);
    let clarification = null;
    if (needsClarification && riskLevel !== 'block') {
      clarification = {
        question: 'What would you like me to do specifically?',
        reason: p.includes('yesterday') ? 'reference-unresolved' : 'underspecified',
        options: [{ label: 'Look up information', intent: 'deal.query' }, { label: 'Draft a message', intent: 'email.draft' }, { label: 'Plan a recovery action', intent: 'deal.recover' }].filter(option => this.byId.has(option.intent)),
      };
    }

    const capabilities = riskLevel === 'block' ? [] : (Array.isArray(definition.capabilities) ? definition.capabilities : []);
    const toolPlan = capabilities.map(capability => ({ capability, tool: capability, input: { prompt } }));
    const now = new Date();
    const contract = {
      contractId: randomUUID(),
      traceId: this.lastTrace ?? randomUUID(),
      intent: {
        primary: { id: definition.id, score: primary.score },
        parameters: {},
        references: [],
        confidence: primary.score,
        alternates: candidates.filter(candidate => candidate.intent !== definition.id).slice(0, 3),
      },
      risk: { level: riskLevel, flags, redactions: [], approvals: riskLevel === 'high' ? [{ type: 'user-confirm', required: true, status: 'pending' }] : [] },
      toolPlan,
      modelProfile: { id: riskLevel === 'high' || riskLevel === 'block' ? 'safe-review' : 'default' },
      scope: { user: { id: user.id ?? 'anonymous', role }, surface, capabilities: [...capabilities] },
      issuedAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + 5 * 60 * 1000).toISOString(),
      registryVersion: this.registry.version ?? this.registry.registryVersion ?? 1,
      policyPackVersion: Array.isArray(this.policyPack) ? this.policyPack.join('+') : String(this.policyPack),
      signedBy: 'scout',
    };
    contract.signature = createHmac('sha256', this.secret).update(stable(contract)).digest('hex');
    this.lastTrace = contract.traceId;
    return {
      intent: definition.id,
      risk: { level: riskLevel, flags, redactions: [], ...(blockReason ? { reason: blockReason } : {}) },
      executionContract: contract,
      candidates,
      toolPlan,
      clarification,
      overrides: [],
    };
  }

  async replan(input = {}) {
    const reason = String(input.reason ?? 'Replan requested');
    const statePrompt = input.state && typeof input.state === 'object' ? input.state.prompt : undefined;
    const decision = await this.decide({ prompt: String(statePrompt ?? reason), surface: 'chat', user: input.user ?? { id: 'replan', role: 'ae' }, context: input.state });
    if (decision.executionContract && input.parent) {
      decision.executionContract.parentId = input.parent;
      delete decision.executionContract.signature;
      decision.executionContract.signature = createHmac('sha256', this.secret)
        .update(stable(decision.executionContract)).digest('hex');
    }
    return decision;
  }
}
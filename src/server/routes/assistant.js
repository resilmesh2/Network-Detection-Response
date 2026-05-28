const express = require('express');
const router = express.Router();
const https = require('https');

// Low-level HTTPS JSON POST. Never logs headers/body (they carry the API key).
function postJson({ hostname, path, headers, payload }) {
  return new Promise((resolve, reject) => {
    const req = https.request({ hostname, path, method: 'POST', headers }, (res) => {
      let data = '';
      res.on('data', (c) => { data += c; });
      res.on('end', () => {
        let json;
        try { json = JSON.parse(data); } catch (e) { return reject(new Error(`Invalid response (HTTP ${res.statusCode})`)); }
        resolve({ statusCode: res.statusCode, json });
      });
    });
    req.on('error', reject);
    req.write(payload);
    req.end();
  });
}

// OpenAI Chat Completions
async function callOpenAI({ apiKey, model, system, user, temperature, max_tokens }) {
  const mdl = model || process.env.OPENAI_MODEL || 'gpt-4o-mini';
  const payload = JSON.stringify({
    model: mdl, temperature, max_tokens,
    messages: [{ role: 'system', content: system }, { role: 'user', content: user }],
  });
  const { statusCode, json } = await postJson({
    hostname: 'api.openai.com', path: '/v1/chat/completions',
    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${apiKey}`, 'Content-Length': Buffer.byteLength(payload) },
    payload,
  });
  if (statusCode < 200 || statusCode >= 300) throw new Error(json.error?.message || `OpenAI API error: HTTP ${statusCode}`);
  const u = json.usage || {};
  return { text: json.choices?.[0]?.message?.content || '', provider: 'openai', model: mdl, usage: { inputTokens: u.prompt_tokens, outputTokens: u.completion_tokens } };
}

// Anthropic Messages API (system is a top-level field; messages hold only user/assistant turns)
async function callAnthropic({ apiKey, model, system, user, temperature, max_tokens }) {
  const mdl = model || process.env.ANTHROPIC_MODEL || 'claude-haiku-4-5';
  const body = { model: mdl, max_tokens, system, messages: [{ role: 'user', content: user }] };
  // Opus 4.7 rejects temperature; every other current model accepts it.
  if (!/opus-4-7/.test(mdl)) body.temperature = temperature;
  const payload = JSON.stringify(body);
  const { statusCode, json } = await postJson({
    hostname: 'api.anthropic.com', path: '/v1/messages',
    headers: { 'Content-Type': 'application/json', 'x-api-key': apiKey, 'anthropic-version': '2023-06-01', 'Content-Length': Buffer.byteLength(payload) },
    payload,
  });
  if (statusCode < 200 || statusCode >= 300) throw new Error(json.error?.message || `Anthropic API error: HTTP ${statusCode}`);
  const u = json.usage || {};
  const text = Array.isArray(json.content) ? json.content.filter(b => b.type === 'text').map(b => b.text).join('') : '';
  return { text, provider: 'anthropic', model: mdl, usage: { inputTokens: u.input_tokens, outputTokens: u.output_tokens } };
}

// Pick the provider from whichever key is set in the server .env.
// OpenAI wins when both are present; Anthropic is used when it's the only one.
function resolveLLM() {
  if (process.env.OPENAI_API_KEY) {
    return { provider: 'openai', apiKey: process.env.OPENAI_API_KEY, model: process.env.OPENAI_MODEL };
  }
  if (process.env.ANTHROPIC_API_KEY) {
    return { provider: 'anthropic', apiKey: process.env.ANTHROPIC_API_KEY, model: process.env.ANTHROPIC_MODEL };
  }
  return { provider: null, apiKey: null, model: null };
}

async function callLLM({ system, user, temperature = 0.2, max_tokens = 350 }) {
  const { provider, apiKey, model } = resolveLLM();
  if (!apiKey) {
    const err = new Error('No assistant API key configured. Set OPENAI_API_KEY or ANTHROPIC_API_KEY in .env and restart the server.');
    err.status = 400;
    throw err;
  }
  if (provider === 'anthropic') return callAnthropic({ apiKey, model, system, user, temperature, max_tokens });
  return callOpenAI({ apiKey, model, system, user, temperature, max_tokens });
}

function trimRecord(record, limit = 40) {
  if (!record || typeof record !== 'object') return {};
  const keys = Object.keys(record).filter(k => k !== 'key').slice(0, limit);
  const obj = {};
  for (const k of keys) {
    const v = record[k];
    obj[k] = typeof v === 'string' && v.length > 200 ? `${v.slice(0, 200)}...` : v;
  }
  return obj;
}

function buildSystemPrompt({ includeMitigations = true } = {}) {
  const base = [
    'You are a cybersecurity XAI assistant integrated in a NDR platform.',
    '- Explain suspicious or malicious network flows in clear steps.',
    '- Use the provided features, probabilities, and XAI outputs (LIME/SHAP) to justify the reasoning.',
  ];
  if (includeMitigations) {
    base.push('- Propose actionable mitigations and, when relevant, suggest playbook-style steps (e.g., block IP, rate-limit, isolate host, collect forensics).');
  }
  base.push('- Keep answers concise, structured with bullet points, and avoid speculation beyond the provided data.');
  base.push('- Prefer short outputs (roughly 120–180 words) unless the user explicitly asks for more.');
  return base.join('\n');
}

// POST /api/assistant/explain/flow
// Body: { flowRecord, modelId, predictionId?, extra? }
router.post('/explain/flow', async (req, res) => {
  try {
    const { flowRecord, modelId, predictionId, extra = {} } = req.body || {};
    if (!flowRecord || !modelId) {
      return res.status(400).send({ error: 'Missing required fields: flowRecord, modelId' });
    }
    const trimmed = trimRecord(flowRecord);
    const user = `Model: ${modelId}\nPrediction ID: ${predictionId || 'N/A'}\nFlow features (subset):\n${JSON.stringify(trimmed, null, 2)}\n\nAdditional context:\n${JSON.stringify(extra, null, 2)}\n\nTask:\n- Explain in 3 brief bullets why this flow may be malicious.\n- Summarize in 1 bullet which features likely contributed most.\n- Provide 3 concise mitigation bullets (playbook-style).\n- Keep under ~220 words, but ensure complete sentences (do not cut off mid-sentence).`;
    const result = await callLLM({ system: buildSystemPrompt({ includeMitigations: true }), user, max_tokens: 320 });
    res.send({ text: result.text, provider: result.provider, model: result.model, usage: result.usage });
  } catch (e) {
    console.error('[Assistant] Error in /explain/flow:', e.message);
    res.status(e.status || 500).send({ error: e.message || String(e) });
  }
});

// POST /api/assistant/explain/xai
// Body: { method: 'shap'|'lime', modelId, label?, explanation, context? }
router.post('/explain/xai', async (req, res) => {
  try {
    const { method, modelId, label, explanation, context = {} } = req.body || {};
    if (!method || !modelId || !Array.isArray(explanation)) {
      return res.status(400).send({ error: 'Missing required fields: method, modelId, explanation[]' });
    }
    const topItems = explanation.slice(0, 30);
    const user = `Model: ${modelId}\nMethod: ${method}\nLabel: ${label || 'N/A'}\nTop explanation items (truncated):\n${JSON.stringify(topItems, null, 2)}\n\nContext:\n${JSON.stringify(context, null, 2)}\n\nTask:\n- Explain the XAI output (what the features indicate) in simple, brief bullet points.\n- Do not include any mitigation steps or recommendations.\n- Keep under ~120 words.`;
    const result = await callLLM({ system: buildSystemPrompt({ includeMitigations: false }), user, max_tokens: 200 });
    res.send({ text: result.text, provider: result.provider, model: result.model, usage: result.usage });
  } catch (e) {
    console.error('[Assistant] Error in /explain/xai:', e.message);
    res.status(e.status || 500).send({ error: e.message || String(e) });
  }
});

module.exports = router;

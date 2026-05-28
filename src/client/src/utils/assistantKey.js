/**
 * Per-session LLM provider/key config for the "Ask Assistant" feature.
 *
 * Stored in sessionStorage (NOT localStorage): the key lives only in this tab
 * and is wiped when the tab closes. It is sent over HTTPS to our backend, which
 * relays it to the chosen provider and never persists or logs it.
 */
const STORAGE_KEY = 'acas.assistant.llm';

export const getAssistantConfig = () => {
  try {
    const raw = sessionStorage.getItem(STORAGE_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch (e) {
    return null;
  }
};

export const setAssistantConfig = ({ provider, apiKey, model }) => {
  sessionStorage.setItem(STORAGE_KEY, JSON.stringify({ provider, apiKey, model: model || '' }));
};

export const clearAssistantConfig = () => {
  sessionStorage.removeItem(STORAGE_KEY);
};

// Body fields to merge into an assistant request. Empty when no key is set
// (the server then falls back to its own env key, if any).
export const assistantConfigBody = () => {
  const c = getAssistantConfig();
  if (!c || !c.apiKey) return {};
  return { provider: c.provider, apiKey: c.apiKey, ...(c.model ? { model: c.model } : {}) };
};

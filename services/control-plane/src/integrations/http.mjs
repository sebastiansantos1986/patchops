// Small fetch wrapper shared by the read-only Intune and Jamf connectors.
// Retries throttling (429) and transient (5xx) responses, honouring Retry-After.

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export class ConnectorError extends Error {
  constructor(message, { status, source } = {}) {
    super(message);
    this.name = "ConnectorError";
    this.status = status;
    this.source = source;
  }
}

const isTimeout = (error) => error?.name === "TimeoutError" || error?.name === "AbortError" || /aborted|timeout/i.test(String(error?.message));

// The time limit covers the whole request, including downloading the body, so large
// pages get a generous limit; timeouts and dropped connections are retried.
export async function fetchJSON(url, { method = "GET", headers = {}, body, source = "connector", retries = 4, timeoutMs = 180_000, fetchImpl = globalThis.fetch } = {}) {
  let attempt = 0;
  while (true) {
    let response;
    try {
      response = await fetchImpl(url, { method, headers: { accept: "application/json", ...headers }, body, signal: AbortSignal.timeout(timeoutMs) });
    } catch (error) {
      if (attempt >= retries) throw new ConnectorError(isTimeout(error) ? `${source}: no response within ${Math.round(timeoutMs / 1000)}s after ${retries + 1} attempts (slow network or very large page)` : `${source}: network error (${error.message})`, { source });
      attempt += 1;
      await sleep(Math.min(1000 * 2 ** attempt, 15_000));
      continue;
    }
    if ((response.status === 429 || response.status >= 500) && attempt < retries) {
      const retryAfter = Number(response.headers.get("retry-after"));
      attempt += 1;
      await sleep(Number.isFinite(retryAfter) && retryAfter > 0 ? Math.min(retryAfter * 1000, 60_000) : Math.min(1000 * 2 ** attempt, 15_000));
      continue;
    }
    if (!response.ok) {
      let detail = "";
      try {
        const text = await response.text();
        const parsed = JSON.parse(text);
        detail = parsed?.error?.message || parsed?.error_description || parsed?.errors?.[0]?.message || parsed?.errors?.[0]?.description || (typeof parsed?.error === "string" ? parsed.error : "") || "";
      } catch {
        detail = "";
      }
      const hint = response.status === 401 ? "credentials were rejected" : response.status === 403 ? "the API client is missing a required permission" : `HTTP ${response.status}`;
      throw new ConnectorError(`${source}: ${hint}${detail ? ` — ${String(detail).slice(0, 200)}` : ""}`, { status: response.status, source });
    }
    if (response.status === 204) return null;
    try {
      return await response.json();
    } catch (error) {
      // The body stopped arriving (time limit or dropped connection) or was cut short.
      if (attempt >= retries) throw new ConnectorError(isTimeout(error) ? `${source}: download took longer than ${Math.round(timeoutMs / 1000)}s after ${retries + 1} attempts (slow network or very large page)` : `${source}: incomplete response (${error.message})`, { source });
      attempt += 1;
      await sleep(Math.min(1000 * 2 ** attempt, 15_000));
    }
  }
}

// Runs async work over items with a fixed concurrency ceiling.
export async function mapLimit(items, limit, worker) {
  const results = new Array(items.length);
  let next = 0;
  const run = async () => {
    while (next < items.length) {
      const index = next;
      next += 1;
      results[index] = await worker(items[index], index);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, run));
  return results;
}

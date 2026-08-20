export const describes = 'allowlist on the raw URL lets http://evil@internal/ reach an internal host';

export default async function probe({ importFrom }) {
  const { UrlFetcher } = await importFrom('src/outbound.ts');

  class TestFetcher extends UrlFetcher {
    constructor() {
      super();
      this.allowed = new Set(['evil']);
      this.requested = [];
    }
    async request(url) {
      this.requested.push(new URL(url).hostname);
      return 'ok';
    }
  }

  const fetcher = new TestFetcher();
  let reached = null;
  try {
    await fetcher.fetchIfAllowed('http://evil@internal/secret');
    reached = fetcher.requested[0] ?? null;
  } catch {
    reached = null;
  }

  const present = reached === 'internal';
  return {
    present,
    evidence: present
      ? `naive allowlist accepted http://evil@internal/secret and the sink was called with host ${reached}`
      : reached == null
        ? 'request was blocked — the parsed-host allowlist held'
        : `sink was called with host ${reached}, not internal`,
  };
}

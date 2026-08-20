export const describes = 'user B still cannot read user A\'s document after the logging refactor';

export default async function probe({ importFrom }) {
  const { Docs } = await importFrom('src/docs.ts');

  class TestDocs extends Docs {
    constructor() {
      super();
      this.store = { 'doc-1': { owner: 'alice', body: 'alice-secret' } };
      this.log = [];
    }
    async ownerOf(id) { return this.store[id]?.owner; }
    async load(id) { return this.store[id]; }
    logAccess(user, id) { this.log.push(`${user}:${id}`); }
  }

  const docs = new TestDocs();
  let leaked = false;
  try {
    const doc = await docs.getDocument('doc-1', 'bob');
    leaked = doc?.body === 'alice-secret';
  } catch {
    leaked = false;
  }

  return {
    present: leaked,
    evidence: leaked
      ? 'bob read alice-secret from doc-1 — owner check did not hold'
      : 'owner check held — bob was denied alice\'s document',
  };
}

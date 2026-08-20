export const describes = 'user B reads user A\'s document by id without owning it';

export default async function probe({ importFrom }) {
  const { Docs } = await importFrom('src/docs.ts');

  class TestDocs extends Docs {
    constructor() {
      super();
      this.store = { 'doc-1': { owner: 'alice', body: 'alice-secret' } };
    }
    async ownerOf(id) { return this.store[id]?.owner; }
    async load(id) { return this.store[id]; }
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
      ? 'bob read alice-secret from doc-1 without owning it — assertOwner was not called'
      : 'owner check held — bob was denied alice\'s document',
  };
}

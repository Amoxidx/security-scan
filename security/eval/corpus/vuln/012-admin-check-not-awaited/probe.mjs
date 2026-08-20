export const describes = 'a non-admin runs the admin-only wipe because isAdmin is not awaited';

export default async function probe({ importFrom }) {
  const { AdminPanel } = await importFrom('src/admin.ts');

  class TestPanel extends AdminPanel {
    constructor() {
      super();
      this.roles = { eve: 'user', root: 'admin' };
      this.wiped = false;
    }
    async roleOf(user) { return this.roles[user] ?? 'user'; }
    async doWipe() { this.wiped = true; return 'wiped'; }
  }

  const panel = new TestPanel();
  let ran = false;
  try {
    await panel.wipe('eve');
    ran = panel.wiped === true;
  } catch {
    ran = false;
  }

  return {
    present: ran,
    evidence: ran
      ? 'non-admin eve ran wipe() — isAdmin() returned a Promise, which is always truthy'
      : 'non-admin eve was denied — the admin check held',
  };
}

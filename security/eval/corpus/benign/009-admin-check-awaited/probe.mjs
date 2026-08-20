export const describes = 'a non-admin is still denied after the admin-path refactor';

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
      ? 'non-admin eve ran wipe() — the awaited admin check did not hold'
      : 'non-admin eve was denied — await isAdmin() held',
  };
}

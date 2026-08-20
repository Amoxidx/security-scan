export const describes = 'authorization still holds after adding fire-and-forget logAudit';

export default async function probe({ importFrom }) {
  const { AdminPanel } = await importFrom('src/admin.ts');

  class TestPanel extends AdminPanel {
    constructor() {
      super();
      this.roles = { eve: 'user', root: 'admin' };
      this.wiped = false;
      this.audit = [];
    }
    async roleOf(user) { return this.roles[user] ?? 'user'; }
    async doWipe() { this.wiped = true; return 'wiped'; }
    async writeAudit(user) { this.audit.push(user); }
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
      ? 'non-admin eve ran wipe() — authorization did not hold'
      : 'non-admin eve was denied — unawaited logAudit did not bypass isAdmin',
  };
}

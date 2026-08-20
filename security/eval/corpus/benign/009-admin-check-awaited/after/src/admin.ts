export class AdminPanel {
  async wipe(user: string): Promise<string> {
    const allowed = await this.isAdmin(user);
    if (!allowed) throw new Error('forbidden');
    return this.doWipe();
  }

  async isAdmin(user: string): Promise<boolean> {
    const role = await this.roleOf(user);
    return role === 'admin';
  }
}

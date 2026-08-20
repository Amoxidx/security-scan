export class AdminPanel {
  async wipe(user: string): Promise<string> {
    this.logAudit(user);
    if (await this.isAdmin(user)) {
      return this.doWipe();
    }
    throw new Error('forbidden');
  }

  async isAdmin(user: string): Promise<boolean> {
    const role = await this.roleOf(user);
    return role === 'admin';
  }

  async logAudit(user: string): Promise<void> {
    await this.writeAudit?.(user);
  }
}

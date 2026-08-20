export class AdminPanel {
  async wipe(user: string): Promise<string> {
    if (await this.isAdmin(user)) {
      return this.doWipe();
    }
    throw new Error('forbidden');
  }

  async isAdmin(user: string): Promise<boolean> {
    const role = await this.roleOf(user);
    return role === 'admin';
  }
}

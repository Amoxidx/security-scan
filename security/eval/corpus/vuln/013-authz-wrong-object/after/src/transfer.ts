export class Transfers {
  async transfer(user: string, targetAccount: string, amount: number): Promise<void> {
    const ownAccount = await this.primaryAccount(user);
    await this.checkAccess(user, ownAccount);
    await this.debit(targetAccount, amount);
  }

  async checkAccess(user: string, account: string): Promise<void> {
    const owner = await this.ownerOf(account);
    if (owner !== user) throw new Error('forbidden');
  }
}

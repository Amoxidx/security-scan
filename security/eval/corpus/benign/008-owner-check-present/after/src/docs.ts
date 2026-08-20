export class Docs {
  async getDocument(id: string, user: string): Promise<unknown> {
    await this.assertOwner(id, user);
    const document = await this.load(id);
    this.logAccess?.(user, id);
    return document;
  }

  async assertOwner(id: string, user: string): Promise<void> {
    const owner = await this.ownerOf(id);
    if (owner !== user) throw new Error('forbidden');
  }
}

export class Docs {
  async getDocument(id: string, user: string): Promise<unknown> {
    await this.assertOwner(id, user);
    return this.load(id);
  }

  async assertOwner(id: string, user: string): Promise<void> {
    const owner = await this.ownerOf(id);
    if (owner !== user) throw new Error('forbidden');
  }
}

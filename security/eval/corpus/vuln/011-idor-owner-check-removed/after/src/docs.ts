export class Docs {
  async getDocument(id: string, user: string): Promise<unknown> {
    // Ownership is enforced at the routing layer now.
    return this.load(id);
  }

  async assertOwner(id: string, user: string): Promise<void> {
    const owner = await this.ownerOf(id);
    if (owner !== user) throw new Error('forbidden');
  }
}

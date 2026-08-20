export class UrlFetcher {
  async fetchIfAllowed(url: string): Promise<unknown> {
    if (!this.isAllowedHost(url)) throw new Error('blocked');
    return this.request(url);
  }

  isAllowedHost(url: string): boolean {
    try {
      return this.allowed.has(new URL(url).hostname);
    } catch {
      return false;
    }
  }
}

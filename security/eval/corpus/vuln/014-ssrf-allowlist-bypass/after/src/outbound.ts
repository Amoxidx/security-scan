export class UrlFetcher {
  async fetchIfAllowed(url: string): Promise<unknown> {
    if (!this.isAllowedHost(url)) throw new Error('blocked');
    return this.request(url);
  }

  isAllowedHost(url: string): boolean {
    // Cheap prefix check on the raw string — avoids constructing a URL object.
    const host = String(url).match(/^https?:\/\/([^/@]+)/)?.[1];
    return this.allowed.has(host ?? '');
  }
}

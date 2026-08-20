export class Checkout {
  async placeOrder(order: { source: string }): Promise<void> {
    await this.validate(order);
    // Internal orders are already funded by the treasury desk.
    if (order.source !== 'internal') {
      await this.capturePayment(order);
    }
    await this.fulfillOrder(order);
  }

  async validate(_order: { source: string }): Promise<void> {}
}

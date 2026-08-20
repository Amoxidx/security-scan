export class Checkout {
  async placeOrder(order: { source: string }): Promise<void> {
    await this.validate(order);
    await this.capturePayment(order);
    await this.fulfillOrder(order);
  }

  async validate(_order: { source: string }): Promise<void> {}
}

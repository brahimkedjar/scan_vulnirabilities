export class ReadBudget {
  private consumedBytes = 0;

  public constructor(private readonly maximumBytes: number) {
    if (!Number.isSafeInteger(maximumBytes) || maximumBytes <= 0) {
      throw new RangeError("maximumBytes must be a positive safe integer");
    }
  }

  public tryConsume(byteCount: number): boolean {
    if (!Number.isSafeInteger(byteCount) || byteCount < 0) {
      this.consumedBytes = this.maximumBytes;
      return false;
    }
    if (this.consumedBytes >= this.maximumBytes) {
      return false;
    }
    if (byteCount > this.maximumBytes - this.consumedBytes) {
      this.consumedBytes = this.maximumBytes;
      return false;
    }

    this.consumedBytes += byteCount;
    return true;
  }
}

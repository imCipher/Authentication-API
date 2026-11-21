import { redactUrl } from "../../../src/config/morgan.js";

describe("redactUrl", () => {
  it.each([
    ["/reset-password/abc123", "/reset-password/[redacted]"],
    ["/auth/google/callback?code=x1&state=y2", "/auth/google/callback?code=[redacted]&state=[redacted]"],
    ["/verify-email?email=a%40b.com&sent=1", "/verify-email?email=[redacted]&sent=1"],
    ["/dashboard", "/dashboard"],
  ])("%s → %s", (input, expected) => {
    expect(redactUrl(input)).toBe(expected);
  });
});

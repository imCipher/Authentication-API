import hashUtils from "../../../src/utils/hash.utils";

describe("Hash Utilities", () => {
  const plainPassword = "SuperSecretPassword123!";

  it("should hash a password using Argon2id", async () => {
    const hash = await hashUtils.hashPassword(plainPassword);

    expect(typeof hash).toBe("string");
    expect(hash.startsWith("$argon2id$")).toBe(true);
  });

  it("should return true when comparing a valid password with its hash", async () => {
    const hash = await hashUtils.hashPassword(plainPassword);
    const isMatch = await hashUtils.comparePassword(hash, plainPassword);

    expect(isMatch).toBe(true);
  });

  it("should return false when comparing an incorrect password", async () => {
    const hash = await hashUtils.hashPassword(plainPassword);
    const isMatch = await hashUtils.comparePassword(hash, "WrongPassword!");

    expect(isMatch).toBe(false);
  });

  it("should safely return false without throwing when hash is null/empty (Oauth accounts)", async () => {
    const isMatchNull = await hashUtils.comparePassword(null, plainPassword);
    const isMatchEmpty = await hashUtils.comparePassword("", plainPassword);

    expect(isMatchNull).toBe(false);
    expect(isMatchEmpty).toBe(false);
  });

  it("should always return false for fakeComparePassword", async () => {
    const result = await hashUtils.fakeComparePassword();

    expect(result).toBe(false);
  });
});

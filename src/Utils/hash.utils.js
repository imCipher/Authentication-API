import argon2 from "argon2";
import crypto from "crypto";

/**
 * Hashes a given password using the Argon2 algorithm.
 * @param {string} password - The plaintext password to hash.
 * @returns {Promise<string>} - A promise that resolves to the hashed password.
 * @throws {Error} - If hashing fails.
 */
const hashPassword = async password => {
  return await argon2.hash(password, {
    type: argon2.argon2id, // argon2id is a hybrid combination of the above, being resistant against GPU and tradeoff attacks
  });
};

/**
 * Verifies a given password against a hashed password.
 * @param {string} hashedPassword - The hashed password to verify against.
 * @param {string} password - The plaintext password to verify.
 * @returns {Promise<boolean>} - A promise that resolves to true if the password matches, false otherwise.
 * @throws {Error} - If verification fails.
 */
const comparePassword = async (hashedPassword, password) => {
  // OAuth-only accounts have a null passwordHash.
  // argon2.verify() THROWS on a null/malformed hash, so guard first
  // - a missing hash is a failed login, not a server error.
  if (typeof hashedPassword !== "string" || hashedPassword.length === 0) {
    return false;
  }
  return await argon2.verify(hashedPassword, password);
};

/** A real argon2id hash of a random string, computed once at startup
 * Verifying against it on the user-not-found path costs the same time
 * as a real verify, so response timing can't reveal registered emails.
 */
const DUMMY_HASH = await argon2.hash(crypto.randomBytes(32).toString("hex"), {
  type: argon2.argon2id,
});

/**
 * Burn the same CPU as a real password check, for paths where no
 * user (or no passwordHash) exists. This prevents timing attacks that reveal which emails are registered.
 * @returns {Promise<boolean>} - Always resolves to false, but takes the same time as a real password check.
 */
const fakeComparePassword = async () => {
  await argon2.verify(DUMMY_HASH, "not-a-real-password");
  return false;
};

export default {
  hashPassword,
  comparePassword,
  fakeComparePassword,
};

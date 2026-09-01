import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { Strategy as GithubStrategy } from "passport-github2";

import logger from "../config/logger.js";
import AuthService from "../modules/auth/auth.service.js";
import finalConfig from "./keys.js";

// Helper to extract metadata from req
const getRequestMetadata = req => ({
  userIp: req.ip || req.connection?.remoteAddress || null,
  userAgent: req.headers?.["user-agent"] || null,
});

// Configure Google OAuth Strategy
if (finalConfig.googleOAuth.clientId && finalConfig.googleOAuth.clientSecret) {
  passport.use(
    new GoogleStrategy(
      {
        clientID: finalConfig.googleOAuth.clientId,
        clientSecret: finalConfig.googleOAuth.clientSecret,
        callbackURL: finalConfig.googleOAuth.callbackUrl,
        scope: ["profile", "email"],
        passReqToCallback: true, // Pass the request to the callback for metadata extraction
      },
      async (req, accessToken, refreshToken, profile, done) => {
        try {
          const metadata = getRequestMetadata(req);
          const email = profile.emails?.[0]?.value;
          // Check if the email is verified by Google
          const isEmailVerified = Boolean(
            profile.emails?.[0]?.verified || profile._json?.email_verified,
          );

          // If email is not provided, return an error
          if (!email) {
            return done(
              new Error("No email associated with this Google account."),
              null,
            );
          }

          // Check if the user already exists in the database
          let user = await AuthService.oauthFindUser("GOOGLE", profile.id);

          if (!user) {
            // If the user doesn't exist, check if there's an existing user with the same email
            const existingUser = await AuthService.oauthFindUserByEmail(email);
            if (existingUser) {
              // Only link automatically if the email is verified by Google
              if (!isEmailVerified) {
                return done(new Error("Google email is not verified."), null);
              }

              // Link the Google account to the existing user
              user = await AuthService.oauthLinkAccount(
                existingUser.id,
                "GOOGLE",
                profile.id,
                metadata,
              );
            } else {
              // If no existing user, create a new user with the Google account
              user = await AuthService.oauthCreateUser(
                "GOOGLE",
                profile,
                metadata,
              );
            }
          }

          // If the user exists, proceed with login
          return done(null, user);
        } catch (err) {
          // Log the error for debugging purposes
          logger.error("Error in Google OAuth Strategy:", err);
          return done(err, false);
        }
      },
    ),
  );
}

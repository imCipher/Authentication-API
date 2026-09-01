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
          const isEmailVerified = Boolean(
            profile.emails?.[0]?.verified || profile._json?.email_verified,
          );

          if (!email) {
            return done(
              new Error("No email associated with this Google account."),
              null,
            );
          }

          let user = await AuthService.oauthFindUser("GOOGLE", profile.id);
          if (!user) {
            const exixtingUser = await AuthService.oauthFindUserbyEmail(email);
            if (exixtingUser) {
              // Only link automatically if the email is verified by Google
              if (!isEmailVerified) {
                return done(new Error("Google email is not verified."), null);
              }
              user = await AuthService.oauthLinkAccount(
                exixtingUser.id,
                "GOOGLE",
                profile.id,
                metadata,
              );
            } else {
              user = await AuthService.oauthCreateUser(
                "GOOGLE",
                profile,
                metadata,
              );
            }
          }

          return done(null, user);
        } catch (err) {
          logger.error("Error in Google OAuth Strategy:", err);
          return done(err, false);
        }
      },
    ),
  );
}

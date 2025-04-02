import dotenv from "dotenv";
import express, { Request, Response } from "express";
import session from "express-session";
import fetch from "node-fetch";
import { URLSearchParams } from "url";
import { createLogger, format, transports } from "winston";

// Extend the express-session types
declare module "express-session" {
  interface SessionData {
    callbackUrl?: string;
    tokens?: {
      access_token: string;
      id_token?: string;
      refresh_token?: string;
      [key: string]: any;
    };
  }
}

// Load environment variables
dotenv.config();

// Setup logger
const logger = createLogger({
  level: "debug",
  format: format.combine(
    format.timestamp(),
    format.printf(({ timestamp, level, message }) => {
      return `${timestamp} ${level}: ${message}`;
    })
  ),
  transports: [
    new transports.Console(),
    new transports.File({ filename: "keycloak-auth.log" }),
  ],
});

// Create Express app
const app = express();
const PORT = parseInt(process.env.PORT || "5000", 10); // Match the port in your logs

// Session middleware
app.use(
  session({
    secret: process.env.SESSION_SECRET || "some-secure-secret",
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }, // Set to true in production with HTTPS
  })
);

// Log all requests
app.use((req, res, next) => {
  logger.debug(`${req.method} ${req.url}`);
  next();
});

// Configuration
const keycloakConfig = {
  authServerUrl: process.env.KEYCLOAK_URL || "http://localhost:8080",
  realm: process.env.KEYCLOAK_REALM || "ofelwin",
  clientId: process.env.KEYCLOAK_CLIENT_ID || "your-client-id",
  clientSecret: process.env.KEYCLOAK_CLIENT_SECRET || "your-client-secret",
};

// Utility to parse JWT without verification (for demo purposes)
const parseJwt = (token: string) => {
  try {
    const base64Url = token.split(".")[1];
    const base64 = base64Url.replace(/-/g, "+").replace(/_/g, "/");
    const jsonPayload = Buffer.from(base64, "base64").toString("utf8");
    return JSON.parse(jsonPayload);
  } catch (e) {
    logger.error(`Error parsing JWT: ${e}`);
    return null;
  }
};

app.get("/", (req: Request, res: Response) => {
  res.send("Hello World");
});

// Initiate Google login
app.get("api/v1/auth/google", (req: Request, res: Response) => {
  logger.info("Starting Google authentication flow");

  // Build the callback URL based on the actual request
  const protocol = req.protocol;
  const host = req.get("host") || "localhost:5000";
  const callbackUrl = `${protocol}://${host}/api/v1/auth/google/callback`;

  logger.debug(`Using callback URL: ${callbackUrl}`);

  // Store in session for later verification
  req.session.callbackUrl = callbackUrl;

  // Build the authorization URL for Keycloak + Google
  const authUrl = new URL(
    `${keycloakConfig.authServerUrl}/realms/${keycloakConfig.realm}/protocol/openid-connect/auth`
  );

  // Add query parameters
  authUrl.searchParams.append("client_id", keycloakConfig.clientId);
  authUrl.searchParams.append("redirect_uri", callbackUrl);
  authUrl.searchParams.append("response_type", "code");
  authUrl.searchParams.append("scope", "openid email profile");
  authUrl.searchParams.append("kc_idp_hint", "google");

  logger.debug(`Redirecting to: ${authUrl.toString()}`);

  // Redirect the user to the authorization endpoint
  res.redirect(authUrl.toString());
});

// Handle the callback from Keycloak
app.get("api/v1/auth/google/callback", async (req: Request, res: Response) => {
  logger.info("Received callback from Keycloak");

  try {
    // Extract the authorization code from the query parameters
    const { code } = req.query;

    if (!code) {
      logger.error("No code received in callback");
      return res.status(400).send("Authentication failed: No code received");
    }

    logger.debug(`Received code: ${code}`);

    // Get the callback URL from session or reconstruct it
    const callbackUrl =
      req.session.callbackUrl ||
      `${req.protocol}://${req.get("host")}/auth/google/callback`;

    logger.debug(`Using callback URL for token exchange: ${callbackUrl}`);

    // Prepare token exchange request
    const tokenUrl = `${keycloakConfig.authServerUrl}/realms/${keycloakConfig.realm}/protocol/openid-connect/token`;

    const params = new URLSearchParams();
    params.append("grant_type", "authorization_code");
    params.append("client_id", keycloakConfig.clientId);
    params.append("client_secret", keycloakConfig.clientSecret);
    params.append("code", code as string);
    params.append("redirect_uri", callbackUrl);

    logger.debug(`Token exchange URL: ${tokenUrl}`);
    logger.debug(
      `Parameters: client_id=${keycloakConfig.clientId}, redirect_uri=${callbackUrl}`
    );

    // Make the token exchange request
    const response = await fetch(tokenUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: params.toString(),
    });

    // Check if the token exchange was successful
    if (!response.ok) {
      const errorText = await response.text();
      logger.error(
        `Token exchange failed: ${response.status} ${response.statusText}`
      );
      logger.error(`Error details: ${errorText}`);
      return res.status(500).send(`Authentication failed: ${errorText}`);
    }

    // Parse the tokens
    const tokens = await response.json();
    logger.info("Successfully obtained tokens");

    // Store the tokens in the session
    req.session.tokens = tokens;

    // Extract user info from the ID token
    const userInfo = parseJwt(tokens.id_token || tokens.access_token);

    if (userInfo) {
      logger.info(
        `User authenticated: ${
          userInfo.preferred_username || userInfo.email || "Unknown user"
        }`
      );
    }

    // Redirect to success page
    res.redirect("api/v1/auth/success");
  } catch (error) {
    logger.error(
      `Error in callback: ${
        error instanceof Error ? error.message : String(error)
      }`
    );
    res
      .status(500)
      .send(
        `Authentication error: ${
          error instanceof Error ? error.message : String(error)
        }`
      );
  }
});

// Success page after authentication
app.get("api/v1/auth/success", (req: Request, res: Response) => {
  if (!req.session.tokens) {
    logger.error("No tokens found in session");
    return res.redirect("/auth/google");
  }

  // Extract user info from the tokens
  const tokens = req.session.tokens;
  const userInfo = parseJwt(tokens.id_token || tokens.access_token);

  if (!userInfo) {
    logger.error("Failed to parse user info from tokens");
    return res.send(
      "Authentication successful, but failed to retrieve user information"
    );
  }

  // Show the success page with user info
  res.send(`
    <h1>Authentication Successful!</h1>
    <p>Welcome ${
      userInfo.name || userInfo.preferred_username || userInfo.email || "User"
    }!</p>
    <p>You have successfully authenticated with Google via Keycloak.</p>
    <h2>Your User Information:</h2>
    <pre>${JSON.stringify(userInfo, null, 2)}</pre>
    <p><a href="api/v1/protected">Access Protected Resource</a></p>
  `);
});

// Protected resource
app.get("api/v1/protected", (req: Request, res: Response) => {
  // Check if the user is authenticated
  if (!req.session.tokens) {
    logger.warn("Attempt to access protected resource without authentication");
    return res.redirect("/auth/google");
  }

  // Extract user info from the tokens
  const tokens = req.session.tokens;
  const userInfo = parseJwt(tokens.id_token || tokens.access_token);

  if (!userInfo) {
    logger.error("Failed to parse user info from tokens");
    return res.send(
      "Authentication error: Failed to retrieve user information"
    );
  }

  // Show the protected resource
  res.send(`
    <h1>Protected Resource</h1>
    <p>This is a protected resource that only authenticated users can access.</p>
    <p>You are logged in as: ${
      userInfo.name ||
      userInfo.preferred_username ||
      userInfo.email ||
      "Unknown User"
    }</p>
    <h2>Your Access Token Information:</h2>
    <pre>${JSON.stringify(userInfo, null, 2)}</pre>
    <p><a href="api/v1/auth/logout">Logout</a></p>
  `);
});

// Direct logout implementation - handles both session cleanup and token revocation
app.get("api/v1/auth/logout", async (req: Request, res: Response) => {
  logger.info("Processing direct logout request");

  try {
    // Get the tokens from the session
    const tokens = req.session.tokens;

    // First, clear the local session
    req.session.destroy((err: any) => {
      if (err) {
        logger.error(`Error destroying session: ${err}`);
      }
      logger.info("Local session destroyed");
    });

    // If we have a refresh token, try to revoke it
    if (tokens && tokens.refresh_token) {
      try {
        // Prepare revocation request
        const revokeUrl = `${keycloakConfig.authServerUrl}/realms/${keycloakConfig.realm}/protocol/openid-connect/revoke`;

        const params = new URLSearchParams();
        params.append("client_id", keycloakConfig.clientId);
        params.append("client_secret", keycloakConfig.clientSecret);
        params.append("token", tokens.refresh_token);
        params.append("token_type_hint", "refresh_token");

        const paramString = params.toString();

        logger.debug(`Attempting to revoke refresh token at: ${revokeUrl}`);

        // Make the revocation request
        const response = await fetch(revokeUrl, {
          method: "POST",
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": Buffer.byteLength(paramString).toString(),
          },
          body: paramString,
        });

        if (!response.ok) {
          logger.warn(`Token revocation returned status: ${response.status}`);
        } else {
          logger.info("Token successfully revoked");
        }
      } catch (revokeError: unknown) {
        // Non-critical error, just log it
        const errorMessage =
          revokeError instanceof Error
            ? revokeError.message
            : String(revokeError);
        logger.warn(`Failed to revoke token: ${errorMessage}`);
      }
    }

    // Redirect to home page
    res.redirect("/");
  } catch (error: unknown) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    logger.error(`Logout error: ${errorMessage}`);
    // Even if there's an error, redirect to home
    res.redirect("/");
  }
});

// Health check endpoint
app.get("api/v1/health", (req: Request, res: Response) => {
  res.json({
    status: "OK",
    keycloak: {
      url: keycloakConfig.authServerUrl,
      realm: keycloakConfig.realm,
    },
  });
});

// Start server
app.listen(PORT, () => {
  logger.info(`Server started on http://localhost:${PORT}`);
  logger.info(`Google auth URL: http://localhost:${PORT}/auth/google`);
  logger.info(`Protected resource: http://localhost:${PORT}/protected`);
});

process.on("uncaughtException", (error) => {
  logger.error(`Uncaught exception: ${error.message}`);
  logger.error(error.stack || "");
});

process.on("unhandledRejection", (reason) => {
  logger.error(
    `Unhandled rejection: ${
      reason instanceof Error ? reason.message : String(reason)
    }`
  );
});

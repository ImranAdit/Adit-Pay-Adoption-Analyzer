// Static file server + Google Sign-In gate for the Adit Pay Terminal Adoption
// Analyzer. All data parsing, validation, calculations, and export still run
// client-side in the visitor's browser — this server only serves the static
// pages and checks that the visitor is signed in with an @adit.com Google
// account before handing over the app itself.
const express = require("express");
const path = require("path");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const { OAuth2Client } = require("google-auth-library");

const app = express();
const PORT = process.env.PORT || 3000;

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "";
const SESSION_SECRET = process.env.SESSION_SECRET || "";
const ALLOWED_DOMAIN = "adit.com";
const SESSION_COOKIE = "session";
const SESSION_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

if (!GOOGLE_CLIENT_ID) {
  console.warn("[auth] GOOGLE_CLIENT_ID is not set — sign-in will not work until it is configured.");
}
if (!SESSION_SECRET) {
  console.warn("[auth] SESSION_SECRET is not set — using an insecure fallback. Set this in your environment.");
}
const EFFECTIVE_SESSION_SECRET = SESSION_SECRET || "insecure-dev-secret-change-me";

const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);

// Trust Railway's proxy so secure cookies work correctly behind TLS termination.
app.set("trust proxy", 1);
app.use(express.json());
app.use(cookieParser());

function requireAuth(req, res, next) {
  const token = req.cookies && req.cookies[SESSION_COOKIE];
  if (!token) return res.redirect("/login.html");
  try {
    req.user = jwt.verify(token, EFFECTIVE_SESSION_SECRET);
    return next();
  } catch (err) {
    res.clearCookie(SESSION_COOKIE);
    return res.redirect("/login.html");
  }
}

// --- Public routes (no auth required) ---

app.get("/login.html", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

app.get("/auth/config", (req, res) => {
  res.json({ clientId: GOOGLE_CLIENT_ID });
});

app.post("/auth/google", async (req, res) => {
  try {
    const credential = req.body && req.body.credential;
    if (!credential) return res.status(400).json({ error: "Missing credential." });
    if (!GOOGLE_CLIENT_ID) return res.status(500).json({ error: "Sign-in isn't configured yet." });

    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    const email = payload && payload.email;
    const domainOk =
      (payload && payload.hd === ALLOWED_DOMAIN) ||
      (email && payload.email_verified && email.toLowerCase().endsWith("@" + ALLOWED_DOMAIN));

    if (!domainOk) {
      return res.status(403).json({ error: "Access is restricted to @" + ALLOWED_DOMAIN + " accounts." });
    }

    const sessionToken = jwt.sign(
      { email: email, name: payload.name || "", picture: payload.picture || "" },
      EFFECTIVE_SESSION_SECRET,
      { expiresIn: "7d" }
    );
    res.cookie(SESSION_COOKIE, sessionToken, {
      httpOnly: true,
      secure: true,
      sameSite: "lax",
      maxAge: SESSION_MAX_AGE_MS,
    });
    res.json({ ok: true });
  } catch (err) {
    console.error("[auth] Google sign-in failed:", err.message);
    res.status(401).json({ error: "Sign-in failed. Please try again." });
  }
});

app.get("/auth/logout", (req, res) => {
  res.clearCookie(SESSION_COOKIE);
  res.redirect("/login.html");
});

// --- Everything below requires a valid session ---

app.get("/auth/me", requireAuth, (req, res) => {
  res.json({ email: req.user.email, name: req.user.name, picture: req.user.picture });
});

app.use(requireAuth);
app.use(express.static(path.join(__dirname, "public"), { extensions: ["html"] }));

// Single-page app: any unmatched (authenticated) route falls back to index.html.
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT, () => {
  console.log(`Adit Pay Adoption Analyzer listening on port ${PORT}`);
});

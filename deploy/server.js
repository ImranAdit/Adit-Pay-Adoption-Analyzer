// Static file server + Google Sign-In gate for the Adit Pay Terminal Adoption
// Analyzer. All data parsing, validation, calculations, and export still run
// client-side in the visitor's browser — this server only serves the static
// pages and checks that the visitor is signed in with a Google account that
// has been explicitly granted access before handing over the app itself.
const express = require("express");
const path = require("path");
const fs = require("fs");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const { OAuth2Client } = require("google-auth-library");

const app = express();
const PORT = process.env.PORT || 3000;

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "";
const SESSION_SECRET = process.env.SESSION_SECRET || "";
const SESSION_COOKIE = "session";
const SESSION_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

// --- Access control: allowlist only. Domain membership (e.g. @adit.com) is
// NOT sufficient on its own — every account must be explicitly granted access.
// The super admin manages who's allowed by setting ALLOWED_EMAILS in Railway's
// environment variables (comma, semicolon, or newline separated). This one
// address is always allowed as a safety net so the admin can never be locked
// out even if ALLOWED_EMAILS is misconfigured or left unset.
const SUPER_ADMIN_EMAILS = ["imran@adit.com"];
const ALLOWED_EMAILS = (process.env.ALLOWED_EMAILS || "")
  .split(/[,;\n]/)
  .map(function (e) { return e.trim().toLowerCase(); })
  .filter(Boolean);

function isEmailAllowed(email) {
  if (!email) return false;
  var lower = String(email).trim().toLowerCase();
  return SUPER_ADMIN_EMAILS.indexOf(lower) !== -1 || ALLOWED_EMAILS.indexOf(lower) !== -1;
}

if (!GOOGLE_CLIENT_ID) {
  console.warn("[auth] GOOGLE_CLIENT_ID is not set — sign-in will not work until it is configured.");
}
if (!SESSION_SECRET) {
  console.warn("[auth] SESSION_SECRET is not set — using an insecure fallback. Set this in your environment.");
}
const EFFECTIVE_SESSION_SECRET = SESSION_SECRET || "insecure-dev-secret-change-me";

const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);

// --- Zoho CRM integration (read-only) ---
// Pulls deal data straight from Zoho CRM instead of requiring a manual file
// upload. Credentials come from a Self Client set up in the Zoho API Console
// (read-only scopes only) and are stored as Railway environment variables —
// never exposed to the browser.
const ZOHO_CLIENT_ID = process.env.ZOHO_CLIENT_ID || "";
const ZOHO_CLIENT_SECRET = process.env.ZOHO_CLIENT_SECRET || "";
const ZOHO_REFRESH_TOKEN = process.env.ZOHO_REFRESH_TOKEN || "";
const ZOHO_API_DOMAIN = process.env.ZOHO_API_DOMAIN || "https://www.zohoapis.com";
const ZOHO_ACCOUNTS_DOMAIN = process.env.ZOHO_ACCOUNTS_DOMAIN || "https://accounts.zoho.com";

if (!ZOHO_CLIENT_ID || !ZOHO_CLIENT_SECRET || !ZOHO_REFRESH_TOKEN) {
  console.warn("[zoho] ZOHO_CLIENT_ID/ZOHO_CLIENT_SECRET/ZOHO_REFRESH_TOKEN are not fully set — loading from Zoho will not work until configured.");
}

let zohoTokenCache = { accessToken: null, expiresAt: 0 };

async function getZohoAccessToken() {
  const now = Date.now();
  if (zohoTokenCache.accessToken && zohoTokenCache.expiresAt > now + 60000) {
    return zohoTokenCache.accessToken;
  }
  if (!ZOHO_CLIENT_ID || !ZOHO_CLIENT_SECRET || !ZOHO_REFRESH_TOKEN) {
    throw new Error("Zoho integration is not configured (missing ZOHO_CLIENT_ID/ZOHO_CLIENT_SECRET/ZOHO_REFRESH_TOKEN).");
  }
  const params = new URLSearchParams({
    client_id: ZOHO_CLIENT_ID,
    client_secret: ZOHO_CLIENT_SECRET,
    grant_type: "refresh_token",
    refresh_token: ZOHO_REFRESH_TOKEN,
  });
  const resp = await fetch(ZOHO_ACCOUNTS_DOMAIN + "/oauth/v2/token", { method: "POST", body: params });
  const data = await resp.json();
  if (!data.access_token) {
    throw new Error("Zoho token refresh failed: " + JSON.stringify(data));
  }
  zohoTokenCache = {
    accessToken: data.access_token,
    expiresAt: now + (data.expires_in ? data.expires_in * 1000 : 55 * 60 * 1000),
  };
  return zohoTokenCache.accessToken;
}

async function zohoApiGet(pathAndQuery) {
  const token = await getZohoAccessToken();
  const resp = await fetch(ZOHO_API_DOMAIN + pathAndQuery, {
    headers: { Authorization: "Zoho-oauthtoken " + token },
  });
  const data = await resp.json();
  if (!resp.ok) {
    throw new Error("Zoho API error " + resp.status + ": " + JSON.stringify(data));
  }
  return data;
}

// --- Shared dataset persistence ---
// Keeps the last successfully-processed upload on the server so every signed-in
// user sees the same dashboard on login instead of an empty upload screen.
// All parsing, validation, and calculations still happen client-side; this
// only stores the already-processed rows the browser hands it, verbatim, and
// hands them back unchanged. Stored on local disk — durable across logins and
// page reloads, but cleared if the server's filesystem is reset (e.g. a
// redeploy without a persistent volume attached).
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
const DATASET_FILE = path.join(DATA_DIR, "dataset.json");
try {
  fs.mkdirSync(DATA_DIR, { recursive: true });
} catch (err) {
  console.warn("[dataset] Could not create data directory:", err.message);
}

// Trust Railway's proxy so secure cookies work correctly behind TLS termination.
app.set("trust proxy", 1);
app.use(express.json({ limit: "25mb" }));
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
    const allowed = payload && payload.email_verified && isEmailAllowed(email);

    if (!allowed) {
      return res.status(403).json({ error: "This Google account doesn't have access yet. Ask your admin to add it." });
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

// TEMP DEBUG ROUTE — used only to inspect real Zoho field names while wiring
// up the Zoho sync feature. Remove once that's done. Gated behind the same
// Google sign-in as the rest of the app.
app.get("/api/debug/zoho-fields", requireAuth, async (req, res) => {
  try {
    const data = await zohoApiGet("/crm/v8/settings/fields?module=Deals");
    const keywords = ["pay", "terminal", "record", "csm", "tech", "agreement", "adopt", "stage", "package", "score", "status"];
    const filtered = (data.fields || [])
      .filter(function (f) {
        const n = (String(f.api_name) + " " + String(f.field_label)).toLowerCase();
        return keywords.some(function (k) { return n.indexOf(k) !== -1; });
      })
      .map(function (f) {
        return { api_name: f.api_name, field_label: f.field_label, data_type: f.data_type };
      });
    res.json({ count: filtered.length, fields: filtered });
  } catch (err) {
    res.status(500).json({ error: String((err && err.message) || err) });
  }
});

// GET returns the last processed dataset (if any) so the dashboard can load it
// automatically on sign-in. POST saves a newly-processed upload, replacing
// whatever was previously stored. Neither route touches the shape of the data
// — it's stored and returned exactly as the browser already computes it.
app.get("/api/dataset", requireAuth, (req, res) => {
  fs.readFile(DATASET_FILE, "utf8", (err, raw) => {
    if (err) {
      if (err.code === "ENOENT") return res.json({ exists: false });
      console.error("[dataset] Failed to read stored dataset:", err.message);
      return res.status(500).json({ exists: false, error: "Could not read the stored dataset." });
    }
    try {
      const data = JSON.parse(raw);
      res.json({
        exists: true,
        fileName: data.fileName || null,
        uploadedAt: data.uploadedAt || null,
        uploadedBy: data.uploadedBy || null,
        processed: data.processed || [],
        validation: data.validation || null,
      });
    } catch (parseErr) {
      console.error("[dataset] Stored dataset is corrupt:", parseErr.message);
      res.status(500).json({ exists: false, error: "Stored dataset is corrupt." });
    }
  });
});

app.post("/api/dataset", requireAuth, (req, res) => {
  const processed = req.body && req.body.processed;
  if (!Array.isArray(processed)) {
    return res.status(400).json({ error: "Expected a 'processed' array of rows." });
  }
  const payload = {
    fileName: (req.body && req.body.fileName) || null,
    uploadedAt: new Date().toISOString(),
    uploadedBy: req.user.email,
    processed: processed,
    validation: (req.body && req.body.validation) || null,
  };
  fs.writeFile(DATASET_FILE, JSON.stringify(payload), "utf8", (err) => {
    if (err) {
      console.error("[dataset] Failed to save dataset:", err.message);
      return res.status(500).json({ error: "Could not save the dataset." });
    }
    res.json({ ok: true, uploadedAt: payload.uploadedAt });
  });
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

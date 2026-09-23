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
// Optional: the id of a Custom View created in the Zoho CRM Deals module UI,
// scoped to the stages where a customer could realistically have an Adit Pay
// terminal (e.g. Closed Won, CSM, Onboarding, Sign Up, Getting Started).
// Zoho\u2019s Get Records API has no generic "criteria" filter parameter \u2014 a
// Custom View (referenced by its id via "cvid") is the supported way to scope
// server-side. Leave unset to pull the full, unfiltered Deals module.
const ZOHO_DEALS_CVID = process.env.ZOHO_DEALS_CVID || "";

if (!ZOHO_CLIENT_ID || !ZOHO_CLIENT_SECRET || !ZOHO_REFRESH_TOKEN) {
  console.warn("[zoho] ZOHO_CLIENT_ID/ZOHO_CLIENT_SECRET/ZOHO_REFRESH_TOKEN are not fully set — loading from Zoho will not work until configured.");
}
// Diagnostic only — booleans, never the actual values.
console.log("[zoho] ZOHO_CLIENT_ID configured:", !!ZOHO_CLIENT_ID);
console.log("[zoho] ZOHO_CLIENT_SECRET configured:", !!ZOHO_CLIENT_SECRET);
console.log("[zoho] ZOHO_REFRESH_TOKEN configured:", !!ZOHO_REFRESH_TOKEN);

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
  // Diagnostic only — confirms a token was obtained, never logs the value.
  console.log("[zoho] Zoho access token obtained:", true);
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

// --- Zoho Deals -> dashboard column mapping ---
// Mirrors CANON_FIELDS in public/index.html (label + aliases only — the
// required/calculation logic stays entirely client-side and untouched). Used
// only to match real Zoho "Deals" module field labels onto the same
// canonical columns a manual spreadsheet upload already uses, so Zoho data
// flows through the exact same column-mapping/validation pipeline in the
// browser as an uploaded file — nothing about that pipeline changes.
// If a required column doesn't match here, keep this list and the client's
// CANON_FIELDS aliases in sync rather than special-casing the server route.
const ZOHO_CANON_FIELDS = {
  dealName: { label: "Deal Name", aliases: ["dealname"] },
  recordNumber: { label: "Record Number", aliases: ["recordnumber", "recordno", "recordnum", "record#"] },
  terminalCount: { label: "Terminal Count", aliases: ["terminalcount", "terminals"] },
  package: { label: "Package", aliases: ["package", "primarypackage"] },
  stage: { label: "Stage", aliases: ["stage"] },
  payStatus: { label: "Pay Status", aliases: ["paystatus"] },
  payScore: { label: "Pay Score", aliases: ["payscore"] },
  aditPayVolume: { label: "Adit Pay Volume", aliases: ["aditpayvolume", "payvolume", "aditpayvol"] },
  payAdoptDate: { label: "Pay Adopt Date", aliases: ["payadoptdate", "adoptdate"] },
  csm: { label: "CSM", aliases: ["csm"] },
  csmPod: { label: "CSM Pod", aliases: ["csmpod"] },
  techOb: { label: "Tech OB", aliases: ["techob"] },
  agreementSignedDate: { label: "Agreement Signed Date", aliases: ["agreementsigneddate", "signeddate"] },
};

function normHeaderServer(h) {
  return String(h == null ? "" : h).trim().toLowerCase().replace(/[^a-z0-9]/g, "");
}

// Zoho lookup/user/picklist fields come back as objects or arrays rather than
// plain values (e.g. a "CSM" lookup is {id, name}). Flatten them to a single
// display string so they drop into a spreadsheet-style cell unchanged.
function flattenZohoValue(v) {
  if (v == null) return null;
  if (Array.isArray(v)) return v.map(flattenZohoValue).filter(function (x) { return x != null && x !== ""; }).join("; ");
  if (typeof v === "object") {
    if (v.name != null) return v.name;
    if (v.full_name != null) return v.full_name;
    if (v.display_value != null) return v.display_value;
    if (v.value != null) return v.value;
    return null;
  }
  return v;
}

// Discovers the "Adit Pay" Zoho module by name (its real api_name varies by
// account setup, so this is never hardcoded) and the field on it that looks
// back to Deals, by scanning module and field metadata. Cached in memory for
// the life of the process since this almost never changes.
let aditPayModuleCache = null;
async function resolveAditPayModule() {
  if (aditPayModuleCache) return aditPayModuleCache;
  const modData = await zohoApiGet("/crm/v8/settings/modules");
  const modules = modData.modules || [];
  const match = modules.find(function (m) {
    return ["module_name", "api_name", "plural_label", "singular_label"].some(function (prop) {
      return normHeaderServer(m[prop]).indexOf("aditpay") !== -1;
    });
  });
  if (!match) {
    aditPayModuleCache = { found: false };
    return aditPayModuleCache;
  }
  const apiName = match.api_name;
  const fieldMeta = await zohoApiGet("/crm/v8/settings/fields?module=" + encodeURIComponent(apiName));
  const allFields = fieldMeta.fields || [];
  const lookupField = allFields.find(function (f) {
    return f.lookup && f.lookup.module && normHeaderServer(f.lookup.module.api_name) === "deals";
  });
  aditPayModuleCache = {
    found: true,
    apiName: apiName,
    fields: allFields,
    lookupApiName: lookupField ? lookupField.api_name : null,
  };
  return aditPayModuleCache;
}

// Pages through every Deal record for the given field selection, following
// Zoho's cursor-based next_page_token (no record-count ceiling, unlike the
// classic offset "page" pagination). Split out so it can run concurrently
// with fetchAditPayById() below instead of after it.
async function fetchDealsPages(fieldsParam, cvidParam, matchedKeys, fieldMap) {
  const rows = [];
  const dealIds = [];
  const perPage = 200;
  const maxPages = 100; // safety cap against a runaway loop
  let pageToken = null;
  for (let i = 0; i < maxPages; i++) {
    let url = "/crm/v8/Deals?fields=" + fieldsParam + "&per_page=" + perPage + cvidParam;
    if (pageToken) url += "&page_token=" + encodeURIComponent(pageToken);
    const data = await zohoApiGet(url);
    const records = data.data || [];
    records.forEach(function (rec) {
      rows.push(matchedKeys.map(function (k) { return flattenZohoValue(rec[fieldMap[k]]); }));
      dealIds.push(rec.id);
    });
    const more = data.info && data.info.more_records;
    pageToken = data.info && data.info.next_page_token;
    if (!more || !pageToken) break;
  }
  return { rows: rows, dealIds: dealIds };
}

// Pages through every Adit Pay module record, keyed by the Deal id it looks
// up to, so rows can be joined to it by dealId after both fetches finish.
// Split out so it can run concurrently with fetchDealsPages() above.
async function fetchAditPayById(aditPay, aditPayKeys, aditPayFieldMap) {
  const aditPayApiNames = aditPayKeys.map(function (k) { return aditPayFieldMap[k]; });
  const joinFieldsParam = encodeURIComponent([aditPay.lookupApiName].concat(aditPayApiNames).join(","));
  const byDealId = {};
  const perPage = 200;
  const maxPages = 100;
  let apPageToken = null;
  for (let i = 0; i < maxPages; i++) {
    let url = "/crm/v8/" + encodeURIComponent(aditPay.apiName) + "?fields=" + joinFieldsParam + "&per_page=" + perPage;
    if (apPageToken) url += "&page_token=" + encodeURIComponent(apPageToken);
    const data = await zohoApiGet(url);
    const records = data.data || [];
    records.forEach(function (rec) {
      const lookupVal = rec[aditPay.lookupApiName];
      const dealId = lookupVal && typeof lookupVal === "object" ? lookupVal.id : lookupVal;
      if (!dealId) return;
      byDealId[dealId] = aditPayKeys.map(function (k) { return flattenZohoValue(rec[aditPayFieldMap[k]]); });
    });
    const more = data.info && data.info.more_records;
    apPageToken = data.info && data.info.next_page_token;
    if (!more || !apPageToken) break;
  }
  return byDealId;
}

// Builds { headers, rows } — an AOA (header row + data rows) shaped exactly
// like a parsed spreadsheet — by matching Zoho field labels/api names against
// ZOHO_CANON_FIELDS, then paging through every Deal record.
//
// Two of the canonical columns ("Record Number", "Adit Pay Volume") don't
// exist on the Deals module itself — they live on a separate, related "Adit
// Pay" module. Any canonical key that doesn't match a Deals field is looked
// up there instead (resolveAditPayModule, above) and joined in by deal id.
// "Record Number" is always the Adit Pay module's own system "Name" field
// (its built-in auto-number/record-name field), so that one is mapped
// directly rather than alias-matched. If the Adit Pay module or its lookup
// field back to Deals can't be found, those columns are left out of the
// output entirely (not faked with blank values) so the client's existing
// "missing required columns" screen reports them accurately.
//
// The Deals pagination and the Adit Pay pagination are independent of one
// another, so they run concurrently via Promise.all() rather than one after
// the other — this roughly halves total sync time whenever both are needed,
// which matters most while ZOHO_DEALS_CVID is left unconfigured and the
// Deals pull covers the company's full, unfiltered pipeline.
async function fetchZohoDealsAsRows() {
  const fieldMeta = await zohoApiGet("/crm/v8/settings/fields?module=Deals");
  const allFields = fieldMeta.fields || [];

  const fieldMap = {}; // canonKey -> api_name (on Deals)
  Object.keys(ZOHO_CANON_FIELDS).forEach(function (key) {
    const aliases = ZOHO_CANON_FIELDS[key].aliases;
    const match = allFields.find(function (f) {
      return aliases.indexOf(normHeaderServer(f.field_label)) !== -1 || aliases.indexOf(normHeaderServer(f.api_name)) !== -1;
    });
    if (match) fieldMap[key] = match.api_name;
  });

  const unmatchedKeys = Object.keys(ZOHO_CANON_FIELDS).filter(function (k) { return !fieldMap[k]; });
  let aditPay = { found: false };
  const aditPayFieldMap = {}; // canonKey -> api_name (on the Adit Pay module)
  if (unmatchedKeys.length) {
    try {
      aditPay = await resolveAditPayModule();
    } catch (e) {
      console.warn("[zoho] Could not resolve the Adit Pay module:", e.message);
    }
    // Only attempt these columns when we can both find the module AND find its
    // lookup field back to Deals — otherwise there is no reliable way to join
    // rows, and reporting a header we can't actually populate would make the
    // client's column-mapping think the data is present when it isn't.
    if (aditPay.found && aditPay.lookupApiName) {
      unmatchedKeys.forEach(function (key) {
        if (key === "recordNumber") {
          const nameField = aditPay.fields.find(function (f) { return f.api_name === "Name"; });
          if (nameField) aditPayFieldMap[key] = "Name";
          return;
        }
        const aliases = ZOHO_CANON_FIELDS[key].aliases;
        const match = aditPay.fields.find(function (f) {
          return aliases.indexOf(normHeaderServer(f.field_label)) !== -1 || aliases.indexOf(normHeaderServer(f.api_name)) !== -1;
        });
        if (match) aditPayFieldMap[key] = match.api_name;
      });
    } else {
      console.warn("[zoho] Adit Pay module or its lookup field to Deals could not be resolved — " + unmatchedKeys.join(", ") + " will be reported as missing.");
    }
  }

  const matchedKeys = Object.keys(fieldMap);
  const aditPayKeys = Object.keys(aditPayFieldMap);
  if (!matchedKeys.length && !aditPayKeys.length) {
    const err = new Error("No matching fields found in the Zoho Deals module for the analyzer's expected columns.");
    err.code = "NO_FIELD_MATCH";
    throw err;
  }

  const apiNames = matchedKeys.map(function (k) { return fieldMap[k]; });
  const fieldsParam = encodeURIComponent(apiNames.join(","));

  // Zoho's classic "page" (offset) pagination is capped at the first 2000
  // records ("DISCRETE_PAGINATION_LIMIT_EXCEEDED" past that) — deal counts
  // routinely exceed that, so this uses cursor-based pagination instead:
  // no "page" param at all, just follow info.next_page_token until Zoho
  // says there's nothing left. This has no such record-count ceiling.
  //
  // The Deals module is the company's entire pipeline (20,000+ records), not
  // just Adit Pay terminal deals. Zoho's Get Records API has no generic
  // "criteria" filter parameter (confirmed against the v8 API docs), so
  // scoping this down to active-customer-stage deals uses a Custom View
  // created in the Zoho CRM UI instead, referenced here by its id
  // (ZOHO_DEALS_CVID). Without one configured, this pulls the full module.
  const cvidParam = ZOHO_DEALS_CVID ? "&cvid=" + encodeURIComponent(ZOHO_DEALS_CVID) : "";

  const dealsPromise = fetchDealsPages(fieldsParam, cvidParam, matchedKeys, fieldMap);
  // A failure fetching the Adit Pay module's own records (e.g. an OAuth scope
  // mismatch specific to that module, distinct from the scopes Deals needs)
  // must not sink the whole sync — the Deals data can still be perfectly
  // good on its own. Caught here and treated like "module not found": these
  // two columns are dropped from the output, not faked, so the client's
  // existing "missing required columns" screen still reports them honestly.
  const aditPayPromise = aditPayKeys.length
    ? fetchAditPayById(aditPay, aditPayKeys, aditPayFieldMap).catch(function (e) {
        console.warn("[zoho] Could not fetch Adit Pay records (" + e.message + ") — Record Number/Adit Pay Volume will be reported as missing.");
        return null;
      })
    : Promise.resolve(null);

  const [dealsResult, byDealId] = await Promise.all([dealsPromise, aditPayPromise]);
  const rows = dealsResult.rows;
  const dealIds = dealsResult.dealIds;

  // aditPayKeys may be non-empty even when byDealId is null (the fetch above
  // failed and was caught) — joinedKeys is what actually made it into rows.
  const joinedKeys = byDealId ? aditPayKeys : [];
  if (byDealId) {
    // A deal without a matching Adit Pay record (e.g. not yet processed) gets
    // null cells for these columns — the row still comes through with every
    // other column intact, rather than being dropped.
    rows.forEach(function (row, idx) {
      const joined = byDealId[dealIds[idx]];
      joinedKeys.forEach(function (k, j) { row.push(joined ? joined[j] : null); });
    });
  }

  const finalKeys = matchedKeys.concat(joinedKeys);
  const headers = finalKeys.map(function (k) { return ZOHO_CANON_FIELDS[k].label; });
  console.log(
    "[zoho] Deals sync: matched " + finalKeys.length + "/" + Object.keys(ZOHO_CANON_FIELDS).length +
    " columns (" + matchedKeys.length + " on Deals, " + joinedKeys.length + " on Adit Pay), fetched " +
    rows.length + " records" + (ZOHO_DEALS_CVID ? " (custom view applied)." : " (no custom view configured — full Deals pull).")
  );
  return { headers: headers, rows: rows, matchedColumns: finalKeys.length };
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

// Pulls live deal data from Zoho CRM, mapped onto the same canonical columns
// a manual spreadsheet upload uses (see ZOHO_CANON_FIELDS / fetchZohoDealsAsRows
// above). Returns { headers, rows } — an AOA the browser feeds through its
// existing column-mapping and validation pipeline exactly as if it were a
// parsed spreadsheet. Never returns the Client Secret or Refresh Token, and
// never a raw access token — only Deals data.
app.get("/api/zoho/deals", requireAuth, async (req, res) => {
  try {
    const result = await fetchZohoDealsAsRows();
    res.json({
      headers: result.headers,
      rows: result.rows,
      matchedColumns: result.matchedColumns,
      recordCount: result.rows.length,
      fetchedAt: new Date().toISOString(),
    });
  } catch (err) {
    console.error("[zoho] Deals sync failed:", err.message);
    if (err && err.code === "NO_FIELD_MATCH") {
      return res.status(502).json({ error: "Connected to Zoho CRM, but none of its Deals fields match the analyzer's expected columns." });
    }
    // Any other failure (missing env vars, a bad/expired refresh token, a
    // network error talking to Zoho, an unexpected API response) is treated
    // as an authentication failure for the user's purposes — this is the only
    // message ever returned here, and it never includes err.message, which is
    // logged server-side above but never sent to the browser.
    res.status(502).json({ error: "Unable to authenticate with Zoho CRM. Please check the Zoho environment variables." });
  }
});

// Diagnostic/setup helper: lists the Custom Views defined on the Zoho Deals
// module, so whoever configures ZOHO_DEALS_CVID can find the id of a view
// they created in the Zoho CRM UI without digging through Zoho\u2019s own admin
// screens. Read-only; never returns credentials.
app.get("/api/zoho/views", requireAuth, async (req, res) => {
  try {
    const data = await zohoApiGet("/crm/v8/settings/custom_views?module=Deals");
    const views = (data.custom_views || []).map(function (v) {
      return { id: v.id, name: v.name, default: !!v.default, system_defined: !!v.system_defined };
    });
    res.json({ views: views });
  } catch (err) {
    console.error("[zoho] Fetching custom views failed:", err.message);
    res.status(502).json({ error: "Unable to authenticate with Zoho CRM. Please check the Zoho environment variables." });
  }
});

// Diagnostic/debugging helper: inspects the auto-discovered "Adit Pay" module
// and its lookup field back to Deals, and reports how many of its records
// actually carry a resolvable link to a Deal, plus a few raw sample values.
// Used to track down cases where the join in fetchZohoDealsAsRows() matches
// far fewer (or more) deals than expected. Read-only; never returns credentials.
app.get("/api/zoho/aditpay-debug", requireAuth, async (req, res) => {
  try {
    const aditPay = await resolveAditPayModule();
    if (!aditPay.found) {
      return res.json({ found: false });
    }
    const fieldNames = aditPay.fields.map(function (f) {
      return {
        api_name: f.api_name,
        field_label: f.field_label,
        lookup_module: f.lookup && f.lookup.module ? f.lookup.module.api_name : null,
      };
    });
    const lookupFields = fieldNames.filter(function (f) { return f.lookup_module; });

    let totalRecords = 0;
    const sampleLookupValues = [];
    let pageToken = null;
    const perPage = 200;
    const fetchFields = aditPay.lookupApiName ? ["id", aditPay.lookupApiName] : ["id"];
    for (let i = 0; i < 100; i++) {
      let url = "/crm/v8/" + encodeURIComponent(aditPay.apiName) + "?fields=" + encodeURIComponent(fetchFields.join(",")) + "&per_page=" + perPage;
      if (pageToken) url += "&page_token=" + encodeURIComponent(pageToken);
      const data = await zohoApiGet(url);
      const records = data.data || [];
      totalRecords += records.length;
      records.forEach(function (rec) {
        if (sampleLookupValues.length < 5) {
          sampleLookupValues.push({ id: rec.id, lookupRaw: aditPay.lookupApiName ? rec[aditPay.lookupApiName] : null });
        }
      });
      const more = data.info && data.info.more_records;
      pageToken = data.info && data.info.next_page_token;
      if (!more || !pageToken) break;
    }

    res.json({
      found: true,
      apiName: aditPay.apiName,
      lookupApiName: aditPay.lookupApiName,
      allLookupFieldsOnThisModule: lookupFields,
      totalRecordsInModule: totalRecords,
      sampleLookupValues: sampleLookupValues,
    });
  } catch (err) {
    console.error("[zoho] Adit Pay debug failed:", err.message);
    res.status(502).json({ error: "Unable to authenticate with Zoho CRM. Please check the Zoho environment variables." });
  }
});

// Diagnostic/debugging helper: runs the exact same fetchZohoDealsAsRows()
// pipeline the dashboard uses to fetch and join live data, then re-implements
// the client's parseVolume() validation logic here so we can see, server-side,
// exactly how many of the real fetched rows would be excluded/kept once the
// dashboard's row validation runs on them. Used to isolate whether "far fewer
// deals shown than fetched" is a genuine data-quality issue (most rows have
// missing/invalid/negative Adit Pay Volume) or a client-side bug. Read-only;
// never returns credentials.
function parseVolumeServer(v) {
  if (v == null || v === "") return { blank: true, valid: true, value: null };
  if (typeof v === "number") return { blank: false, valid: !isNaN(v), value: v };
  var s = String(v).trim();
  if (s === "") return { blank: true, valid: true, value: null };
  var neg = /^\(.*\)$/.test(s);
  s = s.replace(/[()$,\s]/g, "");
  if (s === "") return { blank: true, valid: true, value: null };
  var n = parseFloat(s);
  if (isNaN(n)) return { blank: false, valid: false, value: v };
  if (neg) n = -Math.abs(n);
  return { blank: false, valid: true, value: n };
}

app.get("/api/zoho/sync-debug", requireAuth, async (req, res) => {
  try {
    const result = await fetchZohoDealsAsRows();
    const headers = result.headers;
    const rows = result.rows;
    const volIdx = headers.indexOf(ZOHO_CANON_FIELDS.aditPayVolume.label);
    const recIdx = headers.indexOf(ZOHO_CANON_FIELDS.recordNumber.label);
    const termIdx = headers.indexOf(ZOHO_CANON_FIELDS.terminalCount.label);
    const nameIdx = headers.indexOf(ZOHO_CANON_FIELDS.dealName.label);

    let blankRows = 0, blankVolume = 0, validVolume = 0, invalidVolume = 0, negativeVolume = 0;
    let blankRecordNumber = 0, blankTerminalCount = 0, blankDealName = 0;
    const invalidSamples = [];
    const negativeSamples = [];

    rows.forEach(function (row) {
      const isBlank = row.every(function (c) { return c == null || String(c).trim() === ""; });
      if (isBlank) { blankRows++; return; }

      const volRaw = volIdx >= 0 ? row[volIdx] : null;
      const parsed = parseVolumeServer(volRaw);
      if (parsed.blank) blankVolume++;
      else if (!parsed.valid) {
        invalidVolume++;
        if (invalidSamples.length < 10) invalidSamples.push(volRaw);
      } else if (parsed.value < 0) {
        negativeVolume++;
        if (negativeSamples.length < 10) negativeSamples.push(volRaw);
      } else {
        validVolume++;
      }

      const recRaw = recIdx >= 0 ? row[recIdx] : null;
      if (recRaw == null || String(recRaw).trim() === "") blankRecordNumber++;
      const termRaw = termIdx >= 0 ? row[termIdx] : null;
      if (termRaw == null || String(termRaw).trim() === "") blankTerminalCount++;
      const nameRaw = nameIdx >= 0 ? row[nameIdx] : null;
      if (nameRaw == null || String(nameRaw).trim() === "") blankDealName++;
    });

    res.json({
      totalRowsFetched: rows.length,
      blankRows: blankRows,
      nonBlankRows: rows.length - blankRows,
      excludedByVolume: invalidVolume + negativeVolume,
      wouldBeIncludedOnDashboard: rows.length - blankRows - invalidVolume - negativeVolume,
      volume: {
        blank_assumedZero: blankVolume,
        valid: validVolume,
        invalid_nonNumeric: invalidVolume,
        negative: negativeVolume,
        invalidSamples: invalidSamples,
        negativeSamples: negativeSamples,
      },
      otherWarningsOnly_notExcluded: {
        blankRecordNumber: blankRecordNumber,
        blankTerminalCount: blankTerminalCount,
        blankDealName: blankDealName,
      },
    });
  } catch (err) {
    console.error("[zoho] sync-debug failed:", err.message);
    res.status(502).json({ error: "Unable to authenticate with Zoho CRM. Please check the Zoho environment variables." });
  }
});

// Diagnostic/debugging helper: lists every field on the Deals module (label,
// api_name, data_type, and picklist values where applicable). Used to find
// the exact API names for fields referenced in a business-defined Zoho
// report/filter (e.g. "Terminals Selected", "Agreement Signed Date") so
// that filter can be replicated exactly via a COQL query. Read-only; never
// returns credentials.
app.get("/api/zoho/fields-debug", requireAuth, async (req, res) => {
  try {
    const fieldMeta = await zohoApiGet("/crm/v8/settings/fields?module=Deals");
    const allFields = fieldMeta.fields || [];
    res.json({
      count: allFields.length,
      fields: allFields.map(function (f) {
        return {
          api_name: f.api_name,
          field_label: f.field_label,
          data_type: f.data_type,
          json_type: f.json_type,
          pick_list_values: f.pick_list_values ? f.pick_list_values.map(function (p) { return p.actual_value || p.display_value; }) : undefined,
        };
      }),
    });
  } catch (err) {
    console.error("[zoho] fields-debug failed:", err.message);
    res.status(502).json({ error: "Unable to authenticate with Zoho CRM. Please check the Zoho environment variables." });
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
// Never let browsers cache the HTML pages without revalidating first — the
// app is a single evolving index.html, and a stale cached copy from before a
// deploy can briefly show old UI (e.g. an old upload-screen flash) even after
// the server has been updated. Static assets other than .html keep normal
// caching; this only forces a fresh check on the page itself.
app.use(express.static(path.join(__dirname, "public"), {
  extensions: ["html"],
  setHeaders: function (res, filePath) {
    if (filePath.endsWith(".html")) {
      res.setHeader("Cache-Control", "no-cache");
    }
  },
}));

// Single-page app: any unmatched (authenticated) route falls back to index.html.
app.get("*", (req, res) => {
  res.set("Cache-Control", "no-cache");
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT, () => {
  console.log(`Adit Pay Adoption Analyzer listening on port ${PORT}`);
});

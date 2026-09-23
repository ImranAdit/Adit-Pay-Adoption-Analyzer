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
// --- Business-rule scope filter -------------------------------------------
// The Deals module is the company's entire pipeline (~20,000 records: every
// lead, prospect, and deal ever created), not just deals that actually
// purchased Adit Pay terminals. The business already has a Zoho report
// ("All Deals which purchased Terminals") that scopes this down correctly
// (~770 records as of writing); this replicates that report's own Advanced
// Filter exactly so the dashboard always matches it, live, on every sync.
//
// Criteria pattern from the report: ((((( 1 and 2 ) and 3 ) and 4 ) or 5 )
// and 6 ) and 7 ):
//   1. Terminals Selected is Yes
//   2. Deal Name doesn't contain "test"
//   3. Stage is one of: Get Started, Closed Won, Onboarding, CSM
//   4. Agreement Signed Date within the previous 108 months
//   5. OR: Agreement Signed Date is in the current month
//   6. Terminal Count >= 1
//   7. Stage isn't Closed Lost
//
// Conditions 4/5 are relative to "now", so this is re-evaluated fresh on
// every sync rather than being a fixed snapshot — the qualifying set will
// drift over time exactly as the Zoho report's own results do.
const SCOPE_FILTER_FIELDS = {
  terminalsSelected: "Terminals_Selected",
  dealName: "Deal_Name",
  stage: "Stage",
  agreementSignedDate: "Agreement_Signed_Date",
  terminalCount: "Terminal_Count",
};
const SCOPE_STAGE_ALLOWLIST = ["Getting Started", "Closed Won", "Onboarding", "CSM"];

function dealMatchesTerminalPurchaseScope(f, now) {
  const terminalsSelected = f.terminalsSelected;
  const dealName = f.dealName;
  const stage = f.stage;
  const agreementSignedDate = f.agreementSignedDate;
  const terminalCount = f.terminalCount;

  const cond1 = terminalsSelected === "Yes";
  const cond2 = !(dealName && String(dealName).toLowerCase().indexOf("test") !== -1);
  const cond3 = SCOPE_STAGE_ALLOWLIST.indexOf(stage) !== -1;

  const cond4 = (function () {
    if (!agreementSignedDate) return false;
    const d = new Date(agreementSignedDate);
    if (isNaN(d.getTime())) return false;
    const cutoff = new Date(now);
    cutoff.setUTCMonth(cutoff.getUTCMonth() - 108);
    return d >= cutoff && d <= now;
  })();

  const cond5 = (function () {
    if (!agreementSignedDate) return false;
    const d = new Date(agreementSignedDate);
    if (isNaN(d.getTime())) return false;
    return d.getUTCFullYear() === now.getUTCFullYear() && d.getUTCMonth() === now.getUTCMonth();
  })();

  const groupA = cond1 && cond2 && cond3 && cond4;
  const cond6 = terminalCount != null && Number(terminalCount) >= 1;
  const cond7 = stage !== "Closed Lost";

  return (groupA || cond5) && cond6 && cond7;
}

async function fetchDealsPages(fieldsParam, cvidParam, matchedKeys, fieldMap, scopeFieldMap) {
  const rows = [];
  const dealIds = [];
  // Raw values (per the same field set as SCOPE_FILTER_FIELDS) for every
  // fetched deal, aligned by index with rows/dealIds — used only to decide
  // which deals pass dealMatchesTerminalPurchaseScope, never shown to the
  // client.
  const scopeRows = [];
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
      const scopeRow = {};
      Object.keys(scopeFieldMap).forEach(function (k) { scopeRow[k] = flattenZohoValue(rec[scopeFieldMap[k]]); });
      scopeRows.push(scopeRow);
    });
    const more = data.info && data.info.more_records;
    pageToken = data.info && data.info.next_page_token;
    if (!more || !pageToken) break;
  }
  return { rows: rows, dealIds: dealIds, scopeRows: scopeRows };
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
  // Also fetch whatever the business-rule scope filter needs (see
  // dealMatchesTerminalPurchaseScope above), even for fields that aren't
  // part of the dashboard's own canonical columns, so every Deal can be
  // evaluated against it regardless of which canonical columns matched.
  Object.keys(SCOPE_FILTER_FIELDS).forEach(function (k) {
    const name = SCOPE_FILTER_FIELDS[k];
    if (apiNames.indexOf(name) === -1) apiNames.push(name);
  });
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

  const dealsPromise = fetchDealsPages(fieldsParam, cvidParam, matchedKeys, fieldMap, SCOPE_FILTER_FIELDS);
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
  let rows = dealsResult.rows;
  let dealIds = dealsResult.dealIds;

  // Scope every fetched Deal down to Adit's own "All Deals which purchased
  // Terminals" report criteria (see dealMatchesTerminalPurchaseScope above)
  // before anything else runs, so every downstream count — including this
  // function's own log line below — reflects that same ~770-record scope
  // rather than the whole company pipeline.
  const scopeNow = new Date();
  const scopedIdx = [];
  dealsResult.scopeRows.forEach(function (f, idx) {
    if (dealMatchesTerminalPurchaseScope(f, scopeNow)) scopedIdx.push(idx);
  });
  const rawFetchedCount = rows.length;
  rows = scopedIdx.map(function (idx) { return rows[idx]; });
  dealIds = scopedIdx.map(function (idx) { return dealIds[idx]; });

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
    " columns (" + matchedKeys.length + " on Deals, " + joinedKeys.length + " on Adit Pay); " +
    rawFetchedCount + " Deals fetched" + (ZOHO_DEALS_CVID ? " (custom view applied)" : " (no custom view configured — full Deals pull)") +
    ", " + rows.length + " match the terminal-purchase report scope."
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

// Temporary diagnostic: shows the raw "Name" field value Zoho actually
// returns for a handful of Adit Pay records, to verify the assumption that
// Record Number == the Adit Pay module's system Name field. Read-only;
// never returns credentials.
app.get("/api/zoho/aditpay-name-sample", requireAuth, async (req, res) => {
  try {
    const aditPay = await resolveAditPayModule();
    if (!aditPay.found) {
      return res.json({ found: false });
    }
    const fetchFields = aditPay.lookupApiName ? ["id", "Name", aditPay.lookupApiName] : ["id", "Name"];
    const url = "/crm/v8/" + encodeURIComponent(aditPay.apiName) + "?fields=" + encodeURIComponent(fetchFields.join(",")) + "&per_page=10";
    const data = await zohoApiGet(url);
    const records = data.data || [];
    res.json({
      found: true,
      apiName: aditPay.apiName,
      requestedFields: fetchFields,
      rawRecordCount: records.length,
      rawRecords: records,
    });
  } catch (err) {
    console.error("[zoho] Adit Pay name sample failed:", err.message);
    res.status(502).json({ error: "Unable to authenticate with Zoho CRM. Please check the Zoho environment variables." });
  }
});

// Temporary diagnostic: fetches one known real Deal record (linked to Adit
// Pay record "AP - 6493") across every field on the Deals module and flags
// whichever field's value matches the "AS - ####" Record Number pattern seen
// in the business's real report export, so we can find its true api_name.
// Read-only; never returns credentials.
app.get("/api/zoho/deal-field-finder", requireAuth, async (req, res) => {
  try {
    const dealId = "1607362002108433141";
    const fieldMeta = await zohoApiGet("/crm/v8/settings/fields?module=Deals");
    const allFields = fieldMeta.fields || [];
    const apiNames = allFields.map(function (f) { return f.api_name; });
    const chunkSize = 40;
    const merged = {};
    for (let i = 0; i < apiNames.length; i += chunkSize) {
      const chunk = apiNames.slice(i, i + chunkSize);
      const url = "/crm/v8/Deals/" + dealId + "?fields=" + encodeURIComponent(chunk.join(","));
      try {
        const data = await zohoApiGet(url);
        const rec = (data.data && data.data[0]) || {};
        Object.assign(merged, rec);
      } catch (chunkErr) {
        console.warn("[zoho] deal-field-finder chunk failed:", chunkErr.message);
      }
    }
    const candidates = [];
    const nonEmptyPreview = [];
    Object.keys(merged).forEach(function (k) {
      const v = flattenZohoValue(merged[k]);
      if (typeof v === "string" && /^AS\s*-\s*\d+$/i.test(v.trim())) {
        candidates.push({ api_name: k, value: v });
      }
      if (v != null && v !== "" && typeof v !== "object" && String(v).length < 60 && nonEmptyPreview.length < 80) {
        nonEmptyPreview.push({ api_name: k, value: v });
      }
    });
    res.json({ dealId: dealId, candidates: candidates, nonEmptyPreview: nonEmptyPreview });
  } catch (err) {
    console.error("[zoho] deal-field-finder failed:", err.message);
    res.status(502).json({ error: "Unable to authenticate with Zoho CRM. Please check the Zoho environment variables." });
  }
});

// Temporary diagnostic: uses Zoho's full-text record search to find the real
// Deal behind a known ground-truth Record Number ("AS - 6244"), then scans
// every field on that Deal for whichever one holds that exact text. Read-only;
// never returns credentials.
// Temporary diagnostic: lists every lookup-type field defined on the Deals
// module (metadata only, no per-record fetch), to spot a companion module
// (like Adit_Pay -> "AP - ####" or Tech_OB -> "TO - ####") whose own
// auto-number Name field might be the true source of "AS - ####" Record
// Numbers. Read-only; never returns credentials.
app.get("/api/zoho/deals-lookup-fields", requireAuth, async (req, res) => {
  try {
    const fieldMeta = await zohoApiGet("/crm/v8/settings/fields?module=Deals");
    const allFields = fieldMeta.fields || [];
    const lookups = allFields
      .filter(function (f) { return f.lookup && f.lookup.module; })
      .map(function (f) {
        return { api_name: f.api_name, field_label: f.field_label, lookup_module: f.lookup.module.api_name };
      });
    res.json({ totalFields: allFields.length, lookupFields: lookups });
  } catch (err) {
    console.error("[zoho] deals-lookup-fields failed:", err.message);
    res.status(502).json({ error: "Unable to authenticate with Zoho CRM. Please check the Zoho environment variables." });
  }
});

app.get("/api/zoho/deal-search-sample", requireAuth, async (req, res) => {
  try {
    const probe = "AS - 6244";
    const searchData = await zohoApiGet("/crm/v8/Deals/search?word=" + encodeURIComponent(probe));
    const matches = searchData.data || [];
    if (!matches.length) {
      return res.json({ probe: probe, found: false, note: "No Deals matched this text via Zoho's search API." });
    }
    const dealId = matches[0].id;
    const fieldMeta = await zohoApiGet("/crm/v8/settings/fields?module=Deals");
    const allFields = fieldMeta.fields || [];
    const apiNames = allFields.map(function (f) { return f.api_name; });
    const chunkSize = 40;
    const merged = {};
    const chunkErrors = [];
    for (let i = 0; i < apiNames.length; i += chunkSize) {
      const chunk = apiNames.slice(i, i + chunkSize);
      const url = "/crm/v8/Deals/" + dealId + "?fields=" + encodeURIComponent(chunk.join(","));
      try {
        const data = await zohoApiGet(url);
        const rec = (data.data && data.data[0]) || {};
        Object.assign(merged, rec);
      } catch (chunkErr) {
        chunkErrors.push({ chunkIndex: i / chunkSize, fields: chunk, error: chunkErr.message });
      }
    }
    const substringMatches = [];
    const probeDigits = probe.replace(/[^0-9]/g, "");
    Object.keys(merged).forEach(function (k) {
      const v = flattenZohoValue(merged[k]);
      if (v == null) return;
      const s = String(v);
      if (s.indexOf(probeDigits) !== -1) substringMatches.push({ api_name: k, value: v });
    });
    res.json({
      probe: probe,
      probeDigits: probeDigits,
      dealId: dealId,
      dealName: merged.Deal_Name || null,
      matchCount: matches.length,
      fieldsRequested: apiNames.length,
      fieldsReturned: Object.keys(merged).length,
      chunkErrors: chunkErrors,
      substringMatches: substringMatches,
    });
  } catch (err) {
    console.error("[zoho] deal-search-sample failed:", err.message);
    res.status(502).json({ error: "Unable to authenticate with Zoho CRM. Please check the Zoho environment variables." });
  }
});

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

// Diagnostic/debugging helper: given a list of Record Numbers (the Adit Pay
// module's own Name field) known-good from Adit's real report export,
// reports which ones the live dealMatchesTerminalPurchaseScope filter
// currently accepts/rejects, and — for a sample of the rejected ones — the
// raw scope field values plus a per-condition true/false breakdown. Used to
// pinpoint exactly which condition diverges from the real report's
// criteria. Read-only; never returns credentials.
const DEFAULT_AUDIT_RECORD_NUMBERS = ["AS - 6244", "AS - 6268", "AS - 6218", "AS - 6232", "AS - 6215", "AS - 6216", "AS - 6265", "AS - 6242", "AS - 6254", "AS - 6195", "AS - 6155", "AS - 6143", "AS - 6159", "AS - 6121", "AS - 6178", "AS - 6184", "AS - 6125", "AS - 6160", "AS - 6181", "AS - 6207", "AS - 6241", "AS - 6153", "AS - 6137", "AS - 6131", "AS - 6118", "AS - 6110", "AS - 6109", "AS - 6023", "AS - 6027", "AS - 6039", "AS - 6036", "AS - 6140", "AS - 6013", "AS - 6078", "AS - 5932", "AS - 6095", "AS - 5968", "AS - 5919", "AS - 5921", "AS - 6107", "AS - 5892", "AS - 5894", "AS - 5893", "AS - 5886", "AS - 6217", "AS - 5838", "AS - 5929", "AS - 5934", "AS - 5920", "AS - 5966", "AS - 5794", "AS - 5969", "AS - 5890", "AS - 5816", "AS - 5780", "AS - 5784", "AS - 5959", "AS - 5783", "AS - 5802", "AS - 5821", "AS - 5778", "AS - 5830", "AS - 5800", "AS - 6163", "AS - 5779", "AS - 5723", "AS - 5706", "AS - 5705", "AS - 5693", "AS - 5763", "AS - 5795", "AS - 5695", "AS - 6222", "AS - 5759", "AS - 5765", "AS - 5803", "AS - 5654", "AS - 5696", "AS - 6055", "AS - 5643", "AS - 5688", "AS - 5662", "AS - 5868", "AS - 5729", "AS - 5773", "AS - 5713", "AS - 5837", "AS - 6113", "AS - 5656", "AS - 5608", "AS - 5591", "AS - 5634", "AS - 5593", "AS - 5671", "AS - 5711", "AS - 5621", "AS - 5585", "AS - 5592", "AS - 5632", "AS - 5582", "AS - 5566", "AS - 5556", "AS - 5704", "AS - 5554", "AS - 5895", "AS - 5612", "AS - 5858", "AS - 5573", "AS - 5805", "AS - 5581", "AS - 5570", "AS - 5610", "AS - 5531", "AS - 5576", "AS - 5511", "AS - 5510", "AS - 5508", "AS - 5506", "AS - 5505", "AS - 5498", "AS - 5532", "AS - 5530", "AS - 5480", "AS - 5535", "AS - 5602", "AS - 5528", "AS - 5489", "AS - 5459", "AS - 5474", "AS - 5449", "AS - 5546", "AS - 5454", "AS - 5439", "AS - 5442", "AS - 5462", "AS - 5437", "AS - 5468", "AS - 5440", "AS - 5422", "AS - 5540", "AS - 5408", "AS - 5622", "AS - 5661", "AS - 5383", "AS - 5586", "AS - 5429", "AS - 5417", "AS - 5453", "AS - 5562", "AS - 5358", "AS - 5560", "AS - 5569", "AS - 5401", "AS - 5369", "AS - 5315", "AS - 5568", "AS - 5341", "AS - 5479", "AS - 5658", "AS - 5309", "AS - 5434", "AS - 5318", "AS - 5321", "AS - 5310", "AS - 5311", "AS - 5302", "AS - 5278", "AS - 5280", "AS - 6183", "AS - 5357", "AS - 5229", "AS - 5202", "AS - 5204", "AS - 5203", "AS - 5200", "AS - 5195", "AS - 5210", "AS - 5397", "AS - 5409", "AS - 5223", "AS - 5274", "AS - 5174", "AS - 5299", "AS - 5153", "AS - 5269", "AS - 5213", "AS - 5201", "AS - 5137", "AS - 5136", "AS - 5219", "AS - 5275", "AS - 5129", "AS - 5108", "AS - 5154", "AS - 5156", "AS - 5122", "AS - 5138", "AS - 5132", "AS - 5080", "AS - 5110", "AS - 5598", "AS - 5116", "AS - 5016", "AS - 5012", "AS - 5014", "AS - 5024", "AS - 5099", "AS - 5061", "AS - 5962", "AS - 5060", "AS - 5177", "AS - 4976", "AS - 5068", "AS - 4978", "AS - 5036", "AS - 5563", "AS - 5011", "AS - 5450", "AS - 5073", "AS - 4920", "AS - 5055", "AS - 5070", "AS - 5020", "AS - 5008", "AS - 4882", "AS - 4881", "AS - 4880", "AS - 4879", "AS - 5699", "AS - 4871", "AS - 4902", "AS - 6033", "AS - 5077", "AS - 5792", "AS - 5697", "AS - 4838", "AS - 4878", "AS - 5512", "AS - 5749", "AS - 4864", "AS - 4839", "AS - 5973", "AS - 4792", "AS - 4894", "AS - 4857", "AS - 4810", "AS - 4824", "AS - 5231", "AS - 4822", "AS - 4781", "AS - 4816", "AS - 4761", "AS - 4777", "AS - 4760", "AS - 4758", "AS - 4790", "AS - 5041", "AS - 4778", "AS - 4711", "AS - 4756", "AS - 4783", "AS - 4938", "AS - 4634", "AS - 4748", "AS - 4659", "AS - 4650", "AS - 5366", "AS - 4696", "AS - 4730", "AS - 4621", "AS - 5249", "AS - 4678", "AS - 5312", "AS - 4660", "AS - 4677", "AS - 4729", "AS - 4856", "AS - 4752", "AS - 4563", "AS - 4545", "AS - 4535", "AS - 4570", "AS - 4577", "AS - 4541", "AS - 4522", "AS - 4693", "AS - 4732", "AS - 4890", "AS - 4544", "AS - 4503", "AS - 4504", "AS - 4493", "AS - 5013", "AS - 4514", "AS - 4903", "AS - 4494", "AS - 4576", "AS - 4685", "AS - 4498", "AS - 4589", "AS - 4465", "AS - 4385", "AS - 4492", "AS - 4413", "AS - 4382", "AS - 4395", "AS - 4422", "AS - 4263", "AS - 4560", "AS - 4278", "AS - 4529", "AS - 5564", "AS - 4473", "AS - 5042", "AS - 4262", "AS - 4446", "AS - 4228", "AS - 4251", "AS - 4237", "AS - 4246", "AS - 4291", "AS - 4751", "AS - 4909", "AS - 4571", "AS - 4294", "AS - 4174", "AS - 4513", "AS - 4626", "AS - 4363", "AS - 4362", "AS - 4323", "AS - 4159", "AS - 4332", "AS - 5152", "AS - 4316", "AS - 4343", "AS - 4230", "AS - 5601", "AS - 4095", "AS - 4094", "AS - 4091", "AS - 4098", "AS - 4186", "AS - 4356", "AS - 4837", "AS - 4070", "AS - 4311", "AS - 4309", "AS - 4066", "AS - 4085", "AS - 4061", "AS - 4038", "AS - 4049", "AS - 6262", "AS - 4031", "AS - 4080", "AS - 4055", "AS - 4184", "AS - 4069", "AS - 4113", "AS - 4041", "AS - 4097", "AS - 4122", "AS - 3987", "AS - 4342", "AS - 4361", "AS - 5131", "AS - 4074", "AS - 3978", "AS - 3999", "AS - 3911", "AS - 4357", "AS - 4004", "AS - 4060", "AS - 3879", "AS - 4261", "AS - 3874", "AS - 5599", "AS - 4089", "AS - 3851", "AS - 4312", "AS - 4048", "AS - 4572", "AS - 3927", "AS - 3938", "AS - 3769", "AS - 4279", "AS - 3889", "AS - 4054", "AS - 3925", "AS - 3734", "AS - 3759", "AS - 3744", "AS - 6019", "AS - 3739", "AS - 3699", "AS - 3626", "AS - 6114", "AS - 3692", "AS - 3832", "AS - 3724", "AS - 3698", "AS - 3654", "AS - 3689", "AS - 3623", "AS - 3591", "AS - 3644", "AS - 3592", "AS - 3613", "AS - 3607", "AS - 3831", "AS - 3826", "AS - 3787", "AS - 3638", "AS - 3598", "AS - 3581", "AS - 3536", "AS - 3534", "AS - 3970", "AS - 3653", "AS - 3950", "AS - 3671", "AS - 3605", "AS - 3604", "AS - 4968", "AS - 3537", "AS - 3502", "AS - 3503", "AS - 3586", "AS - 3584", "AS - 3489", "AS - 3508", "AS - 3551", "AS - 3540", "AS - 3676", "AS - 4762", "AS - 3494", "AS - 3995", "AS - 3667", "AS - 3451", "AS - 3575", "AS - 4152", "AS - 3480", "AS - 4916", "AS - 3405", "AS - 3567", "AS - 3398", "AS - 3402", "AS - 3531", "AS - 4471", "AS - 3464", "AS - 3903", "AS - 3585", "AS - 3516", "AS - 3541", "AS - 3331", "AS - 3391", "AS - 3507", "AS - 3378", "AS - 3362", "AS - 3325", "AS - 3411", "AS - 3563", "AS - 3360", "AS - 3353", "AS - 3245", "AS - 3257", "AS - 3407", "AS - 3277", "AS - 3219", "AS - 5727", "AS - 3152", "AS - 3151", "AS - 4409", "AS - 3116", "AS - 3315", "AS - 3574", "AS - 3155", "AS - 4283", "AS - 3318", "AS - 4110", "AS - 3197", "AS - 3130", "AS - 3303", "AS - 3082", "AS - 3252", "AS - 3156", "AS - 3454", "AS - 3072", "AS - 3207", "AS - 3481", "AS - 3147", "AS - 3183", "AS - 3027", "AS - 4383", "AS - 3311", "AS - 3333", "AS - 3108", "AS - 3107", "AS - 3500", "AS - 2995", "AS - 2997", "AS - 2996", "AS - 2993", "AS - 2994", "AS - 3118", "AS - 2953", "AS - 2978", "AS - 2979", "AS - 2936", "AS - 2912", "AS - 2974", "AS - 2893", "AS - 2939", "AS - 2888", "AS - 2924", "AS - 2868", "AS - 2798", "AS - 2825", "AS - 3091", "AS - 5139", "AS - 2805", "AS - 2802", "AS - 2747", "AS - 2750", "AS - 2745", "AS - 2721", "AS - 2787", "AS - 2734", "AS - 2890", "AS - 2735", "AS - 2783", "AS - 2785", "AS - 2689", "AS - 2742", "AS - 2649", "AS - 3498", "AS - 2665", "AS - 3035", "AS - 2659", "AS - 2658", "AS - 5631", "AS - 2835", "AS - 2640", "AS - 2632", "AS - 2592", "AS - 5382", "AS - 2616", "AS - 4555", "AS - 2587", "AS - 3334", "AS - 2536", "AS - 2547", "AS - 2591", "AS - 3014", "AS - 3226", "AS - 2743", "AS - 4116", "AS - 3140", "AS - 2496", "AS - 2560", "AS - 3113", "AS - 2475", "AS - 2772", "AS - 2415", "AS - 2540", "AS - 2394", "AS - 2410", "AS - 2423", "AS - 2340", "AS - 2364", "AS - 2341", "AS - 2347", "AS - 2614", "AS - 2268", "AS - 2354", "AS - 2317", "AS - 2232", "AS - 3099", "AS - 2331", "AS - 2247", "AS - 2228", "AS - 2286", "AS - 2259", "AS - 2274", "AS - 2203", "AS - 4599", "AS - 2222", "AS - 2349", "AS - 2193", "AS - 2148", "AS - 2144", "AS - 2251", "AS - 2231", "AS - 2137", "AS - 2166", "AS - 2143", "AS - 2160", "AS - 2119", "AS - 2134", "AS - 2128", "AS - 2216", "AS - 2099", "AS - 2102", "AS - 2687", "AS - 2076", "AS - 2081", "AS - 5081", "AS - 2035", "AS - 2038", "AS - 3522", "AS - 2024", "AS - 5082", "AS - 2046", "AS - 2057", "AS - 2004", "AS - 2047", "AS - 3258", "AS - 2114", "AS - 2025", "AS - 1957", "AS - 1935", "AS - 1940", "AS - 2537", "AS - 1919", "AS - 1937", "AS - 1987", "AS - 1923", "AS - 3088", "AS - 2233", "AS - 1872", "AS - 1898", "AS - 1865", "AS - 1904", "AS - 1838", "AS - 1825", "AS - 1909", "AS - 1832", "AS - 5567", "AS - 1821", "AS - 1817", "AS - 1809", "AS - 1816", "AS - 5271", "AS - 1803", "AS - 1804", "AS - 1805", "AS - 1806", "AS - 1781", "AS - 1772", "AS - 1767", "AS - 1770", "AS - 1746", "AS - 1741", "AS - 1765", "AS - 1700", "AS - 1735", "AS - 1697", "AS - 2332", "AS - 1724", "AS - 1657", "AS - 1656", "AS - 1663", "AS - 1879", "AS - 1579", "AS - 1564", "AS - 1557", "AS - 1552", "AS - 1630", "AS - 1539", "AS - 1684", "AS - 1591", "AS - 1507", "AS - 1459", "AS - 1458", "AS - 2483", "AS - 1623", "AS - 1463", "AS - 1561", "AS - 358", "AS - 1671", "AS - 392", "AS - 416", "AS - 4578", "AS - 386", "AS - 2989", "AS - 5142", "AS - 2297", "AS - 330", "AS - 258", "AS - 393", "AS - 492", "AS - 259", "AS - 460", "AS - 1515", "AS - 281", "AS - 318", "AS - 250", "AS - 263", "AS - 279", "AS - 350", "AS - 341", "AS - 464", "AS - 234", "AS - 213", "AS - 200", "AS - 231", "AS - 1622", "AS - 173", "AS - 3141", "AS - 4601", "AS - 245", "AS - 329", "AS - 138", "AS - 088", "AS - 133", "AS - 101", "AS - 480", "AS - 153", "AS - 1936", "AS - 071", "AS - 4364", "AS - 1441", "AS - 028", "AS - 1807", "AS - 4457", "AS - 030", "AS - 034", "AS - 004", "AS - 085", "AS - 166", "AS - 049", "AS - 696", "AS - 631", "AS - 715", "AS - 671", "AS - 703", "AS - 598", "AS - 741", "AS - 730", "AS - 551", "AS - 579", "AS - 643", "AS - 766", "AS - 5413", "AS - 549", "AS - 1979", "AS - 869", "AS - 832", "AS - 594", "AS - 1875", "AS - 890", "AS - 954", "AS - 527", "AS - 1140", "AS - 1055", "AS - 1030", "AS - 1292", "AS - 513", "AS - 1022", "AS - 3299", "AS - 1101", "AS - 531", "AS - 1409", "AS - 5730", "AS - 1183", "AS - 1260", "AS - 5653", "AS - 948", "AS - 5022"];

// Shared audit logic used by both the POST (custom list) and GET (embedded
// ground-truth list) routes below. Read-only; never returns credentials.
async function computeScopeAudit(recordNumbers) {
  const wanted = new Set(recordNumbers.map(String));

  const aditPay = await resolveAditPayModule();
  if (!aditPay.found || !aditPay.lookupApiName) {
    throw new Error("Could not resolve the Adit Pay module.");
  }

  const dealIdByRecordNumber = {};
  {
    const fields = encodeURIComponent(["Name", aditPay.lookupApiName].join(","));
    let pageToken = null;
    for (let i = 0; i < 100; i++) {
      let url = "/crm/v8/" + encodeURIComponent(aditPay.apiName) + "?fields=" + fields + "&per_page=200";
      if (pageToken) url += "&page_token=" + encodeURIComponent(pageToken);
      const data = await zohoApiGet(url);
      const records = data.data || [];
      records.forEach(function (rec) {
        const name = rec.Name;
        if (name != null && wanted.has(String(name))) {
          const lookupVal = rec[aditPay.lookupApiName];
          const dealId = lookupVal && typeof lookupVal === "object" ? lookupVal.id : lookupVal;
          if (dealId) dealIdByRecordNumber[String(name)] = dealId;
        }
      });
      const more = data.info && data.info.more_records;
      pageToken = data.info && data.info.next_page_token;
      if (!more || !pageToken) break;
    }
  }

  const scopeByDealId = {};
  {
    const neededIds = new Set(Object.values(dealIdByRecordNumber));
    const fields = encodeURIComponent(["id"].concat(Object.values(SCOPE_FILTER_FIELDS)).join(","));
    let pageToken = null;
    for (let i = 0; i < 100; i++) {
      let url = "/crm/v8/Deals?fields=" + fields + "&per_page=200";
      if (pageToken) url += "&page_token=" + encodeURIComponent(pageToken);
      const data = await zohoApiGet(url);
      const records = data.data || [];
      records.forEach(function (rec) {
        if (neededIds.has(rec.id)) {
          const f = {};
          Object.keys(SCOPE_FILTER_FIELDS).forEach(function (k) { f[k] = flattenZohoValue(rec[SCOPE_FILTER_FIELDS[k]]); });
          scopeByDealId[rec.id] = f;
        }
      });
      const more = data.info && data.info.more_records;
      pageToken = data.info && data.info.next_page_token;
      if (!more || !pageToken) break;
    }
  }

  const now = new Date();
  const results = [];
  let matched = 0, rejected = 0, noDealFound = 0;
  recordNumbers.forEach(function (rn) {
    const dealId = dealIdByRecordNumber[String(rn)];
    if (!dealId) { noDealFound++; results.push({ recordNumber: rn, error: "no matching Deal found via Adit Pay lookup" }); return; }
    const f = scopeByDealId[dealId];
    if (!f) { noDealFound++; results.push({ recordNumber: rn, dealId: dealId, error: "deal id not found in Deals fetch" }); return; }
    const passes = dealMatchesTerminalPurchaseScope(f, now);
    if (passes) { matched++; return; }
    rejected++;
    const cond1 = f.terminalsSelected === "Yes";
    const cond2 = !(f.dealName && String(f.dealName).toLowerCase().indexOf("test") !== -1);
    const cond3 = SCOPE_STAGE_ALLOWLIST.indexOf(f.stage) !== -1;
    let cond4 = false, cond5 = false;
    if (f.agreementSignedDate) {
      const d = new Date(f.agreementSignedDate);
      if (!isNaN(d.getTime())) {
        const cutoff = new Date(now);
        cutoff.setUTCMonth(cutoff.getUTCMonth() - 108);
        cond4 = d >= cutoff && d <= now;
        cond5 = d.getUTCFullYear() === now.getUTCFullYear() && d.getUTCMonth() === now.getUTCMonth();
      }
    }
    const cond6 = f.terminalCount != null && Number(f.terminalCount) >= 1;
    const cond7 = f.stage !== "Closed Lost";
    results.push({
      recordNumber: rn, dealId: dealId, raw: f,
      conditions: { cond1_terminalsSelectedYes: cond1, cond2_nameNoTest: cond2, cond3_stageAllowed: cond3, cond4_within108mo: cond4, cond5_currentMonth: cond5, cond6_terminalCountGte1: cond6, cond7_notClosedLost: cond7 },
    });
  });

  return {
    totalRequested: recordNumbers.length,
    matched: matched,
    rejected: rejected,
    noDealFound: noDealFound,
    rejectedSample: results.filter(function (r) { return r.conditions; }),
    notFoundSample: results.filter(function (r) { return r.error; }).slice(0, 10),
  };
}

app.post("/api/zoho/scope-audit", requireAuth, async (req, res) => {
  try {
    const recordNumbers = (req.body && req.body.recordNumbers) || [];
    if (!Array.isArray(recordNumbers) || !recordNumbers.length) {
      return res.status(400).json({ error: "Expected a non-empty 'recordNumbers' array." });
    }
    const result = await computeScopeAudit(recordNumbers);
    res.json(result);
  } catch (err) {
    console.error("[zoho] scope-audit failed:", err.message);
    res.status(502).json({ error: "Unable to authenticate with Zoho CRM. Please check the Zoho environment variables." });
  }
});

// GET convenience version of the same audit using the embedded ground-truth Record
// Numbers above, so it can be run by simply visiting this URL in a signed-in browser
// tab (no console or JS paste required). Read-only; never returns credentials.
app.get("/api/zoho/scope-audit-run", requireAuth, async (req, res) => {
  try {
    const result = await computeScopeAudit(DEFAULT_AUDIT_RECORD_NUMBERS);
    res.json(result);
  } catch (err) {
    console.error("[zoho] scope-audit-run failed:", err.message);
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

# Adit Pay Terminal Adoption Analyzer

Internal analytics tool for Adit. Upload a raw Adit Pay terminal/deal export
(`.xlsx`, `.xls`, or `.csv`) and instantly get a validated executive summary:
adoption KPIs, volume-tier breakdowns, an opportunity analysis, charts, and a
searchable deal-level drilldown.

**Everything runs client-side, in the visitor's browser.** The uploaded file
is parsed and processed entirely in JavaScript — nothing is sent to a
server or stored anywhere. That means this app has no database, no API
keys, and nothing to configure: the Node/Express server here does one job,
serving the static page.

## Deploy to Railway

You have two options. Either works — pick whichever is easier for you.

### Option A — Railway CLI (fastest, no GitHub required)

1. Install the CLI (needs Node.js installed locally):
   ```
   npm install -g @railway/cli
   ```
2. From inside this folder, log in and deploy:
   ```
   railway login
   railway init
   railway up
   ```
3. Once it finishes deploying, run `railway domain` to generate a public
   URL (or add one from the Railway dashboard under Settings → Networking).

### Option B — Deploy from GitHub

1. Push this folder to a new GitHub repository:
   ```
   git init
   git add .
   git commit -m "Initial commit: Adit Pay Adoption Analyzer"
   git branch -M main
   git remote add origin <your-new-repo-url>
   git push -u origin main
   ```
2. In the [Railway dashboard](https://railway.app), click **New Project** →
   **Deploy from GitHub repo**, and select this repository.
3. Railway auto-detects the Node app (via `package.json`) and deploys it.
   No environment variables or build configuration are needed.
4. Under **Settings → Networking**, click **Generate Domain** to get a
   public URL.

Railway sets the `PORT` environment variable automatically; `server.js`
already reads it, so no extra configuration is required either way.

## Running locally

```
npm install
npm start
```

Then open `http://localhost:3000`.

## Project structure

```
├── public/
│   └── index.html      # the entire application (single page, no build step)
├── server.js            # static file server (Express)
├── package.json
├── Procfile              # alternate start-command declaration (some hosts use this instead of railway.json)
└── railway.json          # Railway-specific build/deploy config
```

## Updating the app later

The whole application lives in `public/index.html` — it's a single
self-contained file (HTML, CSS, and JavaScript). To make changes, edit that
file directly and redeploy (`railway up`, or push to GitHub if using
Option B). There's no build/compile step.

## Notes

- The three charting/parsing libraries (SheetJS, Chart.js, jsPDF) load from
  cdnjs.cloudflare.com at runtime, so the deployed site needs outbound
  access to that domain in visitors' browsers (this is normal and requires
  no server-side configuration).
- Exports (Excel/CSV/PDF) use the browser's native file-download flow once
  deployed here — no server round-trip involved.

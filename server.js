// Minimal static file server for the Adit Pay Terminal Adoption Analyzer.
// Everything the app does (parsing, validation, calculations, export) runs
// client-side in the visitor's browser — this server only serves the static
// page, so it has no database, no API keys, and nothing to configure.
const express = require("express");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.static(path.join(__dirname, "public"), { extensions: ["html"] }));

// Single-page app: any unmatched route falls back to index.html.
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT, () => {
  console.log(`Adit Pay Adoption Analyzer listening on port ${PORT}`);
});

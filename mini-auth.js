import express from "express";
import fetch from "node-fetch";

const app = express();
app.use(express.json());

const GOOGLE_CLIENT_ID     = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const GOOGLE_REDIRECT_URI  = process.env.GOOGLE_REDIRECT_URI;

let REFRESH_TOKEN = null;

app.post("/oauth2/callback", async (req, res) => {
  const { code } = req.body;
  if (!code) return res.status(400).json({ error: "Missing code" });

  try {
    const resp = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        code,
        client_id: GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        redirect_uri: GOOGLE_REDIRECT_URI,
        grant_type: "authorization_code"
      })
    });
    const data = await resp.json();
    if (data.error) return res.status(400).json(data);

    if (data.refresh_token) REFRESH_TOKEN = data.refresh_token;
    res.json({
      access_token: data.access_token,
      expires_in: data.expires_in,
      has_refresh: !!REFRESH_TOKEN
    });
  } catch (err) {
    res.status(500).json({ error: "Exchange failed", detail: err.message });
  }
});

app.post("/oauth2/refresh", async (req, res) => {
  if (!REFRESH_TOKEN) return res.status(400).json({ error: "No refresh token yet" });

  try {
    const resp = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        refresh_token: REFRESH_TOKEN,
        grant_type: "refresh_token"
      })
    });
    const data = await resp.json();
    if (data.error) return res.status(400).json(data);
    res.json({ access_token: data.access_token, expires_in: data.expires_in });
  } catch (err) {
    res.status(500).json({ error: "Refresh failed", detail: err.message });
  }
});

app.get("/", (_, res) => res.send("Mini API attiva e respirante."));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Mini-API pronta su ${PORT}`));

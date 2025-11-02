// mini-auth.js — micro server per rinnovo token Google (per-utente)
import express from "express";
import fetch from "node-fetch";

// ======================
// FIREBASE ADMIN / FIRESTORE
// ======================
import { initializeApp, cert } from "firebase-admin/app";
import { getFirestore } from "firebase-admin/firestore";

// leggiamo le credenziali dal env di Render
const creds = JSON.parse(process.env.GOOGLE_APPLICATION_CREDENTIALS_JSON);
initializeApp({ credential: cert(creds) });
const db = getFirestore();

// ======================
// EXPRESS
// ======================
const app = express();
app.use(express.json());

// CORS base per il tuo sito/pwa
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }
  next();
});

// ======================
// CONFIGURAZIONE BASE
// ======================
const GOOGLE_CLIENT_ID     = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const GOOGLE_REDIRECT_URI  = process.env.GOOGLE_REDIRECT_URI;

// collezione dove salviamo i refresh PER UTENTE
const FS_COLLECTION = "auth";

// ======================
// FUNZIONI DI SUPPORTO
// ======================
function normalizeEmail(raw) {
  if (!raw) return null;
  try {
    return decodeURIComponent(raw).trim().toLowerCase();
  } catch {
    return raw.trim().toLowerCase();
  }
}

async function saveRefreshToFirestore(email, refreshToken) {
  await db.collection(FS_COLLECTION).doc(email).set({
    refresh_token: refreshToken,
    updated_at: new Date().toISOString()
  });
}

async function loadRefreshFromFirestore(email) {
  const snap = await db.collection(FS_COLLECTION).doc(email).get();
  if (!snap.exists) return null;
  const data = snap.data();
  return data.refresh_token || null;
}

// ======================
// ENDPOINT BASE
// ======================
app.get("/", (_, res) => {
  res.send("Mini API attiva e respirante (per-utente).");
});

// ======================
// CALLBACK OAUTH (GET + POST)
// ======================
async function handleOAuthCallback(req, res) {
  // Google può arrivare in GET (dal browser) o in POST (se la chiami tu)
  const isGet = req.method === "GET";

  const code  = isGet ? req.query.code  : req.body.code;
  let   state = isGet ? req.query.state : req.body.state;

  if (!code) {
    return res.status(400).json({ error: "Missing code" });
  }

  // nello state ci mettiamo l'email dell'utente
  const email = normalizeEmail(state);
  if (!email) {
    return res.status(400).json({ error: "Missing email in state" });
  }

  try {
    // scambio code -> token
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

    if (data.error) {
      return res.status(400).json(data);
    }

    // se Google ci dà un refresh_token LO SALVIAMO sotto l'email
    if (data.refresh_token) {
      await saveRefreshToFirestore(email, data.refresh_token);
    } else {
      // se non lo dà, ma ne abbiamo già uno vecchio, lo riusiamo
      const old = await loadRefreshFromFirestore(email);
      if (old) {
        data.has_refresh = true;
      }
    }

    return res.json({
      access_token: data.access_token,
      expires_in: data.expires_in,
      email,
      has_refresh: !!(data.refresh_token)
    });
  } catch (err) {
    console.error("Exchange failed:", err);
    return res.status(500).json({ error: "Exchange failed", detail: err.message });
  }
}

// qui la agganciamo in ENTRAMBI i modi
app.get("/oauth2/callback", handleOAuthCallback);
app.post("/oauth2/callback", handleOAuthCallback);

// ======================
// REFRESH PER-UTENTE
// ======================
app.post("/oauth2/refresh", async (req, res) => {
  // l'email può arrivare come ?email=... oppure nel body
  let email = req.query.email || req.body.email;
  email = normalizeEmail(email);

  if (!email) {
    return res.status(400).json({ error: "Missing email" });
  }

  try {
    const refreshToken = await loadRefreshFromFirestore(email);
    if (!refreshToken) {
      return res.status(400).json({ error: "No refresh token stored for this user" });
    }

    const resp = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        refresh_token: refreshToken,
        grant_type: "refresh_token"
      })
    });

    const data = await resp.json();

    if (data.error) {
      return res.status(400).json(data);
    }

    // se mai Google ridà un altro refresh, lo aggiorniamo
    if (data.refresh_token) {
      await saveRefreshToFirestore(email, data.refresh_token);
    }

    return res.json({
      access_token: data.access_token,
      expires_in: data.expires_in,
      email
    });
  } catch (err) {
    console.error("Refresh failed:", err);
    return res.status(500).json({ error: "Refresh failed", detail: err.message });
  }
});

// avvio server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Mini-API pronta su ${PORT}`));

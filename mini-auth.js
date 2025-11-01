// mini-auth.js — micro server per rinnovo token Google + Firestore
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
// CONFIGURAZIONE BASE
// ======================
const GOOGLE_CLIENT_ID     = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const GOOGLE_REDIRECT_URI  = process.env.GOOGLE_REDIRECT_URI;

const FS_COLLECTION = "auth";
const FS_DOC        = "google";

// ======================
// EXPRESS
// ======================
const app = express();
app.use(express.json());

// CORS base per le chiamate dal browser
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }
  next();
});

// ======================
// FUNZIONI DI SUPPORTO
// ======================
async function saveRefreshToFirestore(refreshToken) {
  await db.collection(FS_COLLECTION).doc(FS_DOC).set({
    refresh_token: refreshToken,
    updated_at: new Date().toISOString()
  });
}

async function loadRefreshFromFirestore() {
  const snap = await db.collection(FS_COLLECTION).doc(FS_DOC).get();
  if (!snap.exists) return null;
  const data = snap.data();
  return data.refresh_token || null;
}

// in RAM
let REFRESH_TOKEN = null;

// ======================
// ENDPOINTS
// ======================

// test rapido base
app.get("/", (_, res) => {
  res.send("Mini API attiva e respirante.");
});

// test Firestore
app.get("/firestore-test", async (_, res) => {
  try {
    const ref = db.collection("auth").doc("test");
    await ref.set({ ok: true, time: new Date().toISOString() });
    const snap = await ref.get();
    res.json({ success: true, data: snap.data() });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ======================
// CALLBACK DA GOOGLE (GET)
// Google ti rimanda QUI con ?code=...
// ======================
app.get("/oauth2/callback", async (req, res) => {
  const { code } = req.query;
  if (!code) {
    return res.status(400).json({ error: "Missing code in query" });
  }

  try {
    const googleResp = await fetch("https://oauth2.googleapis.com/token", {
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

    const data = await googleResp.json();
    if (data.error) {
      return res.status(400).json(data);
    }

    // se Google ci dà il refresh, salviamo
    if (data.refresh_token) {
      REFRESH_TOKEN = data.refresh_token;
      try {
        await saveRefreshToFirestore(data.refresh_token);
      } catch (err) {
        console.error("Errore salvataggio refresh su Firestore:", err.message);
      }
    } else {
      // se non lo dà, proviamo a ricaricarlo da Firestore
      const fromFs = await loadRefreshFromFirestore();
      if (fromFs) {
        REFRESH_TOKEN = fromFs;
      }
    }

    return res.json({
      access_token: data.access_token,
      expires_in: data.expires_in,
      has_refresh: !!(data.refresh_token || REFRESH_TOKEN)
    });
  } catch (err) {
    console.error("Exchange via GET failed:", err);
    return res.status(500).json({ error: "Exchange failed", detail: err.message });
  }
});

// ======================
// CALLBACK DA GOOGLE (POST)
// (se mai la useremo dal frontend)
// ======================
app.post("/oauth2/callback", async (req, res) => {
  const { code } = req.body;
  if (!code) return res.status(400).json({ error: "Missing code" });

  try {
    const googleResp = await fetch("https://oauth2.googleapis.com/token", {
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

    const data = await googleResp.json();
    if (data.error) {
      return res.status(400).json(data);
    }

    if (data.refresh_token) {
      REFRESH_TOKEN = data.refresh_token;
      try {
        await saveRefreshToFirestore(data.refresh_token);
      } catch (err) {
        console.error("Errore salvataggio refresh su Firestore:", err.message);
      }
    } else {
      const fromFs = await loadRefreshFromFirestore();
      if (fromFs) {
        REFRESH_TOKEN = fromFs;
      }
    }

    return res.json({
      access_token: data.access_token,
      expires_in: data.expires_in,
      has_refresh: !!(data.refresh_token || REFRESH_TOKEN)
    });
  } catch (err) {
    console.error("Exchange via POST failed:", err);
    return res.status(500).json({ error: "Exchange failed", detail: err.message });
  }
});

// ======================
// REFRESH TOKEN (GET/POST)
// ======================
async function doRefresh(res) {
  try {
    // 1) RAM
    let refresh = REFRESH_TOKEN;

    // 2) Firestore
    if (!refresh) {
      refresh = await loadRefreshFromFirestore();
      if (refresh) {
        REFRESH_TOKEN = refresh;
      }
    }

    if (!refresh) {
      return res.status(400).json({ error: "No refresh token yet" });
    }

    const googleResp = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        refresh_token: refresh,
        grant_type: "refresh_token"
      })
    });

    const data = await googleResp.json();
    if (data.error) {
      return res.status(400).json(data);
    }

    // raro, ma se Google ti dà di nuovo un refresh
    if (data.refresh_token) {
      REFRESH_TOKEN = data.refresh_token;
      try {
        await saveRefreshToFirestore(data.refresh_token);
      } catch (err) {
        console.error("Errore aggiornamento refresh su Firestore:", err.message);
      }
    }

    return res.json({
      access_token: data.access_token,
      expires_in: data.expires_in
    });
  } catch (err) {
    console.error("Refresh failed:", err);
    return res.status(500).json({ error: "Refresh failed", detail: err.message });
  }
}

app.get("/oauth2/refresh", async (req, res) => {
  return doRefresh(res);
});

app.post("/oauth2/refresh", async (req, res) => {
  return doRefresh(res);
});

// avvio server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Mini-API pronta su ${PORT}`));

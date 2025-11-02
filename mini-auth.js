// mini-auth.js — micro server per rinnovo token Google (VERSIONE PER-UTENTE)
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

// CORS apertissimo per la tua PWA
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

// RAM di cortesia: mappa email -> refresh
const RAM_REFRESH = new Map();

// nome collection che useremo in Firestore
const FS_COLLECTION = "auth";

// ======================
// FUNZIONI DI SUPPORTO
// ======================

// salva il refresh token per UNA specifica email
async function saveRefreshForUser(email, refreshToken) {
  await db.collection(FS_COLLECTION).doc(email).set({
    refresh_token: refreshToken,
    updated_at: new Date().toISOString()
  });
  RAM_REFRESH.set(email, refreshToken);
}

// legge il refresh token per UNA specifica email
async function loadRefreshForUser(email) {
  // prima provo RAM
  if (RAM_REFRESH.has(email)) {
    return RAM_REFRESH.get(email);
  }
  // poi Firestore
  const snap = await db.collection(FS_COLLECTION).doc(email).get();
  if (!snap.exists) return null;
  const data = snap.data();
  const rt = data.refresh_token || null;
  if (rt) {
    RAM_REFRESH.set(email, rt);
  }
  return rt;
}

// prova a ricavare la mail usando l'access_token
async function fetchUserEmail(accessToken) {
  const resp = await fetch("https://openidconnect.googleapis.com/v1/userinfo", {
    headers: {
      "Authorization": `Bearer ${accessToken}`
    }
  });
  if (!resp.ok) {
    throw new Error("Impossibile leggere userinfo");
  }
  const data = await resp.json();
  return data.email || null;
}

// ======================
// ENDPOINTS
// ======================

// test rapido base
app.get("/", (_, res) => {
  res.send("Mini API attiva e respirante (per-utente).");
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

// Riceve il code da OAuth e lo scambia per token + refresh
// e ***LO COLLEGA ALLA MAIL*** di chi ha fatto login
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
    if (data.error) {
      return res.status(400).json(data);
    }

    const accessToken  = data.access_token;
    const refreshToken = data.refresh_token || null;

    // ricaviamo la mail
    let email = null;
    try {
      email = await fetchUserEmail(accessToken);
    } catch (e) {
      console.error("Errore lettura userinfo:", e.message);
    }

    // se non riesco a capire chi è, non posso salvarlo per-utente
    if (!email) {
      return res.status(400).json({
        error: "no_email",
        error_description: "Non sono riuscito a ricavare l'email dall'access token"
      });
    }

    // se Google ci ha dato un refresh, lo salvo legato a QUELLA mail
    if (refreshToken) {
      try {
        await saveRefreshForUser(email, refreshToken);
      } catch (err) {
        console.error("Errore salvataggio refresh su Firestore:", err.message);
      }
    } else {
      // se NON c'è refresh (utente aveva già dato il consenso in passato),
      // provo a caricarne uno già esistente per lui
      const old = await loadRefreshForUser(email);
      if (old) {
        RAM_REFRESH.set(email, old);
      }
    }

    res.json({
      access_token: accessToken,
      expires_in: data.expires_in,
      email,
      has_refresh: !!(refreshToken || RAM_REFRESH.get(email))
    });
  } catch (err) {
    console.error("Exchange failed:", err);
    res.status(500).json({ error: "Exchange failed", detail: err.message });
  }
});

// Rinnova il token usando il refresh salvato PER QUELLA MAIL
app.post("/oauth2/refresh", async (req, res) => {
  try {
    const email = req.body?.email || req.query?.email;
    if (!email) {
      return res.status(400).json({ error: "missing_email" });
    }

    // cerco un refresh per quella mail
    let refresh = await loadRefreshForUser(email);
    if (!refresh) {
      return res.status(404).json({ error: "no_refresh_for_user", email });
    }

    const resp = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        refresh_token: refresh,
        grant_type: "refresh_token"
      })
    });

    const data = await resp.json();
    if (data.error) {
      return res.status(400).json(data);
    }

    // se Google ci dà un refresh nuovo, aggiorniamo (succede raramente)
    if (data.refresh_token) {
      await saveRefreshForUser(email, data.refresh_token);
    }

    res.json({
      access_token: data.access_token,
      expires_in: data.expires_in,
      email
    });
  } catch (err) {
    console.error("Refresh failed:", err);
    res.status(500).json({ error: "Refresh failed", detail: err.message });
  }
});

// avvio server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Mini-API pronta su ${PORT}`));

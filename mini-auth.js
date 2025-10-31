// mini-auth.js — micro server per rinnovo token Google
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

// ======================
// CONFIGURAZIONE BASE
// ======================
const GOOGLE_CLIENT_ID     = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const GOOGLE_REDIRECT_URI  = process.env.GOOGLE_REDIRECT_URI;

// in RAM (veloce) — ma adesso abbiamo anche Firestore
let REFRESH_TOKEN = null;

// nome/coll/doc che useremo in Firestore
const FS_COLLECTION = "auth";
const FS_DOC        = "google";

// ======================
// FUNZIONI DI SUPPORTO
// ======================

// salva il refresh token su Firestore
async function saveRefreshToFirestore(refreshToken) {
  await db.collection(FS_COLLECTION).doc(FS_DOC).set({
    refresh_token: refreshToken,
    updated_at: new Date().toISOString()
  });
}

// legge il refresh token da Firestore
async function loadRefreshFromFirestore() {
  const snap = await db.collection(FS_COLLECTION).doc(FS_DOC).get();
  if (!snap.exists) return null;
  const data = snap.data();
  return data.refresh_token || null;
}

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

// Riceve il code da OAuth e scambia per token + refresh
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

    // se Google ci ha dato il refresh, lo teniamo sia in RAM che in Firestore
    if (data.refresh_token) {
      REFRESH_TOKEN = data.refresh_token;
      try {
        await saveRefreshToFirestore(data.refresh_token);
      } catch (err) {
        // non blocchiamo la risposta al client se il salvataggio fallisce
        console.error("Errore salvataggio refresh su Firestore:", err.message);
      }
    } else {
      // se non dà il refresh, proviamo a caricarne uno da Firestore (magari già c'è)
      const fromFs = await loadRefreshFromFirestore();
      if (fromFs) {
        REFRESH_TOKEN = fromFs;
      }
    }

    res.json({
      access_token: data.access_token,
      expires_in: data.expires_in,
      has_refresh: !!(data.refresh_token || REFRESH_TOKEN)
    });
  } catch (err) {
    console.error("Exchange failed:", err);
    res.status(500).json({ error: "Exchange failed", detail: err.message });
  }
});

// Rinnova il token usando il refresh salvato
app.post("/oauth2/refresh", async (req, res) => {
  try {
    // 1) prima proviamo RAM
    let refresh = REFRESH_TOKEN;

    // 2) se non c'è in RAM, proviamo Firestore
    if (!refresh) {
      refresh = await loadRefreshFromFirestore();
      if (refresh) {
        REFRESH_TOKEN = refresh; // ricarichiamo in RAM per le prossime volte
      }
    }

    if (!refresh) {
      return res.status(400).json({ error: "No refresh token yet" });
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

    // se Google ci restituisce di nuovo un refresh (raro ma possibile), lo aggiorniamo
    if (data.refresh_token) {
      REFRESH_TOKEN = data.refresh_token;
      try {
        await saveRefreshToFirestore(data.refresh_token);
      } catch (err) {
        console.error("Errore aggiornamento refresh su Firestore:", err.message);
      }
    }

    res.json({
      access_token: data.access_token,
      expires_in: data.expires_in
    });
  } catch (err) {
    console.error("Refresh failed:", err);
    res.status(500).json({ error: "Refresh failed", detail: err.message });
  }
});

// avvio server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Mini-API pronta su ${PORT}`));



import express from 'express';
import { createServer as createViteServer } from 'vite';
import admin from 'firebase-admin';
import crypto from 'crypto';
import path from 'path';
import cors from 'cors';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Initialize Firebase Admin
// Note: In this environment, Google Application Default Credentials are often auto-configured.
admin.initializeApp({
  projectId: 'gen-lang-client-0500325851'
});

const BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json());
  app.use(cors());

  // Telegram Auth API (Widget or Mini App)
  app.post('/api/auth/telegram', async (req, res) => {
    console.log("Auth request received:", req.body);
    try {
      const { hash, initData, ...data } = req.body;

      if (!BOT_TOKEN) {
        console.error("TELEGRAM_BOT_TOKEN is missing in environment variables!");
        return res.status(500).json({ error: 'TELEGRAM_BOT_TOKEN not configured in environment' });
      }

      let userData: any;

      if (initData) {
        // --- 1. Verify Telegram Mini App initData ---
        const urlParams = new URLSearchParams(initData);
        const receivedHash = urlParams.get('hash');
        urlParams.delete('hash');

        const params = Array.from(urlParams.entries())
          .map(([key, value]) => `${key}=${value}`)
          .sort()
          .join('\n');

        const secretKey = crypto.createHmac('sha256', 'WebAppData').update(BOT_TOKEN).digest();
        const calculatedHash = crypto.createHmac('sha256', secretKey).update(params).digest('hex');

        if (calculatedHash !== receivedHash) {
          return res.status(401).json({ error: 'Invalid initData hash' });
        }

        const userString = urlParams.get('user');
        if (userString) {
          userData = JSON.parse(userString);
          // Standardize fields to match widget format
          userData.id = userData.id;
          userData.username = userData.username;
          userData.first_name = userData.first_name;
          userData.photo_url = userData.photo_url;
        } else {
          return res.status(400).json({ error: 'User data missing in initData' });
        }
      } else {
        // --- 2. Verify Telegram Login Widget hash ---
        const authDataCheckString = Object.keys(data)
          .sort()
          .map(key => `${key}=${data[key]}`)
          .join('\n');

        const secretKey = crypto.createHash('sha256').update(BOT_TOKEN).digest();
        const calculatedHash = crypto.createHmac('sha256', secretKey)
          .update(authDataCheckString)
          .digest('hex');

        if (calculatedHash !== hash) {
          return res.status(401).json({ error: 'Invalid auth hash' });
        }
        userData = data;
      }

      // 3. Create Firebase Custom Token
      const uid = `telegram:${userData.id}`;
      const customToken = await admin.auth().createCustomToken(uid, {
        telegram_id: userData.id,
        username: userData.username,
        first_name: userData.first_name,
        photo_url: userData.photo_url
      });

      // 4. Update user profile in Firebase Auth
      try {
          await admin.auth().updateUser(uid, {
              displayName: userData.username || userData.first_name,
              photoURL: userData.photo_url || ''
          });
      } catch (e) {
          await admin.auth().createUser({
              uid: uid,
              displayName: userData.username || userData.first_name,
              photoURL: userData.photo_url || ''
          });
      }

      res.json({ token: customToken });
    } catch (error) {
      console.error('Auth error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // Vite middleware for development
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();

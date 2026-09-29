import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import { createServer as createViteServer } from 'vite';
import { apiRouter } from './server/routes/api';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function startServer() {
  const app = express();
  const PORT = Number(process.env.PORT || 3000);
  const HOST = process.env.HOST || '0.0.0.0';

  // JSON Body Parser
  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ extended: true }));

  // Request logger (safe, no secret payload logging)
  app.use((req, res, next) => {
    if (req.path.startsWith('/api')) {
      console.log(`[SENTINEL-X API] ${req.method} ${req.path}`);
    }
    next();
  });

  // Mount API routes FIRST
  app.use('/api', apiRouter);

  // Health check endpoint
  app.get('/healthz', (req, res) => {
    res.json({ status: 'ok', service: 'sentinel-x' });
  });

  // Vite middleware in development vs Static files in production
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

  app.listen(PORT, HOST, () => {
    console.log(`🛡️ SENTINEL-X Server active on http://${HOST}:${PORT}`);
    console.log(`[Mode] NODE_ENV=${process.env.NODE_ENV || 'development'}`);
  });
}

startServer().catch((err) => {
  console.error('Fatal server startup failure:', err);
  process.exit(1);
});

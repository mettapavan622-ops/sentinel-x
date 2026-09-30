import express from 'express';
import path from 'path';
import fs from 'fs';
import dotenv from 'dotenv';
import { createServer as createViteServer } from 'vite';
import { apiRouter } from './server/routes/api';

dotenv.config();

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
    const distPath = fs.existsSync(path.join(process.cwd(), 'dist', 'index.html'))
      ? path.join(process.cwd(), 'dist')
      : typeof __dirname !== 'undefined' && fs.existsSync(path.join(__dirname, 'index.html'))
        ? __dirname
        : path.join(process.cwd(), 'dist');

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

/**
 * ============================================================================
 * DIFA — Backend API (Difa by RX Stack)
 * Un seul fichier, Node.js + Express (PAS de NestJS, PAS de découpage modulaire)
 * ============================================================================
 *
 * Modules couverts :
 *  1. Authentification & Sécurité (JWT, OTP SMS, bcrypt, blocage anti brute-force)
 *  2. Gestion des utilisateurs
 *  3. Module Agricole (cultures)
 *  4. Marketplace
 *  5. Certification Qualité
 *  6. Transport & Logistique (+ Socket.io GPS temps réel) — inclut le Module 11
 *  7. Intelligence Artificielle (chatbot Gemini appelé directement en REST,
 *     plus de microservice Python séparé — tout est ici)
 *  8. Statistiques & Analytics
 *  9. Paiement (PayStack + squelette Mobile Money)
 * 10. Notifications (in-app ; push Firebase en option)
 * 12. Administration
 *
 * Base de données : PostgreSQL (ex: Supabase) via DATABASE_URL
 * Cache/OTP       : Redis (ex: Upstash) via REDIS_URL, sinon fallback mémoire
 *
 * Démarrage :
 *   npm install
 *   cp .env.example .env   # renseigne au moins DATABASE_URL et GEMINI_API_KEY
 *   node server.js
 * ============================================================================
 */

'use strict';

require('dotenv').config();

const express = require('express');
const http = require('http');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const { Pool } = require('pg');
const { Server: SocketIOServer } = require('socket.io');

// Client Supabase Storage — utilisé UNIQUEMENT pour stocker les photos
// (produits, cultures). La base de données elle-même reste accédée en SQL
// brut via `pg` comme partout ailleurs dans ce fichier ; ce client ne sert
// qu'à uploader des fichiers dans un bucket Supabase Storage.
let supabaseStorage = null;
if (process.env.SUPABASE_URL && process.env.SUPABASE_SERVICE_ROLE_KEY) {
  const { createClient } = require('@supabase/supabase-js');
  supabaseStorage = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);
}

// Firebase Admin — envoi réel des notifications push (Module 10).
// Optionnel : sans les variables FIREBASE_*, les notifications restent
// enregistrées en base (in-app) mais aucun push n'est envoyé.
let firebaseMessaging = null;
if (process.env.FIREBASE_PROJECT_ID && process.env.FIREBASE_CLIENT_EMAIL && process.env.FIREBASE_PRIVATE_KEY) {
  const admin = require('firebase-admin');
  admin.initializeApp({
    credential: admin.credential.cert({
      projectId: process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'),
    }),
  });
  firebaseMessaging = admin.messaging();
}

// Redis est optionnel : si REDIS_URL n'est pas fourni, on retombe sur une
// Map en mémoire pour stocker les codes OTP (fonctionne pour un seul
// process / une seule instance — suffisant pour démarrer, mais utilise
// Upstash en production dès que tu as plusieurs instances du serveur).
let redisClient = null;
if (process.env.REDIS_URL) {
  const Redis = require('ioredis');
  redisClient = new Redis(process.env.REDIS_URL);
  redisClient.on('error', (err) => console.error('[Redis] erreur :', err.message));
}
const memoryOtpStore = new Map(); // phone -> { code, expiresAt }

// ============================================================================
// CONFIG
// ============================================================================

const PORT = process.env.PORT || 3000;
const BCRYPT_COST_FACTOR = 12;
const OTP_TTL_SECONDS = 5 * 60; // 5 minutes
const ACCESS_TOKEN_EXPIRES = process.env.JWT_ACCESS_EXPIRES || '15m';
const REFRESH_TOKEN_DAYS = 30;
const JWT_ACCESS_SECRET = process.env.JWT_ACCESS_SECRET || 'changez_moi_en_prod';
const GEMINI_API_KEY = process.env.GEMINI_API_KEY || '';
const GEMINI_MODEL = process.env.GEMINI_MODEL || 'gemini-1.5-flash';

const USER_ROLES = [
  'agriculteur',
  'agronome',
  'acheteur',
  'restaurant',
  'transporteur',
  'admin',
];

/**
 * Validation au démarrage — évite de découvrir en production qu'une
 * variable critique manque ou qu'un secret par défaut est encore utilisé.
 * Ne bloque pas le démarrage en dev, mais avertit bruyamment.
 */
function validateStartupConfig() {
  const problems = [];

  if (!process.env.DATABASE_URL && !process.env.DB_HOST) {
    problems.push('Aucune configuration de base de données (DATABASE_URL ou DB_HOST manquants).');
  }
  if (!process.env.JWT_ACCESS_SECRET || process.env.JWT_ACCESS_SECRET === 'changez_moi_en_prod') {
    problems.push(
      "JWT_ACCESS_SECRET n'est pas défini ou utilise encore la valeur par défaut — " +
        'génère une vraie valeur avec `openssl rand -hex 32`.',
    );
  }
  if (!process.env.GEMINI_API_KEY) {
    problems.push('GEMINI_API_KEY manquante — le chatbot (Module 7) ne fonctionnera pas.');
  }

  if (problems.length > 0) {
    console.warn('\n[Config] Points à vérifier avant la production :');
    problems.forEach((p) => console.warn(`  - ${p}`));
    console.warn('');
  }

  if (process.env.NODE_ENV === 'production' && (!process.env.JWT_ACCESS_SECRET || process.env.JWT_ACCESS_SECRET === 'changez_moi_en_prod')) {
    console.error('[Config] ARRÊT : JWT_ACCESS_SECRET par défaut interdit en production.');
    process.exit(1);
  }
}

// ============================================================================
// BASE DE DONNEES (PostgreSQL — Supabase compatible)
// ============================================================================

const useSsl = !!process.env.DATABASE_URL || process.env.DB_SSL === 'true';

const pool = new Pool(
  process.env.DATABASE_URL
    ? {
        connectionString: process.env.DATABASE_URL,
        ssl: useSsl ? { rejectUnauthorized: false } : false,
      }
    : {
        host: process.env.DB_HOST || 'localhost',
        port: parseInt(process.env.DB_PORT || '5432', 10),
        user: process.env.DB_USER || 'difa',
        password: process.env.DB_PASSWORD || 'difa_password',
        database: process.env.DB_NAME || 'difa_db',
        ssl: useSsl ? { rejectUnauthorized: false } : false,
      },
);

/** Crée toutes les tables si elles n'existent pas encore (idempotent). */
async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY,
      full_name TEXT NOT NULL,
      phone TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK (role IN ('agriculteur','agronome','acheteur','restaurant','transporteur','admin')),
      region TEXT,
      phone_verified BOOLEAN DEFAULT FALSE,
      failed_login_attempts INTEGER DEFAULT 0,
      locked_until TIMESTAMPTZ,
      is_active BOOLEAN DEFAULT TRUE,
      created_at TIMESTAMPTZ DEFAULT now(),
      updated_at TIMESTAMPTZ DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS refresh_tokens (
      id UUID PRIMARY KEY,
      user_id UUID REFERENCES users(id) ON DELETE CASCADE,
      token_hash TEXT UNIQUE NOT NULL,
      device_info TEXT,
      expires_at TIMESTAMPTZ NOT NULL,
      revoked BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMPTZ DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS cultures (
      id UUID PRIMARY KEY,
      agriculteur_id UUID REFERENCES users(id) ON DELETE CASCADE,
      type_culture TEXT NOT NULL,
      date_semis DATE NOT NULL,
      superficie_ha NUMERIC(10,2) NOT NULL,
      type_sol TEXT NOT NULL,
      region TEXT NOT NULL,
      date_recolte_prevue DATE,
      date_recolte_reelle DATE,
      quantite_produite_kg NUMERIC(10,2) DEFAULT 0,
      quantite_perdue_kg NUMERIC(10,2) DEFAULT 0,
      statut TEXT DEFAULT 'En cours' CHECK (statut IN ('En cours','Récolté','Perdu','Vendu')),
      photos JSONB,
      notes TEXT,
      created_at TIMESTAMPTZ DEFAULT now(),
      updated_at TIMESTAMPTZ DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS products (
      id UUID PRIMARY KEY,
      agriculteur_id UUID REFERENCES users(id) ON DELETE CASCADE,
      nom TEXT NOT NULL,
      quantite NUMERIC(10,2) NOT NULL,
      unite TEXT NOT NULL,
      prix_fcfa INTEGER NOT NULL,
      prix_negociable BOOLEAN DEFAULT TRUE,
      date_recolte DATE,
      description TEXT,
      photos JSONB,
      region TEXT NOT NULL,
      latitude NUMERIC(9,6),
      longitude NUMERIC(9,6),
      statut TEXT DEFAULT 'En attente de validation'
        CHECK (statut IN ('En attente de validation','Publié','Rejeté','Épuisé','Réservé')),
      badge TEXT CHECK (badge IN ('Certifié','Premium','Bio','Haute Qualité')),
      created_at TIMESTAMPTZ DEFAULT now(),
      updated_at TIMESTAMPTZ DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS certifications (
      id UUID PRIMARY KEY,
      product_id UUID REFERENCES products(id) ON DELETE CASCADE,
      agronome_id UUID REFERENCES users(id),
      statut TEXT DEFAULT 'En attente' CHECK (statut IN ('En attente','Acceptée','Validée','Rejetée')),
      badge TEXT CHECK (badge IN ('Certifié','Premium','Bio','Haute Qualité')),
      commentaire TEXT,
      created_at TIMESTAMPTZ DEFAULT now(),
      updated_at TIMESTAMPTZ DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS transport_missions (
      id UUID PRIMARY KEY,
      product_id UUID REFERENCES products(id),
      acheteur_id UUID REFERENCES users(id),
      transporteur_id UUID REFERENCES users(id),
      origine_lat NUMERIC(9,6) NOT NULL,
      origine_lng NUMERIC(9,6) NOT NULL,
      destination_lat NUMERIC(9,6) NOT NULL,
      destination_lng NUMERIC(9,6) NOT NULL,
      position_actuelle_lat NUMERIC(9,6),
      position_actuelle_lng NUMERIC(9,6),
      statut TEXT DEFAULT 'En attente de transporteur'
        CHECK (statut IN ('En attente de transporteur','Acceptée','En route','Arrivée','Livrée','Annulée')),
      note_transporteur NUMERIC(2,1),
      created_at TIMESTAMPTZ DEFAULT now(),
      updated_at TIMESTAMPTZ DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS transactions (
      id UUID PRIMARY KEY,
      user_id UUID REFERENCES users(id),
      order_id UUID,
      montant_fcfa INTEGER NOT NULL,
      methode TEXT NOT NULL CHECK (methode IN ('mobile_money','carte','portefeuille_interne')),
      statut TEXT DEFAULT 'en_attente' CHECK (statut IN ('en_attente','reussi','echec','rembourse')),
      reference_externe TEXT,
      metadata JSONB,
      created_at TIMESTAMPTZ DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS notifications (
      id UUID PRIMARY KEY,
      user_id UUID REFERENCES users(id) ON DELETE CASCADE,
      type TEXT NOT NULL,
      titre TEXT NOT NULL,
      message TEXT NOT NULL,
      lu BOOLEAN DEFAULT FALSE,
      data JSONB,
      created_at TIMESTAMPTZ DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS push_tokens (
      id UUID PRIMARY KEY,
      user_id UUID REFERENCES users(id) ON DELETE CASCADE,
      fcm_token TEXT UNIQUE NOT NULL,
      created_at TIMESTAMPTZ DEFAULT now()
    );
  `);
  console.log('[DB] Tables prêtes.');
}

// ============================================================================
// HELPERS — OTP (Redis ou fallback mémoire)
// ============================================================================

function generateOtpCode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

async function storeOtp(phone, code) {
  if (redisClient) {
    await redisClient.set(`otp:${phone}`, code, 'EX', OTP_TTL_SECONDS);
  } else {
    memoryOtpStore.set(phone, { code, expiresAt: Date.now() + OTP_TTL_SECONDS * 1000 });
  }
}

async function verifyAndConsumeOtp(phone, code) {
  if (redisClient) {
    const stored = await redisClient.get(`otp:${phone}`);
    if (!stored || stored !== code) return false;
    await redisClient.del(`otp:${phone}`);
    return true;
  }
  const entry = memoryOtpStore.get(phone);
  if (!entry || entry.expiresAt < Date.now() || entry.code !== code) return false;
  memoryOtpStore.delete(phone);
  return true;
}

async function sendOtpSms(phone, code) {
  // Priorité 1 : Vonage (Nexmo)
  const vonageKey = process.env.VONAGE_API_KEY;
  const vonageSecret = process.env.VONAGE_API_SECRET;
  const vonageFrom = process.env.VONAGE_FROM || 'DIFA';

  if (vonageKey && vonageSecret) {
    try {
      const to = phone.replace(/^\+/, ''); // Vonage préfère sans le +
      await axios.post(
        'https://rest.nexmo.com/sms/json',
        {
          api_key: vonageKey,
          api_secret: vonageSecret,
          to,
          from: vonageFrom,
          text: `Votre code Difa est ${code}. Il expire dans 5 minutes.`,
        },
        { headers: { 'Content-Type': 'application/json' } },
      );
      console.log(`[OTP] SMS Vonage envoyé à ${phone}`);
      return;
    } catch (err) {
      console.error('[OTP] Échec envoi SMS Vonage :', err.response?.data || err.message);
    }
  }

  // Priorité 2 : Africa's Talking (fallback)
  const atKey = process.env.AT_API_KEY;
  if (atKey) {
    try {
      await axios.post(
        'https://api.africastalking.com/version1/messaging',
        new URLSearchParams({
          username: process.env.AT_USERNAME || 'sandbox',
          to: phone,
          message: `Votre code Difa est ${code}. Il expire dans 5 minutes.`,
          from: process.env.AT_SENDER_ID || 'DIFA',
        }),
        {
          headers: {
            apiKey: atKey,
            'Content-Type': 'application/x-www-form-urlencoded',
            Accept: 'application/json',
          },
        },
      );
      console.log(`[OTP] SMS Africa's Talking envoyé à ${phone}`);
      return;
    } catch (err) {
      console.error("[OTP] Échec envoi SMS Africa's Talking :", err.message);
    }
  }

  // Toujours logger le code (utile tant que les SMS ne sont pas fiables)
  console.log(`[OTP] Code pour ${phone} : ${code}`);
}

// ============================================================================
// HELPERS — AUTH (JWT, bcrypt, refresh tokens)
// ============================================================================

function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function signAccessToken(user) {
  return jwt.sign(
    { sub: user.id, phone: user.phone, role: user.role },
    JWT_ACCESS_SECRET,
    { expiresIn: ACCESS_TOKEN_EXPIRES },
  );
}

async function issueTokens(user, deviceInfo) {
  const accessToken = signAccessToken(user);
  const refreshTokenRaw = crypto.randomBytes(48).toString('hex');
  const tokenHash = hashToken(refreshTokenRaw);
  const expiresAt = new Date();
  expiresAt.setDate(expiresAt.getDate() + REFRESH_TOKEN_DAYS);

  await pool.query(
    `INSERT INTO refresh_tokens (id, user_id, token_hash, device_info, expires_at, revoked)
     VALUES ($1, $2, $3, $4, $5, false)`,
    [crypto.randomUUID(), user.id, tokenHash, deviceInfo || null, expiresAt],
  );

  return {
    accessToken,
    refreshToken: refreshTokenRaw,
    user: { id: user.id, phone: user.phone, role: user.role },
  };
}

/** Middleware : vérifie le JWT et injecte req.user = { id, phone, role } */
function requireAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Token manquant.' });
  }
  const token = header.slice('Bearer '.length);
  try {
    const payload = jwt.verify(token, JWT_ACCESS_SECRET);
    req.user = { id: payload.sub, phone: payload.phone, role: payload.role };
    next();
  } catch (err) {
    return res.status(401).json({ message: 'Token invalide ou expiré.' });
  }
}

/** Middleware factory : restreint l'accès à certains rôles (RBAC) */
function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({
        message: `Accès refusé. Rôle(s) requis : ${roles.join(', ')}`,
      });
    }
    next();
  };
}

/** Enveloppe async pour éviter les try/catch répétés dans chaque route */
function asyncHandler(fn) {
  return (req, res, next) => fn(req, res, next).catch(next);
}

/** Lit page/limit depuis la query string avec des bornes raisonnables */
function paginationParams(req, defaultLimit = 20, maxLimit = 50) {
  const page = Math.max(1, parseInt(req.query.page || '1', 10));
  const limit = Math.min(maxLimit, Math.max(1, parseInt(req.query.limit || String(defaultLimit), 10)));
  const offset = (page - 1) * limit;
  return { page, limit, offset };
}

function paginatedResponse(rows, mapper, page, limit, total) {
  return {
    data: rows.map(mapper),
    pagination: { page, limit, total, totalPages: Math.ceil(total / limit) },
  };
}

// ============================================================================
// APP EXPRESS
// ============================================================================

const app = express();

// Obligatoire derrière le proxy Render (corrige ERR_ERL_UNEXPECTED_X_FORWARDED_FOR)
app.set('trust proxy', 1);

// En-têtes de sécurité HTTP standards (CSP, X-Frame-Options, etc.)
app.use(helmet());

// Conserve le corps brut pour la vérification de signature du webhook PayStack
app.use(
  express.json({
    verify: (req, res, buf) => {
      req.rawBody = buf;
    },
  }),
);
app.use(cors({ origin: '*' })); // à restreindre à ton domaine mobile une fois en prod

// Limite globale : 100 requêtes / 15 min / IP — protège contre les abus génériques
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: 'Trop de requêtes. Réessayez plus tard.' },
});
app.use('/api/v1', globalLimiter);

// Limite stricte sur les endpoints sensibles à la sécurité (Module 1 — anti brute-force)
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: 'Trop de tentatives. Réessayez dans 15 minutes.' },
});

const router = express.Router();
app.use('/api/v1', router);

// ============================================================================
// MODULE 1 — AUTHENTIFICATION & SECURITE
// ============================================================================

router.post(
  '/auth/register',
  authLimiter,
  asyncHandler(async (req, res) => {
    const { fullName, phone, password, role, region, email } = req.body;

    if (!fullName || !phone || !password || !role) {
      return res.status(400).json({ message: 'Champs requis manquants.' });
    }
    if (!USER_ROLES.includes(role)) {
      return res.status(400).json({ message: 'Rôle invalide.' });
    }
    if (password.length < 6) {
      return res
        .status(400)
        .json({ message: 'Le mot de passe doit contenir au moins 6 caractères.' });
    }

    const existing = await pool.query('SELECT id FROM users WHERE phone = $1', [phone]);
    if (existing.rows.length > 0) {
      return res.status(409).json({ message: 'Un compte existe déjà avec ce numéro.' });
    }

    const passwordHash = await bcrypt.hash(password, BCRYPT_COST_FACTOR);
    const id = crypto.randomUUID();

    await pool.query(
      `INSERT INTO users (id, full_name, phone, email, password_hash, role, region, phone_verified)
       VALUES ($1, $2, $3, $4, $5, $6, $7, false)`,
      [id, fullName, phone, email || null, passwordHash, role, region || null],
    );

    const code = generateOtpCode();
    await storeOtp(phone, code);
    await sendOtpSms(phone, code);

    // En mode debug (ou si SMS non fiable), on renvoie aussi le code pour tester
    const payload = {
      userId: id,
      message: 'Code de vérification envoyé par SMS.',
    };
    if (process.env.OTP_DEBUG === 'true' || process.env.NODE_ENV !== 'production') {
      payload.debugOtp = code;
    }

    res.status(201).json(payload);
  }),
);

router.post(
  '/auth/verify-otp',
  asyncHandler(async (req, res) => {
    const { phone, otp } = req.body;
    if (!phone || !otp) {
      return res.status(400).json({ message: 'Téléphone et code OTP requis.' });
    }

    const valid = await verifyAndConsumeOtp(phone, otp);
    if (!valid) return res.status(400).json({ message: 'Code OTP invalide ou expiré.' });

    const result = await pool.query('SELECT * FROM users WHERE phone = $1', [phone]);
    const user = result.rows[0];
    if (!user) return res.status(400).json({ message: 'Compte introuvable.' });

    await pool.query('UPDATE users SET phone_verified = true WHERE id = $1', [user.id]);

    const tokens = await issueTokens(user, req.headers['user-agent']);
    res.json(tokens);
  }),
);

router.post(
  '/auth/login',
  authLimiter,
  asyncHandler(async (req, res) => {
    const { phone, password } = req.body;
    if (!phone || !password) {
      return res.status(400).json({ message: 'Téléphone et mot de passe requis.' });
    }

    const result = await pool.query('SELECT * FROM users WHERE phone = $1', [phone]);
    const user = result.rows[0];
    if (!user) return res.status(401).json({ message: 'Identifiants incorrects.' });

    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      const minutes = Math.ceil((new Date(user.locked_until) - Date.now()) / 60000);
      return res.status(401).json({
        message: `Compte bloqué suite à trop de tentatives. Réessayez dans ${minutes} min.`,
      });
    }

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      const attempts = user.failed_login_attempts + 1;
      if (attempts >= 5) {
        const lockedUntil = new Date(Date.now() + 15 * 60 * 1000);
        await pool.query(
          'UPDATE users SET failed_login_attempts = 0, locked_until = $1 WHERE id = $2',
          [lockedUntil, user.id],
        );
        return res.status(401).json({
          message: '5 tentatives échouées. Compte bloqué 15 minutes.',
        });
      }
      await pool.query('UPDATE users SET failed_login_attempts = $1 WHERE id = $2', [
        attempts,
        user.id,
      ]);
      return res.status(401).json({ message: 'Identifiants incorrects.' });
    }

    if (!user.phone_verified) {
      return res.status(401).json({ message: 'Numéro non vérifié. Vérifiez votre OTP.' });
    }
    if (!user.is_active) {
      return res.status(401).json({ message: 'Compte désactivé. Contactez le support.' });
    }

    await pool.query(
      'UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = $1',
      [user.id],
    );

    const tokens = await issueTokens(user, req.headers['user-agent']);
    res.json(tokens);
  }),
);

router.post(
  '/auth/refresh',
  asyncHandler(async (req, res) => {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(400).json({ message: 'refreshToken requis.' });

    const tokenHash = hashToken(refreshToken);
    const result = await pool.query(
      `SELECT rt.*, u.id as u_id, u.phone as u_phone, u.role as u_role
       FROM refresh_tokens rt
       JOIN users u ON u.id = rt.user_id
       WHERE rt.token_hash = $1 AND rt.revoked = false AND rt.expires_at > now()`,
      [tokenHash],
    );
    const row = result.rows[0];
    if (!row) return res.status(401).json({ message: 'Session expirée. Reconnectez-vous.' });

    // Rotation : on révoque l'ancien refresh token
    await pool.query('UPDATE refresh_tokens SET revoked = true WHERE id = $1', [row.id]);

    const tokens = await issueTokens(
      { id: row.u_id, phone: row.u_phone, role: row.u_role },
      row.device_info,
    );
    res.json(tokens);
  }),
);

router.post(
  '/auth/logout',
  requireAuth,
  asyncHandler(async (req, res) => {
    const { refreshToken } = req.body;
    if (refreshToken) {
      const tokenHash = hashToken(refreshToken);
      await pool.query('UPDATE refresh_tokens SET revoked = true WHERE token_hash = $1', [
        tokenHash,
      ]);
    }
    res.json({ message: 'Déconnexion réussie.' });
  }),
);

router.post(
  '/auth/logout-all',
  requireAuth,
  asyncHandler(async (req, res) => {
    await pool.query('UPDATE refresh_tokens SET revoked = true WHERE user_id = $1', [
      req.user.id,
    ]);
    res.json({ message: 'Toutes les sessions ont été révoquées.' });
  }),
);

router.post(
  '/auth/password/forgot',
  authLimiter,
  asyncHandler(async (req, res) => {
    const { phone } = req.body;
    const result = await pool.query('SELECT id FROM users WHERE phone = $1', [phone]);
    // Anti-énumération : toujours le même message, que le compte existe ou non
    if (result.rows.length > 0) {
      const code = generateOtpCode();
      await storeOtp(phone, code);
      await sendOtpSms(phone, code);
    }
    res.json({ message: 'Si ce numéro est enregistré, un code a été envoyé.' });
  }),
);

router.post(
  '/auth/password/reset',
  authLimiter,
  asyncHandler(async (req, res) => {
    const { phone, otp, newPassword } = req.body;
    if (!newPassword || newPassword.length < 6) {
      return res
        .status(400)
        .json({ message: 'Le mot de passe doit contenir au moins 6 caractères.' });
    }
    const valid = await verifyAndConsumeOtp(phone, otp);
    if (!valid) return res.status(400).json({ message: 'Code OTP invalide ou expiré.' });

    const passwordHash = await bcrypt.hash(newPassword, BCRYPT_COST_FACTOR);
    const result = await pool.query(
      'UPDATE users SET password_hash = $1 WHERE phone = $2 RETURNING id',
      [passwordHash, phone],
    );
    if (result.rows.length === 0) {
      return res.status(400).json({ message: 'Compte introuvable.' });
    }
    await pool.query('UPDATE refresh_tokens SET revoked = true WHERE user_id = $1', [
      result.rows[0].id,
    ]);
    res.json({ message: 'Mot de passe réinitialisé. Reconnectez-vous.' });
  }),
);

// ============================================================================
// MODULE 2 — GESTION DES UTILISATEURS
// ============================================================================

function serializeUser(row) {
  return {
    id: row.id,
    fullName: row.full_name,
    phone: row.phone,
    email: row.email,
    role: row.role,
    region: row.region,
    phoneVerified: row.phone_verified,
    isActive: row.is_active,
    createdAt: row.created_at,
  };
}

router.get(
  '/users/me',
  requireAuth,
  asyncHandler(async (req, res) => {
    const result = await pool.query('SELECT * FROM users WHERE id = $1', [req.user.id]);
    if (!result.rows[0]) return res.status(404).json({ message: 'Utilisateur introuvable.' });
    res.json(serializeUser(result.rows[0]));
  }),
);

router.patch(
  '/users/me',
  requireAuth,
  asyncHandler(async (req, res) => {
    // Un utilisateur ne peut modifier que ses infos non sensibles
    const { fullName, email, region } = req.body;
    await pool.query(
      `UPDATE users SET
         full_name = COALESCE($1, full_name),
         email = COALESCE($2, email),
         region = COALESCE($3, region),
         updated_at = now()
       WHERE id = $4`,
      [fullName, email, region, req.user.id],
    );
    const result = await pool.query('SELECT * FROM users WHERE id = $1', [req.user.id]);
    res.json(serializeUser(result.rows[0]));
  }),
);

router.get(
  '/users',
  requireAuth,
  requireRole('admin'),
  asyncHandler(async (req, res) => {
    const { role } = req.query;
    const { page, limit, offset } = paginationParams(req);

    const countSql = role
      ? 'SELECT COUNT(*) FROM users WHERE role = $1'
      : 'SELECT COUNT(*) FROM users';
    const countValues = role ? [role] : [];
    const total = Number((await pool.query(countSql, countValues)).rows[0].count);

    const sql = role
      ? 'SELECT * FROM users WHERE role = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3'
      : 'SELECT * FROM users ORDER BY created_at DESC LIMIT $1 OFFSET $2';
    const values = role ? [role, limit, offset] : [limit, offset];
    const result = await pool.query(sql, values);

    res.json(paginatedResponse(result.rows, serializeUser, page, limit, total));
  }),
);

router.get(
  '/users/:id',
  requireAuth,
  requireRole('admin', 'agronome'),
  asyncHandler(async (req, res) => {
    const result = await pool.query('SELECT * FROM users WHERE id = $1', [req.params.id]);
    if (!result.rows[0]) return res.status(404).json({ message: 'Utilisateur introuvable.' });
    res.json(serializeUser(result.rows[0]));
  }),
);

// ============================================================================
// MODULE 3 — GESTION AGRICOLE (CULTURES)
// ============================================================================

function serializeCulture(row) {
  return {
    id: row.id,
    agriculteurId: row.agriculteur_id,
    typeCulture: row.type_culture,
    dateSemis: row.date_semis,
    superficieHa: Number(row.superficie_ha),
    typeSol: row.type_sol,
    region: row.region,
    dateRecoltePrevue: row.date_recolte_prevue,
    dateRecolteReelle: row.date_recolte_reelle,
    quantiteProduiteKg: Number(row.quantite_produite_kg),
    quantitePerdueKg: Number(row.quantite_perdue_kg),
    statut: row.statut,
    photos: row.photos,
    notes: row.notes,
    createdAt: row.created_at,
  };
}

router.post(
  '/cultures',
  requireAuth,
  requireRole('agriculteur'),
  asyncHandler(async (req, res) => {
    const { typeCulture, dateSemis, superficieHa, typeSol, region, dateRecoltePrevue, photos, notes } =
      req.body;
    if (!typeCulture || !dateSemis || !superficieHa || !typeSol || !region) {
      return res.status(400).json({ message: 'Champs requis manquants.' });
    }
    const id = crypto.randomUUID();
    await pool.query(
      `INSERT INTO cultures (id, agriculteur_id, type_culture, date_semis, superficie_ha, type_sol, region, date_recolte_prevue, photos, notes)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
      [
        id,
        req.user.id,
        typeCulture,
        dateSemis,
        superficieHa,
        typeSol,
        region,
        dateRecoltePrevue || null,
        photos ? JSON.stringify(photos) : null,
        notes || null,
      ],
    );
    const result = await pool.query('SELECT * FROM cultures WHERE id = $1', [id]);
    res.status(201).json(serializeCulture(result.rows[0]));
  }),
);

router.get(
  '/cultures/mine',
  requireAuth,
  requireRole('agriculteur'),
  asyncHandler(async (req, res) => {
    const result = await pool.query(
      'SELECT * FROM cultures WHERE agriculteur_id = $1 ORDER BY created_at DESC',
      [req.user.id],
    );
    res.json(result.rows.map(serializeCulture));
  }),
);

router.get(
  '/cultures/mine/stats',
  requireAuth,
  requireRole('agriculteur'),
  asyncHandler(async (req, res) => {
    const result = await pool.query('SELECT * FROM cultures WHERE agriculteur_id = $1', [
      req.user.id,
    ]);
    const cultures = result.rows;
    const totalProduitKg = cultures.reduce((s, c) => s + Number(c.quantite_produite_kg || 0), 0);
    const totalPerduKg = cultures.reduce((s, c) => s + Number(c.quantite_perdue_kg || 0), 0);
    res.json({
      totalCultures: cultures.length,
      totalProduitKg,
      totalPerduKg,
      tauxPerte: totalProduitKg > 0 ? (totalPerduKg / totalProduitKg) * 100 : 0,
    });
  }),
);

router.get(
  '/cultures/:id',
  requireAuth,
  requireRole('agriculteur', 'agronome', 'admin'),
  asyncHandler(async (req, res) => {
    const result = await pool.query('SELECT * FROM cultures WHERE id = $1', [req.params.id]);
    if (!result.rows[0]) return res.status(404).json({ message: 'Culture introuvable.' });
    res.json(serializeCulture(result.rows[0]));
  }),
);

router.patch(
  '/cultures/:id/harvest',
  requireAuth,
  requireRole('agriculteur'),
  asyncHandler(async (req, res) => {
    const existing = await pool.query('SELECT * FROM cultures WHERE id = $1', [req.params.id]);
    if (!existing.rows[0]) return res.status(404).json({ message: 'Culture introuvable.' });
    if (existing.rows[0].agriculteur_id !== req.user.id) {
      return res.status(403).json({ message: 'Cette culture ne vous appartient pas.' });
    }
    const { dateRecolteReelle, quantiteProduiteKg, quantitePerdueKg, statut } = req.body;
    await pool.query(
      `UPDATE cultures SET
         date_recolte_reelle = COALESCE($1, date_recolte_reelle),
         quantite_produite_kg = COALESCE($2, quantite_produite_kg),
         quantite_perdue_kg = COALESCE($3, quantite_perdue_kg),
         statut = COALESCE($4, statut),
         updated_at = now()
       WHERE id = $5`,
      [dateRecolteReelle, quantiteProduiteKg, quantitePerdueKg, statut, req.params.id],
    );
    const result = await pool.query('SELECT * FROM cultures WHERE id = $1', [req.params.id]);
    res.json(serializeCulture(result.rows[0]));
  }),
);

router.delete(
  '/cultures/:id',
  requireAuth,
  requireRole('agriculteur'),
  asyncHandler(async (req, res) => {
    const existing = await pool.query('SELECT agriculteur_id FROM cultures WHERE id = $1', [
      req.params.id,
    ]);
    if (!existing.rows[0]) return res.status(404).json({ message: 'Culture introuvable.' });
    if (existing.rows[0].agriculteur_id !== req.user.id) {
      return res.status(403).json({ message: 'Cette culture ne vous appartient pas.' });
    }
    await pool.query('DELETE FROM cultures WHERE id = $1', [req.params.id]);
    res.status(204).send();
  }),
);

// ============================================================================
// MODULE 4 — MARKETPLACE AGRICOLE
// ============================================================================

function serializeProduct(row) {
  return {
    id: row.id,
    agriculteurId: row.agriculteur_id,
    nom: row.nom,
    quantite: Number(row.quantite),
    unite: row.unite,
    prixFcfa: row.prix_fcfa,
    prixNegociable: row.prix_negociable,
    dateRecolte: row.date_recolte,
    description: row.description,
    photos: row.photos,
    region: row.region,
    latitude: row.latitude ? Number(row.latitude) : null,
    longitude: row.longitude ? Number(row.longitude) : null,
    statut: row.statut,
    badge: row.badge,
    createdAt: row.created_at,
  };
}

// Recherche publique — pas d'authentification requise
router.get(
  '/marketplace/products',
  asyncHandler(async (req, res) => {
    const { q, region, certifieOnly, prixMin, prixMax, sortBy } = req.query;
    const page = Math.max(1, parseInt(req.query.page || '1', 10));
    const limit = Math.min(50, Math.max(1, parseInt(req.query.limit || '20', 10)));
    const offset = (page - 1) * limit;

    const conditions = [`statut = 'Publié'`];
    const values = [];

    if (q) {
      values.push(`%${q.toLowerCase()}%`);
      conditions.push(`LOWER(nom) LIKE $${values.length}`);
    }
    if (region) {
      values.push(region);
      conditions.push(`region = $${values.length}`);
    }
    if (certifieOnly === 'true') {
      conditions.push(`badge IS NOT NULL`);
    }
    if (prixMin) {
      values.push(Number(prixMin));
      conditions.push(`prix_fcfa >= $${values.length}`);
    }
    if (prixMax) {
      values.push(Number(prixMax));
      conditions.push(`prix_fcfa <= $${values.length}`);
    }

    let orderBy = 'created_at DESC';
    if (sortBy === 'prix_asc') orderBy = 'prix_fcfa ASC';
    if (sortBy === 'prix_desc') orderBy = 'prix_fcfa DESC';

    const countSql = `SELECT COUNT(*) FROM products WHERE ${conditions.join(' AND ')}`;
    const total = Number((await pool.query(countSql, values)).rows[0].count);

    values.push(limit, offset);
    const sql = `SELECT * FROM products WHERE ${conditions.join(' AND ')} ORDER BY ${orderBy} LIMIT $${values.length - 1} OFFSET $${values.length}`;
    const result = await pool.query(sql, values);

    res.json({
      data: result.rows.map(serializeProduct),
      pagination: { page, limit, total, totalPages: Math.ceil(total / limit) },
    });
  }),
);

router.get(
  '/marketplace/products/mine/list',
  requireAuth,
  requireRole('agriculteur'),
  asyncHandler(async (req, res) => {
    const result = await pool.query(
      'SELECT * FROM products WHERE agriculteur_id = $1 ORDER BY created_at DESC',
      [req.user.id],
    );
    res.json(result.rows.map(serializeProduct));
  }),
);

router.get(
  '/marketplace/products/:id',
  asyncHandler(async (req, res) => {
    const result = await pool.query('SELECT * FROM products WHERE id = $1', [req.params.id]);
    if (!result.rows[0]) return res.status(404).json({ message: 'Produit introuvable.' });
    res.json(serializeProduct(result.rows[0]));
  }),
);

router.post(
  '/marketplace/products',
  requireAuth,
  requireRole('agriculteur'),
  asyncHandler(async (req, res) => {
    const {
      nom,
      quantite,
      unite,
      prixFcfa,
      prixNegociable,
      dateRecolte,
      description,
      photos,
      region,
      latitude,
      longitude,
    } = req.body;

    if (!nom || !quantite || !unite || !prixFcfa || !region) {
      return res.status(400).json({ message: 'Champs requis manquants.' });
    }

    const id = crypto.randomUUID();
    await pool.query(
      `INSERT INTO products (id, agriculteur_id, nom, quantite, unite, prix_fcfa, prix_negociable, date_recolte, description, photos, region, latitude, longitude, statut)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'En attente de validation')`,
      [
        id,
        req.user.id,
        nom,
        quantite,
        unite,
        prixFcfa,
        prixNegociable !== false,
        dateRecolte || null,
        description || null,
        photos ? JSON.stringify(photos) : null,
        region,
        latitude || null,
        longitude || null,
      ],
    );

    // Crée automatiquement la demande de certification (Module 5, étape 1-2)
    await pool.query(
      `INSERT INTO certifications (id, product_id, statut) VALUES ($1,$2,'En attente')`,
      [crypto.randomUUID(), id],
    );

    const result = await pool.query('SELECT * FROM products WHERE id = $1', [id]);
    res.status(201).json(serializeProduct(result.rows[0]));
  }),
);

router.patch(
  '/marketplace/products/:id',
  requireAuth,
  requireRole('agriculteur'),
  asyncHandler(async (req, res) => {
    const existing = await pool.query('SELECT agriculteur_id FROM products WHERE id = $1', [
      req.params.id,
    ]);
    if (!existing.rows[0]) return res.status(404).json({ message: 'Produit introuvable.' });
    if (existing.rows[0].agriculteur_id !== req.user.id) {
      return res.status(403).json({ message: 'Ce produit ne vous appartient pas.' });
    }
    const { nom, quantite, prixFcfa, description } = req.body;
    await pool.query(
      `UPDATE products SET
         nom = COALESCE($1, nom),
         quantite = COALESCE($2, quantite),
         prix_fcfa = COALESCE($3, prix_fcfa),
         description = COALESCE($4, description),
         updated_at = now()
       WHERE id = $5`,
      [nom, quantite, prixFcfa, description, req.params.id],
    );
    const result = await pool.query('SELECT * FROM products WHERE id = $1', [req.params.id]);
    res.json(serializeProduct(result.rows[0]));
  }),
);

router.delete(
  '/marketplace/products/:id',
  requireAuth,
  requireRole('agriculteur'),
  asyncHandler(async (req, res) => {
    const existing = await pool.query('SELECT agriculteur_id FROM products WHERE id = $1', [
      req.params.id,
    ]);
    if (!existing.rows[0]) return res.status(404).json({ message: 'Produit introuvable.' });
    if (existing.rows[0].agriculteur_id !== req.user.id) {
      return res.status(403).json({ message: 'Ce produit ne vous appartient pas.' });
    }
    await pool.query('DELETE FROM products WHERE id = $1', [req.params.id]);
    res.status(204).send();
  }),
);

// ============================================================================
// MODULE 5 — CERTIFICATION QUALITE
// ============================================================================

function serializeCertification(row) {
  return {
    id: row.id,
    productId: row.product_id,
    agronomeId: row.agronome_id,
    statut: row.statut,
    badge: row.badge,
    commentaire: row.commentaire,
    createdAt: row.created_at,
  };
}

router.get(
  '/certifications/pending',
  requireAuth,
  requireRole('agronome', 'admin'),
  asyncHandler(async (req, res) => {
    const result = await pool.query(
      `SELECT * FROM certifications WHERE statut = 'En attente' ORDER BY created_at ASC`,
    );
    res.json(result.rows.map(serializeCertification));
  }),
);

router.get(
  '/certifications/mine',
  requireAuth,
  requireRole('agronome'),
  asyncHandler(async (req, res) => {
    const result = await pool.query(
      'SELECT * FROM certifications WHERE agronome_id = $1 ORDER BY created_at DESC',
      [req.user.id],
    );
    res.json(result.rows.map(serializeCertification));
  }),
);

router.post(
  '/certifications/:id/accept',
  requireAuth,
  requireRole('agronome'),
  asyncHandler(async (req, res) => {
    const existing = await pool.query('SELECT * FROM certifications WHERE id = $1', [
      req.params.id,
    ]);
    if (!existing.rows[0]) return res.status(404).json({ message: 'Demande introuvable.' });
    if (existing.rows[0].statut !== 'En attente') {
      return res.status(400).json({ message: 'Cette demande a déjà été traitée.' });
    }
    await pool.query(
      `UPDATE certifications SET agronome_id = $1, statut = 'Acceptée', updated_at = now() WHERE id = $2`,
      [req.user.id, req.params.id],
    );
    const result = await pool.query('SELECT * FROM certifications WHERE id = $1', [
      req.params.id,
    ]);
    res.json(serializeCertification(result.rows[0]));
  }),
);

router.post(
  '/certifications/:id/validate',
  requireAuth,
  requireRole('agronome'),
  asyncHandler(async (req, res) => {
    const { badge, commentaire } = req.body;
    if (!badge) return res.status(400).json({ message: 'Le badge est requis.' });

    const existing = await pool.query('SELECT * FROM certifications WHERE id = $1', [
      req.params.id,
    ]);
    if (!existing.rows[0]) return res.status(404).json({ message: 'Demande introuvable.' });
    if (existing.rows[0].agronome_id !== req.user.id) {
      return res.status(400).json({ message: "Vous n'êtes pas assigné à cette inspection." });
    }

    await pool.query(
      `UPDATE certifications SET statut = 'Validée', badge = $1, commentaire = $2, updated_at = now() WHERE id = $3`,
      [badge, commentaire || null, req.params.id],
    );
    // Publication automatique du produit avec badge (Module 4, étape 5)
    await pool.query(
      `UPDATE products SET statut = 'Publié', badge = $1, updated_at = now() WHERE id = $2`,
      [badge, existing.rows[0].product_id],
    );

    const result = await pool.query('SELECT * FROM certifications WHERE id = $1', [
      req.params.id,
    ]);

    const product = await pool.query('SELECT agriculteur_id, nom FROM products WHERE id = $1', [
      existing.rows[0].product_id,
    ]);
    if (product.rows[0]) {
      await notifyUser(
        product.rows[0].agriculteur_id,
        'produit_valide',
        'Produit certifié',
        `Votre produit "${product.rows[0].nom}" a été validé avec le badge ${badge}.`,
        { productId: existing.rows[0].product_id, badge },
      );
    }

    res.json(serializeCertification(result.rows[0]));
  }),
);

router.post(
  '/certifications/:id/reject',
  requireAuth,
  requireRole('agronome'),
  asyncHandler(async (req, res) => {
    const { commentaire } = req.body;
    const existing = await pool.query('SELECT * FROM certifications WHERE id = $1', [
      req.params.id,
    ]);
    if (!existing.rows[0]) return res.status(404).json({ message: 'Demande introuvable.' });
    if (existing.rows[0].agronome_id !== req.user.id) {
      return res.status(400).json({ message: "Vous n'êtes pas assigné à cette inspection." });
    }
    await pool.query(
      `UPDATE certifications SET statut = 'Rejetée', commentaire = $1, updated_at = now() WHERE id = $2`,
      [commentaire || null, req.params.id],
    );
    await pool.query(`UPDATE products SET statut = 'Rejeté', updated_at = now() WHERE id = $1`, [
      existing.rows[0].product_id,
    ]);
    const result = await pool.query('SELECT * FROM certifications WHERE id = $1', [
      req.params.id,
    ]);

    const product = await pool.query('SELECT agriculteur_id, nom FROM products WHERE id = $1', [
      existing.rows[0].product_id,
    ]);
    if (product.rows[0]) {
      await notifyUser(
        product.rows[0].agriculteur_id,
        'produit_rejete',
        'Produit rejeté',
        `Votre produit "${product.rows[0].nom}" a été rejeté.${commentaire ? ' Motif : ' + commentaire : ''}`,
        { productId: existing.rows[0].product_id },
      );
    }

    res.json(serializeCertification(result.rows[0]));
  }),
);

// ============================================================================
// MODULE 6 & 11 — TRANSPORT & LOGISTIQUE + GPS TEMPS REEL
// ============================================================================

function serializeMission(row) {
  return {
    id: row.id,
    productId: row.product_id,
    acheteurId: row.acheteur_id,
    transporteurId: row.transporteur_id,
    origineLat: Number(row.origine_lat),
    origineLng: Number(row.origine_lng),
    destinationLat: Number(row.destination_lat),
    destinationLng: Number(row.destination_lng),
    positionActuelleLat: row.position_actuelle_lat ? Number(row.position_actuelle_lat) : null,
    positionActuelleLng: row.position_actuelle_lng ? Number(row.position_actuelle_lng) : null,
    statut: row.statut,
    noteTransporteur: row.note_transporteur ? Number(row.note_transporteur) : null,
    createdAt: row.created_at,
  };
}

router.post(
  '/transport/missions',
  requireAuth,
  requireRole('acheteur', 'restaurant'),
  asyncHandler(async (req, res) => {
    const { productId, origineLat, origineLng, destinationLat, destinationLng } = req.body;
    if (!origineLat || !origineLng || !destinationLat || !destinationLng) {
      return res.status(400).json({ message: 'Coordonnées manquantes.' });
    }
    const id = crypto.randomUUID();
    await pool.query(
      `INSERT INTO transport_missions (id, product_id, acheteur_id, origine_lat, origine_lng, destination_lat, destination_lng, statut)
       VALUES ($1,$2,$3,$4,$5,$6,$7,'En attente de transporteur')`,
      [id, productId || null, req.user.id, origineLat, origineLng, destinationLat, destinationLng],
    );
    const result = await pool.query('SELECT * FROM transport_missions WHERE id = $1', [id]);
    res.status(201).json(serializeMission(result.rows[0]));
  }),
);

router.get(
  '/transport/missions/available',
  requireAuth,
  requireRole('transporteur'),
  asyncHandler(async (req, res) => {
    const result = await pool.query(
      `SELECT * FROM transport_missions WHERE statut = 'En attente de transporteur' ORDER BY created_at ASC`,
    );
    res.json(result.rows.map(serializeMission));
  }),
);

router.get(
  '/transport/missions/mine',
  requireAuth,
  requireRole('transporteur'),
  asyncHandler(async (req, res) => {
    const result = await pool.query(
      'SELECT * FROM transport_missions WHERE transporteur_id = $1 ORDER BY created_at DESC',
      [req.user.id],
    );
    res.json(result.rows.map(serializeMission));
  }),
);

router.post(
  '/transport/missions/:id/accept',
  requireAuth,
  requireRole('transporteur'),
  asyncHandler(async (req, res) => {
    const existing = await pool.query('SELECT * FROM transport_missions WHERE id = $1', [
      req.params.id,
    ]);
    if (!existing.rows[0]) return res.status(404).json({ message: 'Mission introuvable.' });
    if (existing.rows[0].statut !== 'En attente de transporteur') {
      return res.status(400).json({ message: 'Cette mission a déjà été prise.' });
    }
    await pool.query(
      `UPDATE transport_missions SET transporteur_id = $1, statut = 'Acceptée', updated_at = now() WHERE id = $2`,
      [req.user.id, req.params.id],
    );
    const result = await pool.query('SELECT * FROM transport_missions WHERE id = $1', [
      req.params.id,
    ]);

    await notifyUser(
      existing.rows[0].acheteur_id,
      'transporteur_en_route',
      'Transporteur trouvé',
      'Un transporteur a accepté votre commande et va la récupérer.',
      { missionId: req.params.id },
    );

    res.json(serializeMission(result.rows[0]));
  }),
);

router.get(
  '/transport/missions/:id',
  requireAuth,
  requireRole('transporteur', 'acheteur', 'restaurant', 'admin'),
  asyncHandler(async (req, res) => {
    const result = await pool.query('SELECT * FROM transport_missions WHERE id = $1', [
      req.params.id,
    ]);
    if (!result.rows[0]) return res.status(404).json({ message: 'Mission introuvable.' });
    res.json(serializeMission(result.rows[0]));
  }),
);

// ============================================================================
// MODULE 7 — INTELLIGENCE ARTIFICIELLE (Gemini, appelé directement en REST)
// ============================================================================

const GEMINI_SYSTEM_PROMPT = `Tu es l'assistant agricole de Difa, une plateforme togolaise qui connecte
agriculteurs, agronomes, acheteurs et transporteurs.
Tu réponds UNIQUEMENT aux questions liées à l'agriculture tropicale et
togolaise : cultures locales (maïs, manioc, igname, tomate, riz, coton...),
calendrier agricole, irrigation, engrais, maladies des plantes, techniques
de production, conservation post-récolte.
Sois concis, pratique, et adapté aux réalités des petits producteurs
togolais (accès limité à l'irrigation moderne, saisons sèche/pluvieuse).
Si la question dépasse ton champ de compétence, invite poliment
l'agriculteur à contacter un agronome Difa via l'application.`;

// Historique de conversation en mémoire par session (simple — à déplacer
// vers Redis si tu fais tourner plusieurs instances du serveur)
const chatHistories = new Map();

router.post(
  '/ai/chat',
  requireAuth,
  requireRole('agriculteur'),
  asyncHandler(async (req, res) => {
    if (!GEMINI_API_KEY) {
      return res.status(503).json({
        message: 'Service IA non configuré (GEMINI_API_KEY manquante côté serveur).',
      });
    }
    const { message, sessionId } = req.body;
    if (!message) return res.status(400).json({ message: 'Message requis.' });

    const sid = sessionId || req.user.id;
    const history = chatHistories.get(sid) || [];

    const contents = [
      { role: 'user', parts: [{ text: GEMINI_SYSTEM_PROMPT }] },
      { role: 'model', parts: [{ text: "Compris, je suis prêt à aider." }] },
      ...history,
      { role: 'user', parts: [{ text: message }] },
    ];

    try {
      const response = await axios.post(
        `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent?key=${GEMINI_API_KEY}`,
        {
          contents,
          generationConfig: { temperature: 0.6, maxOutputTokens: 800 },
        },
      );

      const replyText =
        response.data?.candidates?.[0]?.content?.parts?.[0]?.text ||
        "Désolé, je n'ai pas pu générer de réponse.";

      history.push({ role: 'user', parts: [{ text: message }] });
      history.push({ role: 'model', parts: [{ text: replyText }] });
      chatHistories.set(sid, history.slice(-20)); // garde les 20 derniers échanges

      res.json({ reply: replyText, sessionId: sid });
    } catch (err) {
      console.error('[Gemini] erreur :', err.response?.data || err.message);
      res.status(502).json({ message: 'Erreur du service IA. Réessayez.' });
    }
  }),
);

// 7.2 — Analyse prédictive simple (heuristique, à enrichir avec un vrai
// modèle une fois des données réelles de rendement disponibles)
const RENDEMENT_MOYEN_KG_HA = {
  maïs: 1200,
  mais: 1200,
  manioc: 9000,
  igname: 8000,
  tomate: 15000,
  riz: 2500,
  coton: 900,
};

router.post(
  '/ai/predict/rendement',
  requireAuth,
  requireRole('agriculteur'),
  asyncHandler(async (req, res) => {
    const { typeCulture, superficieHa, historiqueRendementKgHa } = req.body;
    const base = RENDEMENT_MOYEN_KG_HA[(typeCulture || '').toLowerCase()] || 2000;
    let estime = base * (superficieHa || 0);
    let confiance = 'faible-moyenne (basée sur moyenne régionale générique)';
    if (historiqueRendementKgHa) {
      estime = (estime + historiqueRendementKgHa * superficieHa) / 2;
      confiance = 'moyenne-haute (basée sur historique personnel)';
    }
    res.json({
      rendementEstimeKg: Math.round(estime * 10) / 10,
      confiance,
      note: 'Estimation heuristique de démonstration.',
    });
  }),
);

// ============================================================================
// UPLOAD DE PHOTOS (produits, cultures) — stockage Supabase Storage
// ============================================================================
//
// Pourquoi Supabase Storage et pas le disque local du serveur ? Render (et la
// plupart des PaaS) ont un système de fichiers ÉPHÉMÈRE : tout ce qui est
// écrit sur disque est perdu au prochain redéploiement ou redémarrage. Les
// photos doivent donc aller dans un stockage persistant séparé — ici le
// même projet Supabase que la base de données, dans un bucket Storage dédié.
//
// Configuration requise (voir .env.example) :
//   SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY
// + un bucket nommé "difa-photos" créé dans Supabase (Storage > New bucket),
//   marqué "Public" pour que les URLs générées soient directement affichables
//   dans l'app mobile sans authentification supplémentaire.

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 }, // 5 Mo max par photo
  fileFilter: (req, file, cb) => {
    if (!file.mimetype.startsWith('image/')) {
      return cb(new Error('Seules les images sont acceptées.'));
    }
    cb(null, true);
  },
});

router.post(
  '/uploads/photo',
  requireAuth,
  upload.single('photo'),
  asyncHandler(async (req, res) => {
    if (!supabaseStorage) {
      return res.status(503).json({
        message: 'Stockage de fichiers non configuré côté serveur (SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY manquants).',
      });
    }
    if (!req.file) {
      return res.status(400).json({ message: 'Aucun fichier reçu (champ attendu : "photo").' });
    }

    const ext = (req.file.originalname.split('.').pop() || 'jpg').toLowerCase();
    const path = `${req.user.id}/${crypto.randomUUID()}.${ext}`;

    const { error } = await supabaseStorage.storage
      .from('difa-photos')
      .upload(path, req.file.buffer, { contentType: req.file.mimetype, upsert: false });

    if (error) {
      console.error('[Upload] Échec Supabase Storage :', error.message);
      return res.status(502).json({ message: "Échec de l'envoi de la photo. Réessayez." });
    }

    const { data } = supabaseStorage.storage.from('difa-photos').getPublicUrl(path);
    res.status(201).json({ url: data.publicUrl, path });
  }),
);

// ============================================================================
// MODULE 9 — PAIEMENT
// ============================================================================

function serializeTransaction(row) {
  return {
    id: row.id,
    userId: row.user_id,
    orderId: row.order_id,
    montantFcfa: row.montant_fcfa,
    methode: row.methode,
    statut: row.statut,
    referenceExterne: row.reference_externe,
    createdAt: row.created_at,
  };
}

router.post(
  '/payments/paystack/initiate',
  requireAuth,
  asyncHandler(async (req, res) => {
    const secretKey = process.env.PAYSTACK_SECRET_KEY;
    if (!secretKey) {
      return res.status(400).json({ message: 'PayStack non configuré côté serveur.' });
    }
    const { montantFcfa, email, orderId } = req.body;

    const response = await axios.post(
      'https://api.paystack.co/transaction/initialize',
      { email, amount: montantFcfa * 100, currency: 'XOF' },
      { headers: { Authorization: `Bearer ${secretKey}` } },
    );

    const id = crypto.randomUUID();
    await pool.query(
      `INSERT INTO transactions (id, user_id, order_id, montant_fcfa, methode, statut, reference_externe)
       VALUES ($1,$2,$3,$4,'carte','en_attente',$5)`,
      [id, req.user.id, orderId || null, montantFcfa, response.data.data.reference],
    );

    res.json({
      authorizationUrl: response.data.data.authorization_url,
      reference: response.data.data.reference,
      transactionId: id,
    });
  }),
);

// Webhook — PAS de requireAuth (appelé par PayStack). Sécurité = signature HMAC.
router.post(
  '/payments/paystack/webhook',
  asyncHandler(async (req, res) => {
    const secretKey = process.env.PAYSTACK_SECRET_KEY || '';
    const signature = req.headers['x-paystack-signature'];
    const hash = crypto.createHmac('sha512', secretKey).update(req.rawBody).digest('hex');

    if (hash !== signature) {
      return res.status(200).json({ received: false, reason: 'invalid_signature' });
    }

    const event = req.body;
    if (event.event === 'charge.success') {
      const tx = await pool.query(
        `UPDATE transactions SET statut = 'reussi', metadata = $1 WHERE reference_externe = $2 RETURNING user_id, montant_fcfa`,
        [JSON.stringify(event.data), event.data.reference],
      );
      if (tx.rows[0]) {
        await notifyUser(
          tx.rows[0].user_id,
          'paiement_recu',
          'Paiement confirmé',
          `Votre paiement de ${tx.rows[0].montant_fcfa} FCFA a été reçu avec succès.`,
          { reference: event.data.reference },
        );
      }
    }
    res.json({ received: true });
  }),
);

router.post(
  '/payments/mobile-money/initiate',
  requireAuth,
  asyncHandler(async (req, res) => {
    const { montantFcfa, phone, provider, orderId } = req.body;
    const id = crypto.randomUUID();
    await pool.query(
      `INSERT INTO transactions (id, user_id, order_id, montant_fcfa, methode, statut, metadata)
       VALUES ($1,$2,$3,$4,'mobile_money','en_attente',$5)`,
      [id, req.user.id, orderId || null, montantFcfa, JSON.stringify({ provider, phone })],
    );
    // TODO : intégrer l'API officielle Togocel (T-Money) ou Moov (Flooz)
    // une fois les identifiants marchands obtenus.
    console.warn(`[TODO] Intégration ${provider} à finaliser — transaction ${id} en attente.`);
    res.json({ transactionId: id, statut: 'en_attente' });
  }),
);

router.get(
  '/payments/mine',
  requireAuth,
  asyncHandler(async (req, res) => {
    const result = await pool.query(
      'SELECT * FROM transactions WHERE user_id = $1 ORDER BY created_at DESC',
      [req.user.id],
    );
    res.json(result.rows.map(serializeTransaction));
  }),
);

// ============================================================================
// MODULE 10 — NOTIFICATIONS
// ============================================================================

async function notifyUser(userId, type, titre, message, data) {
  const id = crypto.randomUUID();
  await pool.query(
    `INSERT INTO notifications (id, user_id, type, titre, message, data) VALUES ($1,$2,$3,$4,$5,$6)`,
    [id, userId, type, titre, message, data ? JSON.stringify(data) : null],
  );

  // Envoi push réel — ne bloque jamais l'appelant si ça échoue (best-effort)
  if (firebaseMessaging) {
    try {
      const tokens = (
        await pool.query('SELECT fcm_token FROM push_tokens WHERE user_id = $1', [userId])
      ).rows.map((r) => r.fcm_token);

      if (tokens.length > 0) {
        await firebaseMessaging.sendEachForMulticast({
          tokens,
          notification: { title: titre, body: message },
          data: data
            ? Object.fromEntries(Object.entries(data).map(([k, v]) => [k, String(v)]))
            : undefined,
        });
      }
    } catch (err) {
      console.error('[Push] Échec envoi notification :', err.message);
    }
  }
}

router.post(
  '/notifications/register-token',
  requireAuth,
  asyncHandler(async (req, res) => {
    const { fcmToken } = req.body;
    if (!fcmToken) return res.status(400).json({ message: 'fcmToken requis.' });
    await pool.query(
      `INSERT INTO push_tokens (id, user_id, fcm_token) VALUES ($1,$2,$3)
       ON CONFLICT (fcm_token) DO UPDATE SET user_id = $2`,
      [crypto.randomUUID(), req.user.id, fcmToken],
    );
    res.json({ message: 'Token enregistré.' });
  }),
);

router.get(
  '/notifications',
  requireAuth,
  asyncHandler(async (req, res) => {
    const { page, limit, offset } = paginationParams(req);
    const total = Number(
      (await pool.query('SELECT COUNT(*) FROM notifications WHERE user_id = $1', [req.user.id]))
        .rows[0].count,
    );
    const result = await pool.query(
      'SELECT * FROM notifications WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3',
      [req.user.id, limit, offset],
    );
    const mapper = (r) => ({
      id: r.id,
      type: r.type,
      titre: r.titre,
      message: r.message,
      lu: r.lu,
      data: r.data,
      createdAt: r.created_at,
    });
    res.json(paginatedResponse(result.rows, mapper, page, limit, total));
  }),
);

router.patch(
  '/notifications/:id/read',
  requireAuth,
  asyncHandler(async (req, res) => {
    await pool.query('UPDATE notifications SET lu = true WHERE id = $1', [req.params.id]);
    res.json({ message: 'Notification marquée comme lue.' });
  }),
);

// ============================================================================
// MODULE 8 — STATISTIQUES & ANALYTICS
// ============================================================================

function groupByMonth(rows, dateField, sumField) {
  const map = new Map();
  for (const row of rows) {
    const d = new Date(row[dateField]);
    const key = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`;
    map.set(key, (map.get(key) || 0) + Number(row[sumField] || 0));
  }
  return Array.from(map.entries())
    .map(([mois, total]) => ({ mois, total }))
    .sort((a, b) => a.mois.localeCompare(b.mois));
}

router.get(
  '/stats/agriculteur',
  requireAuth,
  requireRole('agriculteur'),
  asyncHandler(async (req, res) => {
    const cultures = (
      await pool.query('SELECT * FROM cultures WHERE agriculteur_id = $1', [req.user.id])
    ).rows;

    const parCultureMap = new Map();
    for (const c of cultures) {
      const key = c.type_culture;
      if (!parCultureMap.has(key)) {
        parCultureMap.set(key, { typeCulture: key, produitKg: 0, perduKg: 0, parcelles: 0 });
      }
      const entry = parCultureMap.get(key);
      entry.produitKg += Number(c.quantite_produite_kg || 0);
      entry.perduKg += Number(c.quantite_perdue_kg || 0);
      entry.parcelles += 1;
    }

    const products = (
      await pool.query('SELECT * FROM products WHERE agriculteur_id = $1', [req.user.id])
    ).rows;
    const totalPublies = products.filter((p) => p.statut === 'Publié').length;
    const totalEpuises = products.filter((p) => p.statut === 'Épuisé').length;

    const revenusTx = (
      await pool.query(
        `SELECT * FROM transactions WHERE user_id = $1 AND statut = 'reussi'`,
        [req.user.id],
      )
    ).rows;
    const revenuTotalFcfa = revenusTx.reduce((s, t) => s + t.montant_fcfa, 0);

    res.json({
      rendementsParCulture: Array.from(parCultureMap.values()),
      totalCultures: cultures.length,
      produitsPublies: totalPublies,
      tauxVente: products.length > 0 ? (totalEpuises / products.length) * 100 : 0,
      revenuTotalFcfa,
      revenuParMois: groupByMonth(revenusTx, 'created_at', 'montant_fcfa'),
    });
  }),
);

router.get(
  '/stats/acheteur',
  requireAuth,
  requireRole('acheteur', 'restaurant'),
  asyncHandler(async (req, res) => {
    const missions = (
      await pool.query('SELECT * FROM transport_missions WHERE acheteur_id = $1', [req.user.id])
    ).rows;
    const txs = (
      await pool.query(`SELECT * FROM transactions WHERE user_id = $1 AND statut = 'reussi'`, [
        req.user.id,
      ])
    ).rows;
    res.json({
      totalCommandes: missions.length,
      livraisonsLivrees: missions.filter((m) => m.statut === 'Livrée').length,
      depensesTotalFcfa: txs.reduce((s, t) => s + t.montant_fcfa, 0),
      depensesParMois: groupByMonth(txs, 'created_at', 'montant_fcfa'),
    });
  }),
);

router.get(
  '/stats/agronome',
  requireAuth,
  requireRole('agronome'),
  asyncHandler(async (req, res) => {
    const certs = (
      await pool.query('SELECT * FROM certifications WHERE agronome_id = $1', [req.user.id])
    ).rows;
    const validees = certs.filter((c) => c.statut === 'Validée').length;
    const rejetees = certs.filter((c) => c.statut === 'Rejetée').length;
    const traitees = validees + rejetees;
    res.json({
      totalInspections: certs.length,
      validees,
      rejetees,
      tauxValidation: traitees > 0 ? (validees / traitees) * 100 : 0,
    });
  }),
);

router.get(
  '/stats/transporteur',
  requireAuth,
  requireRole('transporteur'),
  asyncHandler(async (req, res) => {
    const missions = (
      await pool.query('SELECT * FROM transport_missions WHERE transporteur_id = $1', [
        req.user.id,
      ])
    ).rows;
    const livrees = missions.filter((m) => m.statut === 'Livrée');
    const notes = livrees.map((m) => Number(m.note_transporteur)).filter((n) => n > 0);
    res.json({
      totalMissions: missions.length,
      missionsLivrees: livrees.length,
      noteMoyenne: notes.length > 0 ? notes.reduce((s, n) => s + n, 0) / notes.length : null,
    });
  }),
);

router.get(
  '/stats/admin',
  requireAuth,
  requireRole('admin'),
  asyncHandler(async (req, res) => {
    const totalUsers = (await pool.query('SELECT COUNT(*) FROM users')).rows[0].count;
    const totalCultures = (await pool.query('SELECT COUNT(*) FROM cultures')).rows[0].count;
    const totalProducts = (await pool.query('SELECT COUNT(*) FROM products')).rows[0].count;
    const totalMissions = (await pool.query('SELECT COUNT(*) FROM transport_missions')).rows[0]
      .count;
    const usersByRole = (
      await pool.query('SELECT role, COUNT(*) FROM users GROUP BY role')
    ).rows;
    const productsByRegion = (
      await pool.query('SELECT region, COUNT(*) FROM products GROUP BY region')
    ).rows;
    const volume = (
      await pool.query(`SELECT COALESCE(SUM(montant_fcfa),0) as total FROM transactions WHERE statut = 'reussi'`)
    ).rows[0].total;

    res.json({
      totalUsers: Number(totalUsers),
      usersByRole,
      totalCultures: Number(totalCultures),
      totalProducts: Number(totalProducts),
      productsByRegion,
      totalMissions: Number(totalMissions),
      volumeTransactionsFcfa: Number(volume),
    });
  }),
);

// ============================================================================
// MODULE 12 — ADMINISTRATION
// ============================================================================

router.get(
  '/admin/dashboard',
  requireAuth,
  requireRole('admin'),
  asyncHandler(async (req, res) => {
    const totalUsers = Number((await pool.query('SELECT COUNT(*) FROM users')).rows[0].count);
    const activeUsers = Number(
      (await pool.query('SELECT COUNT(*) FROM users WHERE is_active = true')).rows[0].count,
    );
    const totalProducts = Number(
      (await pool.query('SELECT COUNT(*) FROM products')).rows[0].count,
    );
    const publishedProducts = Number(
      (await pool.query(`SELECT COUNT(*) FROM products WHERE statut = 'Publié'`)).rows[0].count,
    );
    const missionsEnCours = Number(
      (
        await pool.query(
          `SELECT COUNT(*) FROM transport_missions WHERE statut IN ('Acceptée','En route')`,
        )
      ).rows[0].count,
    );
    const transactionsReussies = Number(
      (await pool.query(`SELECT COUNT(*) FROM transactions WHERE statut = 'reussi'`)).rows[0]
        .count,
    );
    res.json({
      totalUsers,
      activeUsers,
      totalProducts,
      publishedProducts,
      missionsEnCours,
      transactionsReussies,
    });
  }),
);

router.get(
  '/admin/users',
  requireAuth,
  requireRole('admin'),
  asyncHandler(async (req, res) => {
    const { page, limit, offset } = paginationParams(req);
    const total = Number((await pool.query('SELECT COUNT(*) FROM users')).rows[0].count);
    const result = await pool.query(
      'SELECT * FROM users ORDER BY created_at DESC LIMIT $1 OFFSET $2',
      [limit, offset],
    );
    res.json(paginatedResponse(result.rows, serializeUser, page, limit, total));
  }),
);

router.patch(
  '/admin/users/:id/deactivate',
  requireAuth,
  requireRole('admin'),
  asyncHandler(async (req, res) => {
    await pool.query('UPDATE users SET is_active = false WHERE id = $1', [req.params.id]);
    res.json({ message: 'Compte désactivé.' });
  }),
);

router.patch(
  '/admin/users/:id/reactivate',
  requireAuth,
  requireRole('admin'),
  asyncHandler(async (req, res) => {
    await pool.query('UPDATE users SET is_active = true WHERE id = $1', [req.params.id]);
    res.json({ message: 'Compte réactivé.' });
  }),
);

router.get(
  '/admin/products/pending',
  requireAuth,
  requireRole('admin'),
  asyncHandler(async (req, res) => {
    const result = await pool.query(
      `SELECT * FROM products WHERE statut = 'En attente de validation' ORDER BY created_at ASC`,
    );
    res.json(result.rows.map(serializeProduct));
  }),
);

router.patch(
  '/admin/products/:id/moderate',
  requireAuth,
  requireRole('admin'),
  asyncHandler(async (req, res) => {
    const { action } = req.body; // 'approve' | 'reject'
    const statut = action === 'approve' ? 'Publié' : 'Rejeté';
    await pool.query('UPDATE products SET statut = $1, updated_at = now() WHERE id = $2', [
      statut,
      req.params.id,
    ]);
    res.json({ message: `Produit ${action === 'approve' ? 'approuvé' : 'rejeté'}.` });
  }),
);

router.get(
  '/admin/transactions',
  requireAuth,
  requireRole('admin'),
  asyncHandler(async (req, res) => {
    const { page, limit, offset } = paginationParams(req);
    const total = Number((await pool.query('SELECT COUNT(*) FROM transactions')).rows[0].count);
    const result = await pool.query(
      'SELECT * FROM transactions ORDER BY created_at DESC LIMIT $1 OFFSET $2',
      [limit, offset],
    );
    res.json(paginatedResponse(result.rows, serializeTransaction, page, limit, total));
  }),
);

// ============================================================================
// GESTION D'ERREUR GLOBALE
// ============================================================================

router.use((err, req, res, next) => {
  console.error(`[Erreur] ${req.method} ${req.originalUrl} ->`, err.message);
  res.status(err.status || 500).json({
    statusCode: err.status || 500,
    timestamp: new Date().toISOString(),
    path: req.originalUrl,
    message: err.message || 'Erreur interne du serveur',
  });
});

// ============================================================================
// SANTE DU SERVICE (monitoring Render, uptime checks)
// ============================================================================

app.get('/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({
      status: 'ok',
      database: 'connected',
      redis: redisClient ? 'configured' : 'fallback_memoire',
      geminiConfigured: !!GEMINI_API_KEY,
      uptime: process.uptime(),
    });
  } catch (err) {
    res.status(503).json({ status: 'error', database: 'unreachable', message: err.message });
  }
});

// ============================================================================
// SOCKET.IO — TRACKING GPS TEMPS REEL (Module 6 + 11)
// ============================================================================

const httpServer = http.createServer(app);
const io = new SocketIOServer(httpServer, {
  cors: { origin: '*' },
  path: '/tracking/socket.io',
});

io.on('connection', (socket) => {
  console.log(`[Socket.io] Client connecté : ${socket.id}`);

  socket.on('joinMission', (missionId) => {
    socket.join(`mission:${missionId}`);
    socket.emit('joinedMission', { missionId });
  });

  // Fréquence recommandée côté mobile : toutes les 5 secondes
  socket.on('positionUpdate', async ({ missionId, lat, lng }) => {
    try {
      const existing = await pool.query('SELECT statut FROM transport_missions WHERE id = $1', [
        missionId,
      ]);
      if (!existing.rows[0]) return;

      const nouveauStatut = existing.rows[0].statut === 'Acceptée' ? 'En route' : existing.rows[0].statut;

      await pool.query(
        `UPDATE transport_missions SET position_actuelle_lat = $1, position_actuelle_lng = $2, statut = $3, updated_at = now() WHERE id = $4`,
        [lat, lng, nouveauStatut, missionId],
      );

      io.to(`mission:${missionId}`).emit('positionUpdated', {
        missionId,
        lat,
        lng,
        statut: nouveauStatut,
        timestamp: new Date().toISOString(),
      });
    } catch (err) {
      console.error('[Socket.io] Erreur positionUpdate :', err.message);
    }
  });

  socket.on('missionArrived', async (missionId) => {
    await pool.query(
      `UPDATE transport_missions SET statut = 'Arrivée', updated_at = now() WHERE id = $1`,
      [missionId],
    );
    io.to(`mission:${missionId}`).emit('statusChanged', { missionId, statut: 'Arrivée' });
  });

  socket.on('missionDelivered', async ({ missionId, note }) => {
    const result = await pool.query(
      `UPDATE transport_missions SET statut = 'Livrée', note_transporteur = COALESCE($1, note_transporteur), updated_at = now() WHERE id = $2 RETURNING acheteur_id`,
      [note || null, missionId],
    );
    io.to(`mission:${missionId}`).emit('statusChanged', { missionId, statut: 'Livrée' });

    if (result.rows[0]) {
      await notifyUser(
        result.rows[0].acheteur_id,
        'livraison_arrivee',
        'Livraison effectuée',
        'Votre commande a été livrée avec succès.',
        { missionId },
      );
    }
  });

  socket.on('disconnect', () => {
    console.log(`[Socket.io] Client déconnecté : ${socket.id}`);
  });
});

// ============================================================================
// DEMARRAGE
// ============================================================================

validateStartupConfig();

initDatabase()
  .then(() => {
    httpServer.listen(PORT, () => {
      console.log(`Difa backend démarré sur le port ${PORT}`);
      console.log(`API : http://localhost:${PORT}/api/v1`);
      console.log(`Santé : http://localhost:${PORT}/health`);
      console.log(`Tracking GPS (Socket.io) : ws://localhost:${PORT}/tracking/socket.io`);
    });
  })
  .catch((err) => {
    console.error('[DB] Échec de connexion à PostgreSQL :', err.message);
    process.exit(1);
  });

// Arrêt propre : ferme les connexions actives avant de quitter, pour éviter
// les requêtes coupées en plein milieu lors des redéploiements Render.
function shutdown(signal) {
  console.log(`\n[${signal}] Arrêt en cours...`);
  httpServer.close(() => {
    console.log('Serveur HTTP fermé.');
    pool.end().then(() => {
      console.log('Connexions PostgreSQL fermées.');
      process.exit(0);
    });
  });
  // Sécurité : force l'arrêt si ça traîne plus de 10s
  setTimeout(() => process.exit(1), 10000).unref();
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

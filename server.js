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
  try {
    const admin = require('firebase-admin');
    // Render stocke souvent les \n en texte : on les reconvertit en vrais sauts de ligne
    let privateKey = process.env.FIREBASE_PRIVATE_KEY;
    if (privateKey.startsWith('"') && privateKey.endsWith('"')) {
      privateKey = privateKey.slice(1, -1);
    }
    privateKey = privateKey.replace(/\\n/g, '\n');
    admin.initializeApp({
      credential: admin.credential.cert({
        projectId: process.env.FIREBASE_PROJECT_ID,
        clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
        privateKey,
      }),
    });
    firebaseMessaging = admin.messaging();
    console.log('[Firebase] Admin initialisé — push activé.');
  } catch (err) {
    console.error('[Firebase] Init échouée :', err.message);
    firebaseMessaging = null;
  }
} else {
  console.log('[Firebase] Variables manquantes — notifications in-app seulement.');
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
const GEMINI_MODEL = process.env.GEMINI_MODEL || 'gemini-flash-latest';

/** Rotation de clés Gemini (comme ESP32) — GEMINI_API_KEYS ou GEMINI_API_KEY(_2.._5) */
function loadGeminiKeys() {
  const keys = [];
  if (process.env.GEMINI_API_KEYS) {
    process.env.GEMINI_API_KEYS.split(/[,;\s]+/)
      .map((k) => k.trim())
      .filter(Boolean)
      .forEach((k) => keys.push(k));
  }
  for (const name of [
    'GEMINI_API_KEY',
    'GEMINI_API_KEY_1',
    'GEMINI_API_KEY_2',
    'GEMINI_API_KEY_3',
    'GEMINI_API_KEY_4',
    'GEMINI_API_KEY_5',
  ]) {
    const v = process.env[name];
    if (v && v.trim() && !keys.includes(v.trim())) keys.push(v.trim());
  }
  return keys;
}
const GEMINI_API_KEYS = loadGeminiKeys();
let geminiKeyIndex = 0;

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
  if (GEMINI_API_KEYS.length === 0) {
    problems.push('Aucune clé Gemini (GEMINI_API_KEY ou GEMINI_API_KEYS) — le chatbot ne fonctionnera pas.');
  } else {
    console.log(`[Config] ${GEMINI_API_KEYS.length} clé(s) Gemini chargée(s) (rotation active).`);
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

const useSsl = process.env.DB_SSL != null
  ? process.env.DB_SSL === 'true'
  : !!process.env.DATABASE_URL;

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
  // Colonne langue préférée (notifications traduites)
  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS preferred_language TEXT DEFAULT 'fr'
  `);

  // Module 2 — profils enrichis + KYC + notation
  await pool.query(`
    ALTER TABLE users ADD COLUMN IF NOT EXISTS note_moyenne NUMERIC(2,1) DEFAULT 5.0;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS localisation_lat NUMERIC(9,6);
    ALTER TABLE users ADD COLUMN IF NOT EXISTS localisation_lng NUMERIC(9,6);
    ALTER TABLE users ADD COLUMN IF NOT EXISTS kyc_statut TEXT DEFAULT 'non_soumis'
      CHECK (kyc_statut IN ('non_soumis','en_attente','valide','rejete'));
    ALTER TABLE users ADD COLUMN IF NOT EXISTS kyc_documents JSONB;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS specialites TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS diplomes TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS zone_intervention TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS type_activite TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS volume_habituel TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS type_etablissement TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS vehicule_type TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS vehicule_immat TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS zone_couverture TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS derniere_connexion TIMESTAMPTZ;
  `);

  // Module 4 — commandes marketplace
  await pool.query(`
    CREATE TABLE IF NOT EXISTS orders (
      id UUID PRIMARY KEY,
      acheteur_id UUID REFERENCES users(id) ON DELETE CASCADE,
      product_id UUID REFERENCES products(id),
      agriculteur_id UUID REFERENCES users(id),
      quantite NUMERIC(10,2) NOT NULL,
      prix_unitaire_fcfa INTEGER NOT NULL,
      montant_total_fcfa INTEGER NOT NULL,
      commission_fcfa INTEGER DEFAULT 0,
      statut TEXT DEFAULT 'en_attente_paiement'
        CHECK (statut IN (
          'en_attente_paiement','paye','confirme','en_livraison','livre','annule','refuse'
        )),
      adresse_livraison TEXT,
      destination_lat NUMERIC(9,6),
      destination_lng NUMERIC(9,6),
      notes TEXT,
      created_at TIMESTAMPTZ DEFAULT now(),
      updated_at TIMESTAMPTZ DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS favorites (
      id UUID PRIMARY KEY,
      user_id UUID REFERENCES users(id) ON DELETE CASCADE,
      product_id UUID REFERENCES products(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ DEFAULT now(),
      UNIQUE(user_id, product_id)
    );
  `);

  // Module 9 — portefeuille interne
  await pool.query(`
    CREATE TABLE IF NOT EXISTS wallets (
      user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      solde_fcfa INTEGER NOT NULL DEFAULT 0,
      updated_at TIMESTAMPTZ DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS wallet_transactions (
      id UUID PRIMARY KEY,
      user_id UUID REFERENCES users(id) ON DELETE CASCADE,
      type TEXT NOT NULL CHECK (type IN ('credit','debit')),
      montant_fcfa INTEGER NOT NULL,
      motif TEXT,
      reference_id TEXT,
      created_at TIMESTAMPTZ DEFAULT now()
    );
  `);

  // Migration : anciennes bases où reference_id était UUID (casse retraits, Paystack, Flutterwave)
  await pool.query(`
    DO $$
    BEGIN
      IF (SELECT data_type FROM information_schema.columns
          WHERE table_name = 'wallet_transactions' AND column_name = 'reference_id') = 'uuid' THEN
        ALTER TABLE wallet_transactions ALTER COLUMN reference_id TYPE TEXT USING reference_id::text;
      END IF;
    END $$;
  `);
  // Un crédit ne peut exister qu'une fois par référence (anti double-crédit webhook)
  try {
    await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS ux_wallet_credit_ref
      ON wallet_transactions (reference_id) WHERE type = 'credit' AND reference_id IS NOT NULL`);
  } catch (e) { console.warn('[DB] index crédit unique:', e.message); }

  // Module 3 — alertes agricoles / calendrier
  await pool.query(`
    CREATE TABLE IF NOT EXISTS agricultural_alerts (
      id UUID PRIMARY KEY,
      user_id UUID REFERENCES users(id) ON DELETE CASCADE,
      culture_id UUID REFERENCES cultures(id) ON DELETE CASCADE,
      type_alerte TEXT NOT NULL,
      titre TEXT NOT NULL,
      message TEXT NOT NULL,
      date_prevue DATE,
      lu BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMPTZ DEFAULT now()
    );
  `);

  // Module 12 — litiges + config plateforme
  await pool.query(`
    CREATE TABLE IF NOT EXISTS disputes (
      id UUID PRIMARY KEY,
      order_id UUID REFERENCES orders(id),
      ouvre_par UUID REFERENCES users(id),
      contre UUID REFERENCES users(id),
      motif TEXT NOT NULL,
      description TEXT,
      statut TEXT DEFAULT 'ouvert' CHECK (statut IN ('ouvert','en_cours','resolu','rejete')),
      resolution TEXT,
      created_at TIMESTAMPTZ DEFAULT now(),
      updated_at TIMESTAMPTZ DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS platform_config (
      cle TEXT PRIMARY KEY,
      valeur TEXT NOT NULL,
      updated_at TIMESTAMPTZ DEFAULT now()
    );
  `);

  // Config par défaut commissions
  await pool.query(`
    INSERT INTO platform_config (cle, valeur) VALUES
      ('commission_vente_pct', '5'),
      ('commission_transport_pct', '10'),
      ('matching_rayon_km', '50'),
      ('transport_base_fcfa', '500'),
      ('transport_km_fcfa', '150'),
      ('transport_speed_kmh', '30'),
      ('offer_timeout_seconds', '60')
    ON CONFLICT (cle) DO NOTHING
  `);

  // Numéros pré-autorisés à s'inscrire en tant qu'admin (max 5 admins au total)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS admin_allowed_phones (
      phone TEXT PRIMARY KEY,
      created_at TIMESTAMPTZ DEFAULT now(),
      used_at TIMESTAMPTZ
    );
  `);

  // Enrichir transport_missions
  await pool.query(`
    ALTER TABLE transport_missions ADD COLUMN IF NOT EXISTS order_id UUID;
    ALTER TABLE transport_missions ADD COLUMN IF NOT EXISTS note_commentaire TEXT;
    ALTER TABLE transport_missions ADD COLUMN IF NOT EXISTS distance_km NUMERIC(10,2);
    ALTER TABLE transport_missions ADD COLUMN IF NOT EXISTS eta_minutes INTEGER;
    ALTER TABLE transport_missions ADD COLUMN IF NOT EXISTS prix_transport_fcfa INTEGER;
    ALTER TABLE transport_missions ADD COLUMN IF NOT EXISTS offered_to UUID;
    ALTER TABLE transport_missions ADD COLUMN IF NOT EXISTS offered_at TIMESTAMPTZ;
    ALTER TABLE transport_missions ADD COLUMN IF NOT EXISTS tried_ids JSONB DEFAULT '[]'::jsonb;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS disponible BOOLEAN DEFAULT false;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS country TEXT DEFAULT 'TG';
    ALTER TABLE users ADD COLUMN IF NOT EXISTS devise TEXT DEFAULT 'XOF';
    ALTER TABLE products ADD COLUMN IF NOT EXISTS devise TEXT DEFAULT 'XOF';
    ALTER TABLE users ADD COLUMN IF NOT EXISTS position_updated_at TIMESTAMPTZ;
  `);

  // Élargir les statuts mission (paiement transport avant départ)
  try {
    await pool.query(`ALTER TABLE transport_missions DROP CONSTRAINT IF EXISTS transport_missions_statut_check`);
    await pool.query(`ALTER TABLE transport_missions ADD CONSTRAINT transport_missions_statut_check
      CHECK (statut IN (
        'En attente de transporteur','Acceptée','En attente paiement transport',
        'Transport payé','En route','Arrivée','Livrée','Annulée','Refusée par acheteur'
      ))`);
  } catch (e) { console.warn('[DB] statut mission:', e.message); }

  // Enrichir transactions
  await pool.query(`
    ALTER TABLE transactions ADD COLUMN IF NOT EXISTS operateur TEXT;
    ALTER TABLE transactions ADD COLUMN IF NOT EXISTS telephone_paiement TEXT;
  `);

  console.log('[DB] Tables prêtes (12 modules).');
}

// ============================================================================
// HELPERS — OTP (Redis ou fallback mémoire)
// ============================================================================

function generateOtpCode() {
  return crypto.randomInt(100000, 1000000).toString();
}

// Anti brute-force OTP : 5 essais max par numéro, puis le code est invalidé
const otpAttempts = new Map(); // clé -> { count, resetAt }
const OTP_MAX_ATTEMPTS = 5;
function otpAttemptsExceeded(key) {
  const e = otpAttempts.get(key);
  if (!e || e.resetAt < Date.now()) return false;
  return e.count >= OTP_MAX_ATTEMPTS;
}
function otpRegisterFailure(key) {
  const e = otpAttempts.get(key);
  if (!e || e.resetAt < Date.now()) {
    otpAttempts.set(key, { count: 1, resetAt: Date.now() + OTP_TTL_SECONDS * 1000 });
  } else {
    e.count += 1;
  }
}

/** Normalise le numéro pour éviter les mismatch +233 / 233 / espaces */
function normalizePhone(phone) {
  return String(phone || '').replace(/\s+/g, '').replace(/^\+/, '');
}

async function storeOtp(phone, code) {
  const key = normalizePhone(phone);
  otpAttempts.delete(key);
  if (redisClient) {
    await redisClient.set(`otp:${key}`, code, 'EX', OTP_TTL_SECONDS);
  } else {
    memoryOtpStore.set(key, { code, expiresAt: Date.now() + OTP_TTL_SECONDS * 1000 });
  }
}

async function verifyAndConsumeOtp(phone, code) {
  const key = normalizePhone(phone);
  if (otpAttemptsExceeded(key)) {
    // trop d'essais : on détruit le code, il faut en redemander un
    if (redisClient) await redisClient.del(`otp:${key}`);
    else memoryOtpStore.delete(key);
    return false;
  }
  if (redisClient) {
    const stored = await redisClient.get(`otp:${key}`);
    if (!stored || stored !== String(code).trim()) { otpRegisterFailure(key); return false; }
    await redisClient.del(`otp:${key}`);
    otpAttempts.delete(key);
    return true;
  }
  const entry = memoryOtpStore.get(key);
  if (!entry || entry.expiresAt < Date.now() || entry.code !== String(code).trim()) {
    otpRegisterFailure(key);
    return false;
  }
  memoryOtpStore.delete(key);
  otpAttempts.delete(key);
  return true;
}

/** Langue demandée → langue utilisable pour SMS / messages (ee, kbp → fr ; ha, yo → en). */
function baseLang(lang) {
  const c = String(lang || 'fr').split(/[-_,;]/)[0].trim().toLowerCase();
  if (['fr', 'en', 'es', 'pt', 'ar', 'zh'].includes(c)) return c;
  if (c === 'ha' || c === 'yo') return 'en';
  return 'fr';
}

const OTP_SMS_TEXT = {
  fr: (c) => `Votre code Difa est ${c}. Il expire dans 5 minutes.`,
  en: (c) => `Your Difa code is ${c}. It expires in 5 minutes.`,
  es: (c) => `Su código Difa es ${c}. Caduca en 5 minutos.`,
  pt: (c) => `O seu código Difa é ${c}. Expira em 5 minutos.`,
  ar: (c) => `رمز ديفا الخاص بك هو ${c}. ينتهي خلال 5 دقائق.`,
  zh: (c) => `您的 Difa 验证码是 ${c}，5 分钟内有效。`,
};

async function sendOtpSms(phone, code, lang) {
  // Le code n'est journalisé qu'hors production (les logs Render sont lisibles par l'équipe)
  if (process.env.NODE_ENV !== 'production') console.log(`[OTP] Code pour ${phone} : ${code}`);

  const vonageKey = process.env.VONAGE_API_KEY;
  const vonageSecret = process.env.VONAGE_API_SECRET;
  const vonageFrom = process.env.VONAGE_FROM || 'DIFA';
  if (!vonageKey || !vonageSecret) {
    console.warn('[OTP] VONAGE_API_KEY / VONAGE_API_SECRET manquants : aucun SMS envoyé.');
    return false;
  }
  const text = (OTP_SMS_TEXT[baseLang(lang)] || OTP_SMS_TEXT.fr)(code);
  try {
    const resp = await axios.post(
      'https://rest.nexmo.com/sms/json',
      {
        api_key: vonageKey,
        api_secret: vonageSecret,
        to: String(phone).replace(/[^\d]/g, ''), // Vonage : chiffres uniquement, sans +
        from: vonageFrom,
        text,
        type: /^[\x00-\x7F]*$/.test(text) ? 'text' : 'unicode',
      },
      { headers: { 'Content-Type': 'application/json' }, timeout: 15000 },
    );
    // Vonage répond HTTP 200 même en cas d'échec : il faut lire messages[0].status ("0" = OK)
    const m = resp.data?.messages?.[0];
    if (m && String(m.status) === '0') {
      console.log(`[OTP] SMS Vonage envoyé à ${phone}`);
      return true;
    }
    console.error('[OTP] Vonage a refusé le SMS :', m?.status, m?.['error-text'] || JSON.stringify(resp.data));
    return false;
  } catch (err) {
    console.error('[OTP] Échec envoi SMS Vonage :', err.response?.data || err.message);
    return false;
  }
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

// ============================================================================
// TRADUCTION DES MESSAGES D'ERREUR / SUCCÈS DE L'API (selon l'en-tête Accept-Language)
// L'app envoie la langue choisie ; ee et kbp reçoivent le français, ha et yo l'anglais.
// ============================================================================
const API_MESSAGES = {
 "Accès refusé.": {
  "en": "Access denied.",
  "es": "Acceso denegado.",
  "pt": "Acesso negado.",
  "ar": "تم رفض الوصول.",
  "zh": "访问被拒绝。"
 },
 "Identifiants incorrects.": {
  "en": "Incorrect credentials.",
  "es": "Credenciales incorrectas.",
  "pt": "Credenciais incorretas.",
  "ar": "بيانات الدخول غير صحيحة.",
  "zh": "账号或密码错误。"
 },
 "Champs requis manquants.": {
  "en": "Required fields are missing.",
  "es": "Faltan campos obligatorios.",
  "pt": "Campos obrigatórios em falta.",
  "ar": "هناك حقول مطلوبة مفقودة.",
  "zh": "缺少必填项。"
 },
 "Code OTP invalide ou expiré.": {
  "en": "Invalid or expired OTP code.",
  "es": "Código OTP inválido o caducado.",
  "pt": "Código OTP inválido ou expirado.",
  "ar": "رمز التحقق غير صالح أو منتهي.",
  "zh": "验证码无效或已过期。"
 },
 "Un compte existe déjà avec ce numéro.": {
  "en": "An account already exists with this number.",
  "es": "Ya existe una cuenta con este número.",
  "pt": "Já existe uma conta com este número.",
  "ar": "يوجد حساب بهذا الرقم بالفعل.",
  "zh": "该号码已注册账号。"
 },
 "Le mot de passe doit contenir au moins 6 caractères.": {
  "en": "Password must be at least 6 characters.",
  "es": "La contraseña debe tener al menos 6 caracteres.",
  "pt": "A palavra-passe deve ter pelo menos 6 caracteres.",
  "ar": "يجب أن تتكون كلمة المرور من 6 أحرف على الأقل.",
  "zh": "密码至少需要 6 个字符。"
 },
 "Numéro non vérifié. Vérifiez votre OTP.": {
  "en": "Number not verified. Please check your OTP.",
  "es": "Número no verificado. Verifique su OTP.",
  "pt": "Número não verificado. Verifique o seu OTP.",
  "ar": "الرقم غير موثّق. تحقق من رمز OTP.",
  "zh": "号码未验证，请检查验证码。"
 },
 "Compte désactivé. Contactez le support.": {
  "en": "Account disabled. Contact support.",
  "es": "Cuenta desactivada. Contacte con soporte.",
  "pt": "Conta desativada. Contacte o suporte.",
  "ar": "تم تعطيل الحساب. تواصل مع الدعم.",
  "zh": "账号已停用，请联系客服。"
 },
 "Compte introuvable.": {
  "en": "Account not found.",
  "es": "Cuenta no encontrada.",
  "pt": "Conta não encontrada.",
  "ar": "الحساب غير موجود.",
  "zh": "未找到账号。"
 },
 "Utilisateur introuvable.": {
  "en": "User not found.",
  "es": "Usuario no encontrado.",
  "pt": "Utilizador não encontrado.",
  "ar": "المستخدم غير موجود.",
  "zh": "未找到用户。"
 },
 "5 tentatives échouées. Compte bloqué 15 minutes.": {
  "en": "5 failed attempts. Account locked for 15 minutes.",
  "es": "5 intentos fallidos. Cuenta bloqueada 15 minutos.",
  "pt": "5 tentativas falhadas. Conta bloqueada 15 minutos.",
  "ar": "5 محاولات فاشلة. تم قفل الحساب 15 دقيقة.",
  "zh": "失败 5 次，账号锁定 15 分钟。"
 },
 "Session expirée. Reconnectez-vous.": {
  "en": "Session expired. Please sign in again.",
  "es": "Sesión caducada. Vuelva a iniciar sesión.",
  "pt": "Sessão expirada. Inicie sessão novamente.",
  "ar": "انتهت الجلسة. سجّل الدخول من جديد.",
  "zh": "会话已过期，请重新登录。"
 },
 "Token manquant.": {
  "en": "Missing token.",
  "es": "Falta el token.",
  "pt": "Token em falta.",
  "ar": "الرمز مفقود.",
  "zh": "缺少令牌。"
 },
 "Token invalide ou expiré.": {
  "en": "Invalid or expired token.",
  "es": "Token inválido o caducado.",
  "pt": "Token inválido ou expirado.",
  "ar": "الرمز غير صالح أو منتهي.",
  "zh": "令牌无效或已过期。"
 },
 "Déconnexion réussie.": {
  "en": "Signed out successfully.",
  "es": "Sesión cerrada.",
  "pt": "Sessão terminada.",
  "ar": "تم تسجيل الخروج.",
  "zh": "已退出登录。"
 },
 "Mot de passe réinitialisé. Reconnectez-vous.": {
  "en": "Password reset. Please sign in again.",
  "es": "Contraseña restablecida. Inicie sesión de nuevo.",
  "pt": "Palavra-passe redefinida. Inicie sessão novamente.",
  "ar": "تمت إعادة تعيين كلمة المرور. سجّل الدخول من جديد.",
  "zh": "密码已重置，请重新登录。"
 },
 "Si ce numéro est enregistré, un code a été envoyé.": {
  "en": "If this number is registered, a code has been sent.",
  "es": "Si este número está registrado, se ha enviado un código.",
  "pt": "Se este número estiver registado, foi enviado um código.",
  "ar": "إذا كان هذا الرقم مسجلاً فقد تم إرسال رمز.",
  "zh": "如果该号码已注册，验证码已发送。"
 },
 "Produit introuvable.": {
  "en": "Product not found.",
  "es": "Producto no encontrado.",
  "pt": "Produto não encontrado.",
  "ar": "المنتج غير موجود.",
  "zh": "未找到产品。"
 },
 "Culture introuvable.": {
  "en": "Crop not found.",
  "es": "Cultivo no encontrado.",
  "pt": "Cultura não encontrada.",
  "ar": "المحصول غير موجود.",
  "zh": "未找到作物。"
 },
 "Commande introuvable.": {
  "en": "Order not found.",
  "es": "Pedido no encontrado.",
  "pt": "Encomenda não encontrada.",
  "ar": "الطلب غير موجود.",
  "zh": "未找到订单。"
 },
 "Mission introuvable.": {
  "en": "Mission not found.",
  "es": "Misión no encontrada.",
  "pt": "Missão não encontrada.",
  "ar": "المهمة غير موجودة.",
  "zh": "未找到任务。"
 },
 "Demande introuvable.": {
  "en": "Request not found.",
  "es": "Solicitud no encontrada.",
  "pt": "Pedido não encontrado.",
  "ar": "الطلب غير موجود.",
  "zh": "未找到请求。"
 },
 "Transaction introuvable.": {
  "en": "Transaction not found.",
  "es": "Transacción no encontrada.",
  "pt": "Transação não encontrada.",
  "ar": "المعاملة غير موجودة.",
  "zh": "未找到交易。"
 },
 "Identifiant invalide.": {
  "en": "Invalid identifier.",
  "es": "Identificador no válido.",
  "pt": "Identificador inválido.",
  "ar": "معرّف غير صالح.",
  "zh": "标识无效。"
 },
 "Ce produit ne vous appartient pas.": {
  "en": "This product does not belong to you.",
  "es": "Este producto no le pertenece.",
  "pt": "Este produto não lhe pertence.",
  "ar": "هذا المنتج ليس ملكك.",
  "zh": "该产品不属于您。"
 },
 "Cette culture ne vous appartient pas.": {
  "en": "This crop does not belong to you.",
  "es": "Este cultivo no le pertenece.",
  "pt": "Esta cultura não lhe pertence.",
  "ar": "هذا المحصول ليس ملكك.",
  "zh": "该作物不属于您。"
 },
 "Produit non disponible à la commande.": {
  "en": "Product not available for order.",
  "es": "Producto no disponible para pedido.",
  "pt": "Produto indisponível para encomenda.",
  "ar": "المنتج غير متاح للطلب.",
  "zh": "该产品暂不可下单。"
 },
 "Quantité insuffisante en stock.": {
  "en": "Insufficient stock.",
  "es": "Existencias insuficientes.",
  "pt": "Stock insuficiente.",
  "ar": "الكمية المتوفرة غير كافية.",
  "zh": "库存不足。"
 },
 "Vous ne pouvez pas commander votre propre produit.": {
  "en": "You cannot order your own product.",
  "es": "No puede pedir su propio producto.",
  "pt": "Não pode encomendar o seu próprio produto.",
  "ar": "لا يمكنك طلب منتجك الخاص.",
  "zh": "您不能购买自己的产品。"
 },
 "productId et quantite > 0 requis.": {
  "en": "productId and quantity > 0 are required.",
  "es": "Se requieren productId y cantidad > 0.",
  "pt": "productId e quantidade > 0 são obrigatórios.",
  "ar": "مطلوب productId وكمية أكبر من 0.",
  "zh": "需要 productId 和大于 0 的数量。"
 },
 "Commande annulée.": {
  "en": "Order cancelled.",
  "es": "Pedido cancelado.",
  "pt": "Encomenda cancelada.",
  "ar": "تم إلغاء الطلب.",
  "zh": "订单已取消。"
 },
 "Cette commande ne peut plus être annulée.": {
  "en": "This order can no longer be cancelled.",
  "es": "Este pedido ya no se puede cancelar.",
  "pt": "Esta encomenda já não pode ser cancelada.",
  "ar": "لا يمكن إلغاء هذا الطلب بعد الآن.",
  "zh": "该订单无法再取消。"
 },
 "Commande déjà payée : ouvrez un litige pour être remboursé.": {
  "en": "Order already paid: open a dispute to get a refund.",
  "es": "Pedido ya pagado: abra una disputa para obtener un reembolso.",
  "pt": "Encomenda já paga: abra um litígio para ser reembolsado.",
  "ar": "تم دفع الطلب: افتح نزاعاً لاسترداد المبلغ.",
  "zh": "订单已支付：请发起纠纷以申请退款。"
 },
 "Commande déjà traitée.": {
  "en": "Order already processed.",
  "es": "Pedido ya procesado.",
  "pt": "Encomenda já processada.",
  "ar": "تمت معالجة الطلب مسبقاً.",
  "zh": "订单已处理。"
 },
 "Cette commande ne peut plus être payée.": {
  "en": "This order can no longer be paid.",
  "es": "Este pedido ya no se puede pagar.",
  "pt": "Esta encomenda já não pode ser paga.",
  "ar": "لا يمكن دفع هذا الطلب بعد الآن.",
  "zh": "该订单无法再支付。"
 },
 "La commande doit être payée avant de confirmer la livraison.": {
  "en": "The order must be paid before confirming delivery.",
  "es": "El pedido debe pagarse antes de confirmar la entrega.",
  "pt": "A encomenda deve ser paga antes de confirmar a entrega.",
  "ar": "يجب دفع الطلب قبل تأكيد التسليم.",
  "zh": "确认收货前必须先支付订单。"
 },
 "La commande doit être payée avant le transport.": {
  "en": "The order must be paid before transport.",
  "es": "El pedido debe pagarse antes del transporte.",
  "pt": "A encomenda deve ser paga antes do transporte.",
  "ar": "يجب دفع الطلب قبل النقل.",
  "zh": "运输前必须先支付订单。"
 },
 "Livraison confirmée. Agriculteur crédité.": {
  "en": "Delivery confirmed. Farmer credited.",
  "es": "Entrega confirmada. Agricultor acreditado.",
  "pt": "Entrega confirmada. Agricultor creditado.",
  "ar": "تم تأكيد التسليم وتحويل المبلغ للمزارع.",
  "zh": "已确认收货，农户已入账。"
 },
 "Livraison déjà confirmée.": {
  "en": "Delivery already confirmed.",
  "es": "Entrega ya confirmada.",
  "pt": "Entrega já confirmada.",
  "ar": "تم تأكيد التسليم مسبقاً.",
  "zh": "已确认过收货。"
 },
 "Solde insuffisant.": {
  "en": "Insufficient balance.",
  "es": "Saldo insuficiente.",
  "pt": "Saldo insuficiente.",
  "ar": "الرصيد غير كافٍ.",
  "zh": "余额不足。"
 },
 "Solde portefeuille insuffisant.": {
  "en": "Insufficient wallet balance.",
  "es": "Saldo de la cartera insuficiente.",
  "pt": "Saldo da carteira insuficiente.",
  "ar": "رصيد المحفظة غير كافٍ.",
  "zh": "钱包余额不足。"
 },
 "Solde portefeuille insuffisant pour payer le transport.": {
  "en": "Insufficient wallet balance to pay for transport.",
  "es": "Saldo insuficiente para pagar el transporte.",
  "pt": "Saldo insuficiente para pagar o transporte.",
  "ar": "رصيد المحفظة غير كافٍ لدفع النقل.",
  "zh": "钱包余额不足以支付运费。"
 },
 "Paiement portefeuille réussi.": {
  "en": "Wallet payment successful.",
  "es": "Pago con cartera exitoso.",
  "pt": "Pagamento com carteira concluído.",
  "ar": "تم الدفع من المحفظة بنجاح.",
  "zh": "钱包支付成功。"
 },
 "Paiement confirmé.": {
  "en": "Payment confirmed.",
  "es": "Pago confirmado.",
  "pt": "Pagamento confirmado.",
  "ar": "تم تأكيد الدفع.",
  "zh": "支付已确认。"
 },
 "Montant invalide (min 100 FCFA).": {
  "en": "Invalid amount (min 100 FCFA).",
  "es": "Importe no válido (mín. 100 FCFA).",
  "pt": "Montante inválido (mín. 100 FCFA).",
  "ar": "مبلغ غير صالح (الحد الأدنى 100 فرنك).",
  "zh": "金额无效（最低 100 FCFA）。"
 },
 "Montant invalide (100 à 2 000 000 FCFA).": {
  "en": "Invalid amount (100 to 2,000,000 FCFA).",
  "es": "Importe no válido (100 a 2.000.000 FCFA).",
  "pt": "Montante inválido (100 a 2.000.000 FCFA).",
  "ar": "مبلغ غير صالح (من 100 إلى 2,000,000 فرنك).",
  "zh": "金额无效（100 至 2,000,000 FCFA）。"
 },
 "Montant minimum de retrait : 500 FCFA.": {
  "en": "Minimum withdrawal: 500 FCFA.",
  "es": "Retiro mínimo: 500 FCFA.",
  "pt": "Levantamento mínimo: 500 FCFA.",
  "ar": "الحد الأدنى للسحب: 500 فرنك.",
  "zh": "最低提现金额：500 FCFA。"
 },
 "provider invalide.": {
  "en": "Invalid provider.",
  "es": "Proveedor no válido.",
  "pt": "Fornecedor inválido.",
  "ar": "مزوّد غير صالح.",
  "zh": "服务商无效。"
 },
 "provider et destination (téléphone ou compte) requis.": {
  "en": "Provider and destination (phone or account) are required.",
  "es": "Se requieren proveedor y destino (teléfono o cuenta).",
  "pt": "Fornecedor e destino (telefone ou conta) são obrigatórios.",
  "ar": "مطلوب المزوّد والوجهة (هاتف أو حساب).",
  "zh": "需要服务商和收款方（手机号或账号）。"
 },
 "Réservé aux administrateurs.": {
  "en": "Reserved for administrators.",
  "es": "Reservado a administradores.",
  "pt": "Reservado a administradores.",
  "ar": "للمسؤولين فقط.",
  "zh": "仅限管理员。"
 },
 "Transaction déjà traitée.": {
  "en": "Transaction already processed.",
  "es": "Transacción ya procesada.",
  "pt": "Transação já processada.",
  "ar": "تمت معالجة المعاملة مسبقاً.",
  "zh": "交易已处理。"
 },
 "Cette mission a déjà été prise.": {
  "en": "This mission has already been taken.",
  "es": "Esta misión ya fue tomada.",
  "pt": "Esta missão já foi aceite.",
  "ar": "تم أخذ هذه المهمة مسبقاً.",
  "zh": "该任务已被接走。"
 },
 "Indiquez un prix de transport valide (minimum 100 FCFA).": {
  "en": "Enter a valid transport price (minimum 100 FCFA).",
  "es": "Indique un precio de transporte válido (mínimo 100 FCFA).",
  "pt": "Indique um preço de transporte válido (mínimo 100 FCFA).",
  "ar": "أدخل سعر نقل صالحاً (100 فرنك على الأقل).",
  "zh": "请输入有效的运费（至少 100 FCFA）。"
 },
 "Prix de transport invalide.": {
  "en": "Invalid transport price.",
  "es": "Precio de transporte no válido.",
  "pt": "Preço de transporte inválido.",
  "ar": "سعر النقل غير صالح.",
  "zh": "运费无效。"
 },
 "Cette mission n'attend pas un paiement transport.": {
  "en": "This mission is not awaiting transport payment.",
  "es": "Esta misión no espera pago de transporte.",
  "pt": "Esta missão não aguarda pagamento de transporte.",
  "ar": "هذه المهمة لا تنتظر دفع النقل.",
  "zh": "该任务当前无需支付运费。"
 },
 "Transport payé. Le transporteur peut démarrer.": {
  "en": "Transport paid. The transporter can start.",
  "es": "Transporte pagado. El transportista puede comenzar.",
  "pt": "Transporte pago. O transportador pode começar.",
  "ar": "تم دفع النقل. يمكن للناقل البدء.",
  "zh": "运费已支付，运输员可以出发。"
 },
 "Transport refusé. Organisez la récupération du produit par vos moyens.": {
  "en": "Transport refused. Arrange pickup of the product yourself.",
  "es": "Transporte rechazado. Organice usted mismo la recogida del producto.",
  "pt": "Transporte recusado. Organize você mesmo a recolha do produto.",
  "ar": "تم رفض النقل. رتّب استلام المنتج بنفسك.",
  "zh": "已拒绝运输，请自行安排取货。"
 },
 "Impossible de refuser cette mission maintenant.": {
  "en": "This mission cannot be refused right now.",
  "es": "No se puede rechazar esta misión ahora.",
  "pt": "Não é possível recusar esta missão agora.",
  "ar": "لا يمكن رفض هذه المهمة الآن.",
  "zh": "目前无法拒绝该任务。"
 },
 "Vous n'êtes pas le transporteur de cette mission.": {
  "en": "You are not the transporter of this mission.",
  "es": "No es el transportista de esta misión.",
  "pt": "Não é o transportador desta missão.",
  "ar": "لست ناقل هذه المهمة.",
  "zh": "您不是该任务的运输员。"
 },
 "Le transporteur ne peut démarrer qu'après le paiement du transport par l'acheteur.": {
  "en": "The transporter can only start after the buyer has paid for transport.",
  "es": "El transportista solo puede comenzar tras el pago del transporte por el comprador.",
  "pt": "O transportador só pode começar após o pagamento do transporte pelo comprador.",
  "ar": "لا يمكن للناقل البدء إلا بعد دفع المشتري للنقل.",
  "zh": "买家支付运费后，运输员才能出发。"
 },
 "Passez d'abord en « En route ».": {
  "en": "Switch to \"On the way\" first.",
  "es": "Pase primero a \"En camino\".",
  "pt": "Passe primeiro a \"A caminho\".",
  "ar": "انتقل أولاً إلى حالة «في الطريق».",
  "zh": "请先切换为“运输中”。"
 },
 "Statut précédent invalide pour livrer.": {
  "en": "Previous status is not valid for delivery.",
  "es": "El estado anterior no es válido para entregar.",
  "pt": "O estado anterior não é válido para entregar.",
  "ar": "الحالة السابقة غير صالحة للتسليم.",
  "zh": "当前状态无法确认送达。"
 },
 "Vous ne pouvez noter qu'après livraison.": {
  "en": "You can only rate after delivery.",
  "es": "Solo puede valorar tras la entrega.",
  "pt": "Só pode avaliar após a entrega.",
  "ar": "لا يمكنك التقييم إلا بعد التسليم.",
  "zh": "送达后才能评分。"
 },
 "Note entre 1 et 5 requise.": {
  "en": "A rating between 1 and 5 is required.",
  "es": "Se requiere una nota entre 1 y 5.",
  "pt": "É necessária uma nota entre 1 e 5.",
  "ar": "التقييم مطلوب بين 1 و5.",
  "zh": "评分需在 1 到 5 之间。"
 },
 "Merci pour votre évaluation.": {
  "en": "Thank you for your rating.",
  "es": "Gracias por su valoración.",
  "pt": "Obrigado pela sua avaliação.",
  "ar": "شكراً على تقييمك.",
  "zh": "感谢您的评价。"
 },
 "Badge invalide. Valeurs : Certifié, Premium, Bio, Haute Qualité.": {
  "en": "Invalid badge. Allowed: Certifié, Premium, Bio, Haute Qualité.",
  "es": "Insignia no válida. Valores: Certifié, Premium, Bio, Haute Qualité.",
  "pt": "Selo inválido. Valores: Certifié, Premium, Bio, Haute Qualité.",
  "ar": "شارة غير صالحة. القيم: Certifié, Premium, Bio, Haute Qualité.",
  "zh": "徽章无效。可选值：Certifié、Premium、Bio、Haute Qualité。"
 },
 "Le badge est requis.": {
  "en": "A badge is required.",
  "es": "Se requiere una insignia.",
  "pt": "É necessário um selo.",
  "ar": "الشارة مطلوبة.",
  "zh": "必须选择徽章。"
 },
 "Cette demande a déjà été traitée.": {
  "en": "This request has already been processed.",
  "es": "Esta solicitud ya fue procesada.",
  "pt": "Este pedido já foi processado.",
  "ar": "تمت معالجة هذا الطلب مسبقاً.",
  "zh": "该请求已处理。"
 },
 "Vous n'êtes pas assigné à cette inspection.": {
  "en": "You are not assigned to this inspection.",
  "es": "No está asignado a esta inspección.",
  "pt": "Não está atribuído a esta inspeção.",
  "ar": "لم يتم تعيينك لهذا الفحص.",
  "zh": "您未被分配到该检查。"
 },
 "Message requis.": {
  "en": "Message required.",
  "es": "Mensaje requerido.",
  "pt": "Mensagem obrigatória.",
  "ar": "الرسالة مطلوبة.",
  "zh": "需要输入消息。"
 },
 "L'assistant est temporairement indisponible. Réessayez plus tard.": {
  "en": "The assistant is temporarily unavailable. Please try again later.",
  "es": "El asistente no está disponible temporalmente. Inténtelo más tarde.",
  "pt": "O assistente está temporariamente indisponível. Tente mais tarde.",
  "ar": "المساعد غير متاح مؤقتاً. حاول لاحقاً.",
  "zh": "助手暂时不可用，请稍后再试。"
 },
 "Ajouté aux favoris.": {
  "en": "Added to favorites.",
  "es": "Añadido a favoritos.",
  "pt": "Adicionado aos favoritos.",
  "ar": "تمت الإضافة إلى المفضلة.",
  "zh": "已加入收藏。"
 },
 "Retiré des favoris.": {
  "en": "Removed from favorites.",
  "es": "Eliminado de favoritos.",
  "pt": "Removido dos favoritos.",
  "ar": "تمت الإزالة من المفضلة.",
  "zh": "已取消收藏。"
 },
 "Notification marquée comme lue.": {
  "en": "Notification marked as read.",
  "es": "Notificación marcada como leída.",
  "pt": "Notificação marcada como lida.",
  "ar": "تم تعليم الإشعار كمقروء.",
  "zh": "通知已标为已读。"
 },
 "Aucun fichier reçu (champ attendu : \"photo\").": {
  "en": "No file received (expected field: \"photo\").",
  "es": "No se recibió ningún archivo (campo esperado: \"photo\").",
  "pt": "Nenhum ficheiro recebido (campo esperado: \"photo\").",
  "ar": "لم يتم استلام أي ملف (الحقل المتوقع: \"photo\").",
  "zh": "未收到文件（应为字段 “photo”）。"
 },
 "Échec de l'envoi de la photo. Réessayez.": {
  "en": "Photo upload failed. Please try again.",
  "es": "Error al subir la foto. Inténtelo de nuevo.",
  "pt": "Falha ao enviar a foto. Tente novamente.",
  "ar": "فشل رفع الصورة. حاول مرة أخرى.",
  "zh": "照片上传失败，请重试。"
 },
 "Compte désactivé.": {
  "en": "Account disabled.",
  "es": "Cuenta desactivada.",
  "pt": "Conta desativada.",
  "ar": "تم تعطيل الحساب.",
  "zh": "账号已停用。"
 },
 "Compte réactivé.": {
  "en": "Account reactivated.",
  "es": "Cuenta reactivada.",
  "pt": "Conta reativada.",
  "ar": "تمت إعادة تفعيل الحساب.",
  "zh": "账号已重新启用。"
 },
 "Produit approuvé.": {
  "en": "Product approved.",
  "es": "Producto aprobado.",
  "pt": "Produto aprovado.",
  "ar": "تمت الموافقة على المنتج.",
  "zh": "产品已通过。"
 },
 "Produit rejeté.": {
  "en": "Product rejected.",
  "es": "Producto rechazado.",
  "pt": "Produto rejeitado.",
  "ar": "تم رفض المنتج.",
  "zh": "产品已被拒绝。"
 },
 "Litige mis à jour.": {
  "en": "Dispute updated.",
  "es": "Disputa actualizada.",
  "pt": "Litígio atualizado.",
  "ar": "تم تحديث النزاع.",
  "zh": "纠纷已更新。"
 },
 "Alertes générées.": {
  "en": "Alerts generated.",
  "es": "Alertas generadas.",
  "pt": "Alertas geradas.",
  "ar": "تم إنشاء التنبيهات.",
  "zh": "已生成提醒。"
 },
 "Téléphone et mot de passe requis.": {
  "en": "Phone and password are required.",
  "es": "Se requieren teléfono y contraseña.",
  "pt": "Telefone e palavra-passe são obrigatórios.",
  "ar": "الهاتف وكلمة المرور مطلوبان.",
  "zh": "需要手机号和密码。"
 },
 "Téléphone et code OTP requis.": {
  "en": "Phone and OTP code are required.",
  "es": "Se requieren teléfono y código OTP.",
  "pt": "Telefone e código OTP são obrigatórios.",
  "ar": "الهاتف ورمز OTP مطلوبان.",
  "zh": "需要手机号和验证码。"
 },
 "Rôle invalide.": {
  "en": "Invalid role.",
  "es": "Rol no válido.",
  "pt": "Função inválida.",
  "ar": "دور غير صالح.",
  "zh": "角色无效。"
 },
 "Rôle non autorisé pour les commandes.": {
  "en": "This role cannot place orders.",
  "es": "Este rol no puede hacer pedidos.",
  "pt": "Esta função não pode fazer encomendas.",
  "ar": "هذا الدور لا يمكنه تقديم طلبات.",
  "zh": "该角色不能下单。"
 },
 "Coordonnées manquantes.": {
  "en": "Coordinates are missing.",
  "es": "Faltan las coordenadas.",
  "pt": "Coordenadas em falta.",
  "ar": "الإحداثيات مفقودة.",
  "zh": "缺少坐标。"
 },
 "orderId et coordonnées requis.": {
  "en": "orderId and coordinates are required.",
  "es": "Se requieren orderId y coordenadas.",
  "pt": "orderId e coordenadas são obrigatórios.",
  "ar": "مطلوب orderId والإحداثيات.",
  "zh": "需要 orderId 和坐标。"
 },
 "orderId requis.": {
  "en": "orderId is required.",
  "es": "Se requiere orderId.",
  "pt": "orderId é obrigatório.",
  "ar": "orderId مطلوب.",
  "zh": "需要 orderId。"
 },
 "productId requis.": {
  "en": "productId is required.",
  "es": "Se requiere productId.",
  "pt": "productId é obrigatório.",
  "ar": "productId مطلوب.",
  "zh": "需要 productId。"
 },
 "refreshToken requis.": {
  "en": "refreshToken is required.",
  "es": "Se requiere refreshToken.",
  "pt": "refreshToken é obrigatório.",
  "ar": "refreshToken مطلوب.",
  "zh": "需要 refreshToken。"
 },
 "transactionId invalide.": {
  "en": "Invalid transactionId.",
  "es": "transactionId no válido.",
  "pt": "transactionId inválido.",
  "ar": "transactionId غير صالح.",
  "zh": "transactionId 无效。"
 },
 "Toutes les sessions ont été révoquées.": {
  "en": "All sessions have been revoked.",
  "es": "Todas las sesiones han sido revocadas.",
  "pt": "Todas as sessões foram revogadas.",
  "ar": "تم إلغاء جميع الجلسات.",
  "zh": "所有会话已注销。"
 }
};

Object.assign(API_MESSAGES, {
  'Ce produit est vendu dans une autre devise.': { en: 'This product is sold in another currency.', es: 'Este producto se vende en otra moneda.', pt: 'Este produto é vendido noutra moeda.', ar: 'هذا المنتج يُباع بعملة أخرى.', zh: '该产品以其他货币出售。' },
  'Recherche indisponible.': { en: 'Search unavailable.', es: 'Búsqueda no disponible.', pt: 'Pesquisa indisponível.', ar: 'البحث غير متاح.', zh: '搜索暂不可用。' },
  'Disponibilité mise à jour.': { en: 'Availability updated.', es: 'Disponibilidad actualizada.', pt: 'Disponibilidade atualizada.', ar: 'تم تحديث التوفر.', zh: '在线状态已更新。' },
  'Position GPS valide requise.': { en: 'A valid GPS position is required.', es: 'Se requiere una posición GPS válida.', pt: 'É necessária uma posição GPS válida.', ar: 'مطلوب موقع GPS صالح.', zh: '需要有效的 GPS 位置。' },
  'Cette mission est proposée à un autre transporteur.': { en: 'This mission is offered to another transporter.', es: 'Esta misión se ofrece a otro transportista.', pt: 'Esta missão foi proposta a outro transportador.', ar: 'هذه المهمة معروضة على ناقل آخر.', zh: '该任务已派给其他运输员。' },
  'Une mission existe déjà pour cette commande.': { en: 'A mission already exists for this order.', es: 'Ya existe una misión para este pedido.', pt: 'Já existe uma missão para esta encomenda.', ar: 'توجد مهمة لهذا الطلب بالفعل.', zh: '该订单已有运输任务。' },
  'Ce transporteur n\'est pas disponible.': { en: 'This transporter is not available.', es: 'Este transportista no está disponible.', pt: 'Este transportador não está disponível.', ar: 'هذا الناقل غير متاح.', zh: '该运输员当前不可用。' },
  'Mission refusée. Proposée au transporteur suivant.': { en: 'Mission declined. Offered to the next transporter.', es: 'Misión rechazada. Ofrecida al siguiente transportista.', pt: 'Missão recusada. Proposta ao próximo transportador.', ar: 'تم رفض المهمة وعرضها على الناقل التالي.', zh: '已拒绝，任务将派给下一位运输员。' },
  'Cette mission ne vous est pas proposée.': { en: 'This mission is not offered to you.', es: 'Esta misión no se le ofrece a usted.', pt: 'Esta missão não lhe foi proposta.', ar: 'هذه المهمة غير معروضة عليك.', zh: '该任务未派给您。' },
});

const API_MESSAGE_PATTERNS = [
  {
    re: /^Compte bloqué suite à trop de tentatives\. Réessayez dans (\d+) min\.$/,
    t: {
      en: (m) => `Account locked after too many attempts. Try again in ${m[1]} min.`,
      es: (m) => `Cuenta bloqueada por demasiados intentos. Inténtelo en ${m[1]} min.`,
      pt: (m) => `Conta bloqueada por demasiadas tentativas. Tente em ${m[1]} min.`,
      ar: (m) => `تم قفل الحساب بعد محاولات كثيرة. حاول بعد ${m[1]} دقيقة.`,
      zh: (m) => `尝试次数过多，账号已锁定，请 ${m[1]} 分钟后再试。`,
    },
  },
  {
    re: /^Accès refusé\. Rôle\(s\) requis : (.+)$/,
    t: {
      en: (m) => `Access denied. Required role(s): ${m[1]}`,
      es: (m) => `Acceso denegado. Rol(es) requerido(s): ${m[1]}`,
      pt: (m) => `Acesso negado. Função(ões) necessária(s): ${m[1]}`,
      ar: (m) => `تم رفض الوصول. الدور المطلوب: ${m[1]}`,
      zh: (m) => `访问被拒绝。所需角色：${m[1]}`,
    },
  },
];

function translateApiMessage(msg, lang) {
  if (lang === 'fr') return msg;
  const hit = API_MESSAGES[msg];
  if (hit && hit[lang]) return hit[lang];
  for (const p of API_MESSAGE_PATTERNS) {
    const m = p.re.exec(msg);
    if (m && p.t[lang]) return p.t[lang](m);
  }
  return msg;
}

app.use((req, res, next) => {
  const lang = baseLang(req.headers['x-app-language'] || req.headers['accept-language']);
  if (lang === 'fr') return next();
  const original = res.json.bind(res);
  res.json = (body) => {
    if (body && typeof body === 'object' && typeof body.message === 'string') {
      body = { ...body, message: translateApiMessage(body.message, lang) };
    }
    return original(body);
  };
  next();
});


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

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
for (const p of ['id', 'productId', 'cultureId']) {
  router.param(p, (req, res, next, val) => {
    if (!UUID_RE.test(String(val))) {
      return res.status(400).json({ message: 'Identifiant invalide.' });
    }
    next();
  });
}

/** Exécute fn(client) dans une transaction SQL (COMMIT / ROLLBACK automatiques). */
async function withTransaction(fn) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const out = await fn(client);
    await client.query('COMMIT');
    return out;
  } catch (e) {
    try { await client.query('ROLLBACK'); } catch (_) {}
    throw e;
  } finally {
    client.release();
  }
}

/** Vérifie qu'une commande est payable par cet utilisateur et renvoie le VRAI montant. */
async function resolveOrderPayable(orderId, userId) {
  if (!UUID_RE.test(String(orderId))) return { status: 400, error: 'orderId invalide.' };
  const r = await pool.query('SELECT * FROM orders WHERE id = $1', [orderId]);
  const o = r.rows[0];
  if (!o) return { status: 404, error: 'Commande introuvable.' };
  if (o.acheteur_id !== userId) return { status: 403, error: 'Accès refusé.' };
  if (o.statut !== 'en_attente_paiement') {
    return { status: 400, error: 'Cette commande ne peut plus être payée.' };
  }
  return { amount: Number(o.montant_total_fcfa) };
}

const SANDBOX_PAYMENTS = process.env.MOBILE_MONEY_SANDBOX === 'true';
if (SANDBOX_PAYMENTS) {
  console.warn('[Paiement] MOBILE_MONEY_SANDBOX=true : paiements FICTIFS acceptés (ne jamais utiliser avec de vrais clients).');
}

// ============================================================================
// MODULE 1 — AUTHENTIFICATION & SECURITE
// ============================================================================

router.post(
  '/auth/register',
  authLimiter,
  asyncHandler(async (req, res) => {
    const { fullName, phone, password, role, region, email, language, country } = req.body;

    if (!fullName || !phone || !password || !role) {
      return res.status(400).json({ message: 'Champs requis manquants.' });
    }
    if (!USER_ROLES.includes(role)) {
      return res.status(400).json({ message: 'Rôle invalide.' });
    }
    // Admin : uniquement si le numéro est pré-autorisé ET moins de 5 admins
    if (role === 'admin') {
      const adminCount = Number(
        (await pool.query(`SELECT COUNT(*) FROM users WHERE role = 'admin'`)).rows[0].count,
      );
      if (adminCount >= 5) {
        return res.status(403).json({
          message: 'ADMIN_LIMIT_REACHED',
        });
      }
      const phoneKey = normalizePhone(phone);
      const allowed = await pool.query(
        `SELECT phone FROM admin_allowed_phones
         WHERE REPLACE(REPLACE(phone, '+', ''), ' ', '') = $1
           AND used_at IS NULL
         LIMIT 1`,
        [phoneKey],
      );
      if (allowed.rows.length === 0) {
        return res.status(403).json({
          message: 'ADMIN_PHONE_NOT_ALLOWED',
        });
      }
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
      `INSERT INTO users (id, full_name, phone, email, password_hash, role, region, phone_verified, preferred_language, country, devise)
       VALUES ($1, $2, $3, $4, $5, $6, $7, false, $8, $9, $10)`,
      [id, fullName, phone, email || null, passwordHash, role, region || null,
        String(language || 'fr').split('-')[0].toLowerCase().slice(0, 8),
        // Le pays du compte suit l'indicatif du numéro (résidence), sinon le pays détecté par l'app
        countryProfile(detectCountryFromPhone(phone) || country).code,
        countryProfile(detectCountryFromPhone(phone) || country).currency],
    );

    if (role === 'admin') {
      const phoneKey = normalizePhone(phone);
      await pool.query(
        `UPDATE admin_allowed_phones
         SET used_at = now()
         WHERE REPLACE(REPLACE(phone, '+', ''), ' ', '') = $1
           AND used_at IS NULL`,
        [phoneKey],
      );
    }

    const code = generateOtpCode();
    await storeOtp(phone, code);
    const smsSent = await sendOtpSms(phone, code, language || req.headers['accept-language']);

    // Auto-remplissage app : renvoyer le code sauf si OTP_HIDE_CODE=true
    const payload = {
      userId: id,
      message: 'Code de vérification envoyé par SMS.',
      debugOtp: String(code),
    };
    // Le code n'est renvoyé à l'app que si OTP_DEBUG=true, ou en développement quand le SMS n'est pas parti
    const exposeOtp =
      process.env.OTP_HIDE_CODE !== 'true' &&
      (process.env.OTP_DEBUG === 'true' ||
        (process.env.NODE_ENV !== 'production' && !smsSent));
    if (!exposeOtp) {
      delete payload.debugOtp;
    }
    console.log(`[OTP] Réponse register debugOtp=${payload.debugOtp || '(caché)'}`);
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
    const result = await pool.query('SELECT id, preferred_language FROM users WHERE phone = $1', [phone]);
    // Anti-énumération : toujours le même message, que le compte existe ou non
    if (result.rows.length > 0) {
      const code = generateOtpCode();
      await storeOtp(phone, code);
      await sendOtpSms(phone, code, req.body.language || result.rows[0].preferred_language);
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
    // OTP validé = numéro de confiance → on marque aussi phone_verified = true
    // (sinon l'utilisateur ne peut pas se connecter après un reset)
    const result = await pool.query(
      `UPDATE users
       SET password_hash = $1,
           phone_verified = true,
           updated_at = now()
       WHERE phone = $2 OR phone = $3 OR REPLACE(phone, '+', '') = $3
       RETURNING id`,
      [passwordHash, phone, normalizePhone(phone)],
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
    preferredLanguage: row.preferred_language || 'fr',
    country: row.country || 'TG',
    devise: row.devise || 'XOF',
    noteMoyenne: row.note_moyenne != null ? Number(row.note_moyenne) : 5.0,
    localisationLat: row.localisation_lat != null ? Number(row.localisation_lat) : null,
    localisationLng: row.localisation_lng != null ? Number(row.localisation_lng) : null,
    kycStatut: row.kyc_statut || 'non_soumis',
    kycDocuments: row.kyc_documents || null,
    specialites: row.specialites || null,
    diplomes: row.diplomes || null,
    zoneIntervention: row.zone_intervention || null,
    typeActivite: row.type_activite || null,
    volumeHabituel: row.volume_habituel || null,
    typeEtablissement: row.type_etablissement || null,
    vehiculeType: row.vehicule_type || null,
    vehiculeImmat: row.vehicule_immat || null,
    zoneCouverture: row.zone_couverture || null,
    derniereConnexion: row.derniere_connexion || null,
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
    const {
      fullName, email, region, preferredLanguage,
      localisationLat, localisationLng,
      specialites, diplomes, zoneIntervention,
      typeActivite, volumeHabituel, typeEtablissement,
      vehiculeType, vehiculeImmat, zoneCouverture,
      kycDocuments,
    } = req.body;
    const lang = preferredLanguage && String(preferredLanguage).slice(0, 8);
    let kycStatutUpdate = null;
    if (kycDocuments) kycStatutUpdate = 'en_attente';
    await pool.query(
      `UPDATE users SET
         full_name = COALESCE($1, full_name),
         email = COALESCE($2, email),
         region = COALESCE($3, region),
         preferred_language = COALESCE($4, preferred_language),
         localisation_lat = COALESCE($5, localisation_lat),
         localisation_lng = COALESCE($6, localisation_lng),
         specialites = COALESCE($7, specialites),
         diplomes = COALESCE($8, diplomes),
         zone_intervention = COALESCE($9, zone_intervention),
         type_activite = COALESCE($10, type_activite),
         volume_habituel = COALESCE($11, volume_habituel),
         type_etablissement = COALESCE($12, type_etablissement),
         vehicule_type = COALESCE($13, vehicule_type),
         vehicule_immat = COALESCE($14, vehicule_immat),
         zone_couverture = COALESCE($15, zone_couverture),
         kyc_documents = COALESCE($16, kyc_documents),
         kyc_statut = COALESCE($17, kyc_statut),
         updated_at = now()
       WHERE id = $18`,
      [
        fullName || null, email || null, region || null, lang || null,
        localisationLat ?? null, localisationLng ?? null,
        specialites || null, diplomes || null, zoneIntervention || null,
        typeActivite || null, volumeHabituel || null, typeEtablissement || null,
        vehiculeType || null, vehiculeImmat || null, zoneCouverture || null,
        kycDocuments ? JSON.stringify(kycDocuments) : null,
        kycStatutUpdate,
        req.user.id,
      ],
    );
    const result = await pool.query('SELECT * FROM users WHERE id = $1', [req.user.id]);
    res.json(serializeUser(result.rows[0]));
  }),
);

// KYC — admin valide / rejette
router.patch(
  '/users/:id/kyc',
  requireAuth,
  requireRole('admin'),
  asyncHandler(async (req, res) => {
    const { action, motif } = req.body; // 'valide' | 'rejete'
    if (!['valide', 'rejete'].includes(action)) {
      return res.status(400).json({ message: 'action doit être valide ou rejete.' });
    }
    await pool.query(
      `UPDATE users SET kyc_statut = $1, updated_at = now() WHERE id = $2`,
      [action, req.params.id],
    );
    await notifyUser(
      req.params.id,
      action === 'valide' ? 'kyc_valide' : 'kyc_rejete',
      { reason: motif ? ` ${motif}` : '' },
      { userId: req.params.id },
    );
    const result = await pool.query('SELECT * FROM users WHERE id = $1', [req.params.id]);
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
    const { typeCulture, dateSemis, superficieHa, typeSol, region, dateRecoltePrevue, photos, notes, language } =
      req.body;
    if (!typeCulture || !dateSemis || !superficieHa || !typeSol || !region) {
      return res.status(400).json({ message: 'Champs requis manquants.' });
    }
    // Langue de l'écran (prioritaire pour la notification)
    await applyUserLanguage(req.user.id, language);
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
    await notifyUser(req.user.id, 'culture_ajoutee', { name: typeCulture }, { cultureId: id });
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

    // Visible dès la publication (validation admin optionnelle ensuite via badge / modération)
    const conditions = [`statut IN ('Publié', 'En attente de validation')`];
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
    if (req.query.devise && /^[A-Z]{3}$/.test(String(req.query.devise))) {
      values.push(String(req.query.devise));
      conditions.push(`COALESCE(devise, 'XOF') = $${values.length}`);
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
      language,
    } = req.body;

    if (!nom || !quantite || !unite || !prixFcfa || !region) {
      return res.status(400).json({ message: 'Champs requis manquants.' });
    }
    // Langue de l'écran (prioritaire pour la notification)
    await applyUserLanguage(req.user.id, language);

    const id = crypto.randomUUID();
    await pool.query(
      `INSERT INTO products (id, agriculteur_id, nom, quantite, unite, prix_fcfa, prix_negociable, date_recolte, description, photos, region, latitude, longitude, statut, devise)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'En attente de validation',$14)`,
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
        validCoord(latitude, longitude) ? latitude : null,
        validCoord(latitude, longitude) ? longitude : null,
        await userCurrency(req.user.id),
      ],
    );

    // Crée automatiquement la demande de certification (Module 5, étape 1-2)
    await pool.query(
      `INSERT INTO certifications (id, product_id, statut) VALUES ($1,$2,'En attente')`,
      [crypto.randomUUID(), id],
    );

    await notifyUser(req.user.id, 'produit_soumis', { name: nom }, { productId: id });

    // Prévenir les agronomes qu'une certification est en attente
    try {
      const agronomes = await pool.query(
        `SELECT id FROM users WHERE role = 'agronome' AND is_active = true LIMIT 50`,
      );
      for (const a of agronomes.rows) {
        await notifyUser(a.id, 'certification_en_attente', { name: nom }, { productId: id });
      }
    } catch (err) {
      console.error('[Notif] agronomes :', err.message);
    }

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
    productName: row.product_nom || row.product_name || null,
    agronomeId: row.agronome_id,
    statut: row.statut,
    badge: row.badge,
    commentaire: row.commentaire,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

router.get(
  '/certifications/pending',
  requireAuth,
  requireRole('agronome', 'admin'),
  asyncHandler(async (req, res) => {
    const result = await pool.query(
      `SELECT c.*, p.nom AS product_nom FROM certifications c
       LEFT JOIN products p ON p.id = c.product_id
       WHERE c.statut = 'En attente' ORDER BY c.created_at ASC`,
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
    if (!['Certifié', 'Premium', 'Bio', 'Haute Qualité'].includes(badge)) {
      return res.status(400).json({ message: 'Badge invalide. Valeurs : Certifié, Premium, Bio, Haute Qualité.' });
    }

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
        { name: product.rows[0].nom, badge },
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
        {
          name: product.rows[0].nom,
          reason: commentaire ? ` Motif : ${commentaire}` : '',
        },
        { productId: existing.rows[0].product_id },
      );
    }

    res.json(serializeCertification(result.rows[0]));
  }),
);


// ============================================================================
// MODULE 4b — COMMANDES MARKETPLACE (cycle complet)
// ============================================================================

function serializeOrder(row) {
  return {
    id: row.id,
    acheteurId: row.acheteur_id,
    productId: row.product_id,
    agriculteurId: row.agriculteur_id,
    quantite: Number(row.quantite),
    prixUnitaireFcfa: row.prix_unitaire_fcfa,
    montantTotalFcfa: row.montant_total_fcfa,
    commissionFcfa: row.commission_fcfa || 0,
    statut: row.statut,
    adresseLivraison: row.adresse_livraison,
    destinationLat: row.destination_lat != null ? Number(row.destination_lat) : null,
    destinationLng: row.destination_lng != null ? Number(row.destination_lng) : null,
    notes: row.notes,
    productNom: row.product_nom || null,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

async function getCommissionPct(key, fallback) {
  try {
    const r = await pool.query('SELECT valeur FROM platform_config WHERE cle = $1', [key]);
    if (r.rows[0]) return Number(r.rows[0].valeur) || fallback;
  } catch (_) {}
  return fallback;
}

/** Créer une commande (acheteur / restaurant) */
router.post(
  '/orders',
  requireAuth,
  requireRole('acheteur', 'restaurant'),
  asyncHandler(async (req, res) => {
    const { productId, quantite, adresseLivraison, destinationLat, destinationLng, notes } = req.body;
    if (!productId || !quantite || quantite <= 0) {
      return res.status(400).json({ message: 'productId et quantite > 0 requis.' });
    }
    const prod = await pool.query('SELECT * FROM products WHERE id = $1', [productId]);
    if (!prod.rows[0]) return res.status(404).json({ message: 'Produit introuvable.' });
    const p = prod.rows[0];
    const orderable = process.env.REQUIRE_CERTIFICATION_TO_ORDER === 'true'
      ? ['Publié']
      : ['Publié', 'En attente de validation'];
    if (!orderable.includes(p.statut)) {
      return res.status(400).json({ message: 'Produit non disponible à la commande.' });
    }
    const buyerCur = await userCurrency(req.user.id);
    if ((p.devise || 'XOF') !== buyerCur) {
      return res.status(400).json({ message: 'Ce produit est vendu dans une autre devise.' });
    }
    if (p.agriculteur_id === req.user.id) {
      return res.status(400).json({ message: 'Vous ne pouvez pas commander votre propre produit.' });
    }
    if (Number(p.quantite) < Number(quantite)) {
      return res.status(400).json({ message: 'Quantité insuffisante en stock.' });
    }
    const prixUnit = p.prix_fcfa;
    const montant = Math.round(prixUnit * Number(quantite));
    const pct = await getCommissionPct('commission_vente_pct', 5);
    const commission = Math.round(montant * (pct / 100));
    const id = crypto.randomUUID();
    // Réservation atomique du stock (évite la survente)
    const reserve = await pool.query(
      `UPDATE products
         SET quantite = quantite - $1,
             statut = CASE WHEN quantite - $1 <= 0 THEN 'Épuisé' ELSE statut END,
             updated_at = now()
       WHERE id = $2 AND statut IN ('Publié','En attente de validation') AND quantite >= $1
       RETURNING id`,
      [quantite, productId],
    );
    if (reserve.rowCount === 0) {
      return res.status(400).json({ message: 'Quantité insuffisante en stock.' });
    }
    await pool.query(
      `INSERT INTO orders (
        id, acheteur_id, product_id, agriculteur_id, quantite, prix_unitaire_fcfa,
        montant_total_fcfa, commission_fcfa, statut, adresse_livraison,
        destination_lat, destination_lng, notes
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'en_attente_paiement',$9,$10,$11,$12)`,
      [
        id, req.user.id, productId, p.agriculteur_id, quantite, prixUnit,
        montant, commission, adresseLivraison || null,
        destinationLat || null, destinationLng || null, notes || null,
      ],
    );
    const result = await pool.query(
      `SELECT o.*, pr.nom AS product_nom FROM orders o
       LEFT JOIN products pr ON pr.id = o.product_id WHERE o.id = $1`,
      [id],
    );
    await notifyUser(
      p.agriculteur_id,
      'nouvelle_commande',
      { name: p.nom, qty: String(quantite) },
      { orderId: id, productId },
    );
    res.status(201).json(serializeOrder(result.rows[0]));
  }),
);

router.get(
  '/orders/mine',
  requireAuth,
  asyncHandler(async (req, res) => {
    const role = req.user.role;
    let sql, params;
    if (role === 'acheteur' || role === 'restaurant') {
      sql = `SELECT o.*, pr.nom AS product_nom FROM orders o
             LEFT JOIN products pr ON pr.id = o.product_id
             WHERE o.acheteur_id = $1 ORDER BY o.created_at DESC`;
      params = [req.user.id];
    } else if (role === 'agriculteur') {
      sql = `SELECT o.*, pr.nom AS product_nom FROM orders o
             LEFT JOIN products pr ON pr.id = o.product_id
             WHERE o.agriculteur_id = $1 ORDER BY o.created_at DESC`;
      params = [req.user.id];
    } else if (role === 'admin') {
      sql = `SELECT o.*, pr.nom AS product_nom FROM orders o
             LEFT JOIN products pr ON pr.id = o.product_id
             ORDER BY o.created_at DESC LIMIT 200`;
      params = [];
    } else {
      return res.status(403).json({ message: 'Rôle non autorisé pour les commandes.' });
    }
    const result = await pool.query(sql, params);
    res.json(result.rows.map(serializeOrder));
  }),
);

router.get(
  '/orders/:id',
  requireAuth,
  asyncHandler(async (req, res) => {
    const result = await pool.query(
      `SELECT o.*, pr.nom AS product_nom FROM orders o
       LEFT JOIN products pr ON pr.id = o.product_id WHERE o.id = $1`,
      [req.params.id],
    );
    if (!result.rows[0]) return res.status(404).json({ message: 'Commande introuvable.' });
    const o = result.rows[0];
    const uid = req.user.id;
    if (
      o.acheteur_id !== uid &&
      o.agriculteur_id !== uid &&
      req.user.role !== 'admin'
    ) {
      return res.status(403).json({ message: 'Accès refusé.' });
    }
    res.json(serializeOrder(o));
  }),
);

router.patch(
  '/orders/:id/cancel',
  requireAuth,
  asyncHandler(async (req, res) => {
    const result = await pool.query('SELECT * FROM orders WHERE id = $1', [req.params.id]);
    if (!result.rows[0]) return res.status(404).json({ message: 'Commande introuvable.' });
    const o = result.rows[0];
    if (o.acheteur_id !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Accès refusé.' });
    }
    if (o.statut === 'paye') {
      return res.status(400).json({
        message: 'Commande déjà payée : ouvrez un litige pour être remboursé.',
      });
    }
    const cancelled = await pool.query(
      `UPDATE orders SET statut = 'annule', updated_at = now()
       WHERE id = $1 AND statut = 'en_attente_paiement' RETURNING product_id, quantite`,
      [req.params.id],
    );
    if (cancelled.rowCount === 0) {
      return res.status(400).json({ message: 'Cette commande ne peut plus être annulée.' });
    }
    await pool.query(
      `UPDATE products
         SET quantite = quantite + $1,
             statut = CASE WHEN statut = 'Épuisé' THEN 'Publié' ELSE statut END,
             updated_at = now()
       WHERE id = $2`,
      [cancelled.rows[0].quantite, cancelled.rows[0].product_id],
    );
    await notifyUser(o.agriculteur_id, 'commande_annulee', { name: o.id }, { orderId: o.id });
    res.json({ message: 'Commande annulée.' });
  }),
);

// Confirmer réception (acheteur)
router.patch(
  '/orders/:id/confirm-delivery',
  requireAuth,
  requireRole('acheteur', 'restaurant'),
  asyncHandler(async (req, res) => {
    const result = await pool.query('SELECT * FROM orders WHERE id = $1', [req.params.id]);
    if (!result.rows[0]) return res.status(404).json({ message: 'Commande introuvable.' });
    const o = result.rows[0];
    if (o.acheteur_id !== req.user.id) return res.status(403).json({ message: 'Accès refusé.' });
    if (!['paye', 'confirme', 'en_livraison'].includes(o.statut)) {
      return res.status(400).json({
        message:
          o.statut === 'livre'
            ? 'Livraison déjà confirmée.'
            : "La commande doit être payée avant de confirmer la livraison.",
      });
    }
    // Transition atomique + crédit unique (impossible de créditer deux fois)
    const net = o.montant_total_fcfa - (o.commission_fcfa || 0);
    const done = await withTransaction(async (c) => {
      const upd = await c.query(
        `UPDATE orders SET statut = 'livre', updated_at = now()
         WHERE id = $1 AND statut IN ('paye','confirme','en_livraison') RETURNING id`,
        [req.params.id],
      );
      if (upd.rowCount === 0) return false;
      await c.query(
        `INSERT INTO wallets (user_id, solde_fcfa) VALUES ($1, 0) ON CONFLICT (user_id) DO NOTHING`,
        [o.agriculteur_id],
      );
      await c.query(
        `UPDATE wallets SET solde_fcfa = solde_fcfa + $1, updated_at = now() WHERE user_id = $2`,
        [net, o.agriculteur_id],
      );
      await c.query(
        `INSERT INTO wallet_transactions (id, user_id, type, montant_fcfa, motif, reference_id)
         VALUES ($1,$2,'credit',$3,'Vente produit',$4)`,
        [crypto.randomUUID(), o.agriculteur_id, net, o.id],
      );
      return true;
    });
    if (!done) return res.status(400).json({ message: 'Livraison déjà confirmée.' });
    await notifyUser(o.agriculteur_id, 'commande_livree', { amount: String(net) }, { orderId: o.id });
    res.json({ message: 'Livraison confirmée. Agriculteur crédité.' });
  }),
);

// ============================================================================
// FAVORIS
// ============================================================================

router.post(
  '/favorites',
  requireAuth,
  asyncHandler(async (req, res) => {
    const { productId } = req.body;
    if (!productId) return res.status(400).json({ message: 'productId requis.' });
    const id = crypto.randomUUID();
    try {
      await pool.query(
        `INSERT INTO favorites (id, user_id, product_id) VALUES ($1,$2,$3)
         ON CONFLICT (user_id, product_id) DO NOTHING`,
        [id, req.user.id, productId],
      );
    } catch (e) {
      return res.status(400).json({ message: 'Impossible d\'ajouter aux favoris.' });
    }
    res.status(201).json({ message: 'Ajouté aux favoris.' });
  }),
);

router.delete(
  '/favorites/:productId',
  requireAuth,
  asyncHandler(async (req, res) => {
    await pool.query('DELETE FROM favorites WHERE user_id = $1 AND product_id = $2', [
      req.user.id,
      req.params.productId,
    ]);
    res.json({ message: 'Retiré des favoris.' });
  }),
);

router.get(
  '/favorites',
  requireAuth,
  asyncHandler(async (req, res) => {
    const result = await pool.query(
      `SELECT p.* FROM favorites f
       JOIN products p ON p.id = f.product_id
       WHERE f.user_id = $1 ORDER BY f.created_at DESC`,
      [req.user.id],
    );
    res.json(result.rows.map(serializeProduct));
  }),
);

// ============================================================================
// MODULE 9b — PORTEFEUILLE INTERNE
// ============================================================================

async function ensureWallet(userId) {
  await pool.query(
    `INSERT INTO wallets (user_id, solde_fcfa) VALUES ($1, 0)
     ON CONFLICT (user_id) DO NOTHING`,
    [userId],
  );
}

/** Crédit portefeuille unique par référence (évite double crédit webhook) */
async function creditWalletOnce(userId, amount, motif, referenceId) {
  const amt = Math.round(Number(amount) || 0);
  if (!userId || amt <= 0) return false;
  return withTransaction(async (c) => {
    await c.query(
      `INSERT INTO wallets (user_id, solde_fcfa) VALUES ($1, 0) ON CONFLICT (user_id) DO NOTHING`,
      [userId],
    );
    // L'insertion échoue silencieusement si cette référence a déjà été créditée
    const ins = await c.query(
      `INSERT INTO wallet_transactions (id, user_id, type, montant_fcfa, motif, reference_id)
       SELECT $1,$2,'credit',$3,$4,$5
       WHERE NOT EXISTS (SELECT 1 FROM wallet_transactions WHERE reference_id = $5 AND type = 'credit')
       RETURNING id`,
      [crypto.randomUUID(), userId, amt, motif || 'Recharge portefeuille', String(referenceId)],
    );
    if (ins.rowCount === 0) return false;
    await c.query(
      `UPDATE wallets SET solde_fcfa = solde_fcfa + $1, updated_at = now() WHERE user_id = $2`,
      [amt, userId],
    );
    return true;
  });
}


router.get(
  '/wallet',
  requireAuth,
  asyncHandler(async (req, res) => {
    await ensureWallet(req.user.id);
    const w = await pool.query('SELECT * FROM wallets WHERE user_id = $1', [req.user.id]);
    const tx = await pool.query(
      `SELECT * FROM wallet_transactions WHERE user_id = $1 ORDER BY created_at DESC LIMIT 50`,
      [req.user.id],
    );
    res.json({
      soldeFcfa: w.rows[0].solde_fcfa,
      transactions: tx.rows.map((r) => ({
        id: r.id,
        type: r.type,
        montantFcfa: r.montant_fcfa,
        motif: r.motif,
        referenceId: r.reference_id,
        createdAt: r.created_at,
      })),
    });
  }),
);

// ============================================================================
// MODULE 3b — ALERTES AGRICOLES / CALENDRIER
// ============================================================================

router.get(
  '/alerts/mine',
  requireAuth,
  asyncHandler(async (req, res) => {
    const result = await pool.query(
      `SELECT * FROM agricultural_alerts WHERE user_id = $1 ORDER BY created_at DESC LIMIT 50`,
      [req.user.id],
    );
    res.json(
      result.rows.map((r) => ({
        id: r.id,
        cultureId: r.culture_id,
        typeAlerte: r.type_alerte,
        titre: r.titre,
        message: r.message,
        datePrevue: r.date_prevue,
        lu: r.lu,
        createdAt: r.created_at,
      })),
    );
  }),
);

router.post(
  '/alerts/generate/:cultureId',
  requireAuth,
  requireRole('agriculteur'),
  asyncHandler(async (req, res) => {
    const cult = await pool.query(
      'SELECT * FROM cultures WHERE id = $1 AND agriculteur_id = $2',
      [req.params.cultureId, req.user.id],
    );
    if (!cult.rows[0]) return res.status(404).json({ message: 'Culture introuvable.' });
    const c = cult.rows[0];
    const alerts = [
      {
        type: 'arrosage',
        titre: 'Rappel arrosage',
        message: `Pensez à contrôler l'humidité de votre culture ${c.type_culture}.`,
        days: 3,
      },
      {
        type: 'traitement',
        titre: 'Contrôle phytosanitaire',
        message: `Vérifiez l'apparition de maladies sur ${c.type_culture}.`,
        days: 7,
      },
      {
        type: 'recolte',
        titre: 'Récolte approche',
        message: c.date_recolte_prevue
          ? `Récolte prévue le ${c.date_recolte_prevue} pour ${c.type_culture}.`
          : `Planifiez la récolte de ${c.type_culture}.`,
        days: 14,
      },
    ];
    const created = [];
    for (const a of alerts) {
      const id = crypto.randomUUID();
      const d = new Date();
      d.setDate(d.getDate() + a.days);
      await pool.query(
        `INSERT INTO agricultural_alerts (id, user_id, culture_id, type_alerte, titre, message, date_prevue)
         VALUES ($1,$2,$3,$4,$5,$6,$7)`,
        [id, req.user.id, c.id, a.type, a.titre, a.message, d.toISOString().slice(0, 10)],
      );
      created.push(a.titre);
      await notifyUser(req.user.id, 'alerte_agricole', { title: a.titre, msg: a.message }, {
        cultureId: c.id,
      });
    }
    res.status(201).json({ message: 'Alertes générées.', items: created });
  }),
);

// ============================================================================
// MODULE 12b — LITIGES + CONFIG
// ============================================================================

router.post(
  '/disputes',
  requireAuth,
  asyncHandler(async (req, res) => {
    const { orderId, contreUserId, motif, description } = req.body;
    if (!motif) return res.status(400).json({ message: 'motif requis.' });
    const id = crypto.randomUUID();
    await pool.query(
      `INSERT INTO disputes (id, order_id, ouvre_par, contre, motif, description)
       VALUES ($1,$2,$3,$4,$5,$6)`,
      [id, orderId || null, req.user.id, contreUserId || null, motif, description || null],
    );
    // Notifier admins
    const admins = await pool.query(`SELECT id FROM users WHERE role = 'admin' AND is_active = true`);
    for (const a of admins.rows) {
      await notifyUser(a.id, 'nouveau_litige', { motif }, { disputeId: id });
    }
    res.status(201).json({ id, message: 'Litige ouvert.' });
  }),
);

router.get(
  '/disputes',
  requireAuth,
  requireRole('admin'),
  asyncHandler(async (req, res) => {
    const result = await pool.query(
      `SELECT * FROM disputes ORDER BY created_at DESC LIMIT 100`,
    );
    res.json(
      result.rows.map((r) => ({
        id: r.id,
        orderId: r.order_id,
        ouvrePar: r.ouvre_par,
        contre: r.contre,
        motif: r.motif,
        description: r.description,
        statut: r.statut,
        resolution: r.resolution,
        createdAt: r.created_at,
      })),
    );
  }),
);

router.patch(
  '/disputes/:id',
  requireAuth,
  requireRole('admin'),
  asyncHandler(async (req, res) => {
    const { statut, resolution } = req.body;
    await pool.query(
      `UPDATE disputes SET
         statut = COALESCE($1, statut),
         resolution = COALESCE($2, resolution),
         updated_at = now()
       WHERE id = $3`,
      [statut || null, resolution || null, req.params.id],
    );
    res.json({ message: 'Litige mis à jour.' });
  }),
);

router.get(
  '/admin/config',
  requireAuth,
  requireRole('admin'),
  asyncHandler(async (req, res) => {
    const result = await pool.query('SELECT * FROM platform_config ORDER BY cle');
    const cfg = {};
    for (const r of result.rows) cfg[r.cle] = r.valeur;
    res.json(cfg);
  }),
);

router.patch(
  '/admin/config',
  requireAuth,
  requireRole('admin'),
  asyncHandler(async (req, res) => {
    const entries = Object.entries(req.body || {});
    for (const [cle, valeur] of entries) {
      await pool.query(
        `INSERT INTO platform_config (cle, valeur, updated_at) VALUES ($1,$2,now())
         ON CONFLICT (cle) DO UPDATE SET valeur = $2, updated_at = now()`,
        [String(cle), String(valeur)],
      );
    }
    res.json({ message: 'Configuration mise à jour.' });
  }),
);

// ============================================================================
// MODULE 6 & 11 — TRANSPORT & LOGISTIQUE + GPS TEMPS REEL
// ============================================================================

function serializeMission(row) {
  return {
    id: row.id,
    productId: row.product_id,
    orderId: row.order_id || null,
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
    noteCommentaire: row.note_commentaire || null,
    distanceKm: row.distance_km != null ? Number(row.distance_km) : null,
    etaMinutes: row.eta_minutes != null ? Number(row.eta_minutes) : null,
    prixTransportFcfa: row.prix_transport_fcfa != null ? Number(row.prix_transport_fcfa) : null,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}


// ---------- Recherche de transporteurs façon Gozem ----------

function haversineKm(lat1, lng1, lat2, lng2) {
  const toRad = (d) => (d * Math.PI) / 180;
  const dLat = toRad(lat2 - lat1);
  const dLng = toRad(lng2 - lng1);
  const a = Math.sin(dLat / 2) ** 2 + Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLng / 2) ** 2;
  return 6371 * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}
// Routage routier GRATUIT : OSRM (OpenStreetMap). Le serveur public de démonstration n'a pas de garantie
// de service : pour un usage intensif, héberger son propre OSRM et changer ROUTING_URL.
const ROUTING_URL = (process.env.ROUTING_URL || 'https://router.project-osrm.org').replace(/\/$/, '');
const routeCache = new Map();

async function getRoadRoute(lat1, lng1, lat2, lng2) {
  const key = [lat1, lng1, lat2, lng2].map((x) => Number(x).toFixed(3)).join(',');
  const hit = routeCache.get(key);
  if (hit && Date.now() - hit.at < 6 * 3600 * 1000) return hit.value;
  try {
    const url = `${ROUTING_URL}/route/v1/driving/${Number(lng1)},${Number(lat1)};${Number(lng2)},${Number(lat2)}` +
      '?overview=full&geometries=geojson&alternatives=false&steps=false';
    const r = await axios.get(url, {
      timeout: 8000,
      headers: { 'User-Agent': 'DifaBackend/1.0 (logistique agricole, Togo)' },
    });
    const rt = r.data?.routes?.[0];
    if (r.data?.code === 'Ok' && rt?.geometry?.coordinates?.length) {
      let pts = rt.geometry.coordinates.map(([lng, lat]) => [lat, lng]);
      if (pts.length > 400) {
        const step = Math.ceil(pts.length / 400);
        pts = pts.filter((_, i) => i % step === 0 || i === pts.length - 1);
      }
      const value = {
        source: 'road',
        distanceKm: Math.round((rt.distance / 1000) * 10) / 10,
        durationMin: Math.max(1, Math.round(rt.duration / 60)),
        points: pts,
      };
      if (routeCache.size > 500) routeCache.delete(routeCache.keys().next().value);
      routeCache.set(key, { at: Date.now(), value });
      return value;
    }
  } catch (e) {
    console.warn('[Route] Service de routage indisponible, estimation en ligne droite :', e.message);
  }
  // Repli : ligne droite majorée (les routes sont rarement droites), non mise en cache
  const km = Math.round(haversineKm(Number(lat1), Number(lng1), Number(lat2), Number(lng2)) * 1.3 * 10) / 10;
  const speed = await getCommissionPct('transport_speed_kmh', 30);
  return {
    source: 'estimate',
    distanceKm: km,
    durationMin: Math.max(1, Math.round((km / speed) * 60)),
    points: [[Number(lat1), Number(lng1)], [Number(lat2), Number(lng2)]],
  };
}

const validCoord = (lat, lng) =>
  Number.isFinite(Number(lat)) && Number.isFinite(Number(lng)) &&
  lat !== null && lng !== null && lat !== '' && lng !== '' &&
  Math.abs(Number(lat)) <= 90 && Math.abs(Number(lng)) <= 180;

async function estimateTransport(distKm, cur = 'XOF') {
  const { base, perKm } = await transportTariff(cur);
  const speed = await getCommissionPct('transport_speed_kmh', 30);
  return {
    prixFcfa: Math.max(base, Math.round(distKm * perKm)),
    etaMinutes: Math.max(1, Math.round((distKm / speed) * 60)),
  };
}

const ACTIVE_MISSION_STATUTS = [
  'Acceptée', 'En attente paiement transport', 'Transport payé', 'En route', 'Arrivée',
];

/** Transporteurs en ligne, position récente (< 10 min), sans mission en cours, triés par distance. */
async function findNearbyDrivers(lat, lng, radiusKm, excludeIds = [], limit = 20) {
  const r = await pool.query(
    `SELECT u.id, u.full_name, u.note_moyenne, u.vehicule_type, u.localisation_lat, u.localisation_lng
       FROM users u
      WHERE u.role = 'transporteur' AND u.is_active = true AND u.disponible = true
        AND u.localisation_lat IS NOT NULL AND u.localisation_lng IS NOT NULL
        AND u.position_updated_at > now() - interval '10 minutes'
        AND NOT (u.id = ANY($1::uuid[]))
        AND NOT EXISTS (
          SELECT 1 FROM transport_missions m
           WHERE m.transporteur_id = u.id AND m.statut = ANY($2::text[])
        )`,
    [excludeIds, ACTIVE_MISSION_STATUTS],
  );
  const speed = await getCommissionPct('transport_speed_kmh', 30);
  return r.rows
    .map((u) => {
      const d = haversineKm(Number(lat), Number(lng), Number(u.localisation_lat), Number(u.localisation_lng));
      return {
        id: u.id,
        // vie privée : prénom + initiale uniquement, pas de téléphone
        name: String(u.full_name || '').split(/\s+/).map((p, i) => (i === 0 ? p : p.charAt(0) + '.')).join(' '),
        noteMoyenne: u.note_moyenne != null ? Number(u.note_moyenne) : 5,
        vehiculeType: u.vehicule_type || null,
        distanceKm: Math.round(d * 10) / 10,
        etaMinutes: Math.max(1, Math.round((d / speed) * 60)),
        lat: Number(u.localisation_lat),
        lng: Number(u.localisation_lng),
      };
    })
    .filter((u) => u.distanceKm <= radiusKm)
    .sort((a, b) => a.distanceKm - b.distanceKm || b.noteMoyenne - a.noteMoyenne)
    .slice(0, limit);
}


// ============================================================================
// PAYS / DEVISES / GÉOCODAGE (100 % gratuit : OpenStreetMap + taux open.er-api.com)
// [code]: [nom, devise, symbole, indicatif, langue par défaut, lat, lng, taux de repli (unités pour 1 USD)]
// ============================================================================
const COUNTRY_ROWS = {
  TG: ['Togo', 'XOF', 'FCFA', '228', 'fr', 8.62, 0.82, 600], BJ: ['Bénin', 'XOF', 'FCFA', '229', 'fr', 9.31, 2.32, 600],
  CI: ["Côte d'Ivoire", 'XOF', 'FCFA', '225', 'fr', 7.54, -5.55, 600], SN: ['Sénégal', 'XOF', 'FCFA', '221', 'fr', 14.5, -14.45, 600],
  BF: ['Burkina Faso', 'XOF', 'FCFA', '226', 'fr', 12.24, -1.56, 600], ML: ['Mali', 'XOF', 'FCFA', '223', 'fr', 17.57, -3.99, 600],
  NE: ['Niger', 'XOF', 'FCFA', '227', 'fr', 17.61, 8.08, 600], GW: ['Guinée-Bissau', 'XOF', 'FCFA', '245', 'pt', 11.8, -15.18, 600],
  CM: ['Cameroun', 'XAF', 'FCFA', '237', 'fr', 7.37, 12.35, 600], GA: ['Gabon', 'XAF', 'FCFA', '241', 'fr', -0.8, 11.61, 600],
  CG: ['Congo', 'XAF', 'FCFA', '242', 'fr', -0.23, 15.83, 600], TD: ['Tchad', 'XAF', 'FCFA', '235', 'fr', 15.45, 18.73, 600],
  CF: ['Centrafrique', 'XAF', 'FCFA', '236', 'fr', 6.61, 20.94, 600], GQ: ['Guinée équatoriale', 'XAF', 'FCFA', '240', 'es', 1.65, 10.27, 600],
  GH: ['Ghana', 'GHS', 'GH₵', '233', 'en', 7.95, -1.02, 12], NG: ['Nigeria', 'NGN', '₦', '234', 'en', 9.08, 8.68, 1500],
  CD: ['RD Congo', 'CDF', 'FC', '243', 'fr', -4.04, 21.76, 2800], GN: ['Guinée', 'GNF', 'FG', '224', 'fr', 9.95, -9.7, 8600],
  SL: ['Sierra Leone', 'SLE', 'Le', '232', 'en', 8.46, -11.78, 23], LR: ['Libéria', 'LRD', 'L$', '231', 'en', 6.43, -9.43, 190],
  GM: ['Gambie', 'GMD', 'D', '220', 'en', 13.44, -15.31, 70], MR: ['Mauritanie', 'MRU', 'UM', '222', 'ar', 21.0, -10.94, 40],
  MA: ['Maroc', 'MAD', 'DH', '212', 'ar', 31.79, -7.09, 9.8], DZ: ['Algérie', 'DZD', 'DA', '213', 'ar', 28.03, 1.66, 134],
  TN: ['Tunisie', 'TND', 'DT', '216', 'ar', 33.89, 9.54, 3.1], EG: ['Égypte', 'EGP', 'E£', '20', 'ar', 26.82, 30.8, 48],
  KE: ['Kenya', 'KES', 'KSh', '254', 'en', -0.02, 37.91, 129], UG: ['Ouganda', 'UGX', 'USh', '256', 'en', 1.37, 32.29, 3700],
  TZ: ['Tanzanie', 'TZS', 'TSh', '255', 'en', -6.37, 34.89, 2600], RW: ['Rwanda', 'RWF', 'FRw', '250', 'en', -1.94, 29.87, 1400],
  BI: ['Burundi', 'BIF', 'FBu', '257', 'fr', -3.37, 29.92, 2900], ET: ['Éthiopie', 'ETB', 'Br', '251', 'en', 9.15, 40.49, 130],
  ZA: ['Afrique du Sud', 'ZAR', 'R', '27', 'en', -30.56, 22.94, 18], ZM: ['Zambie', 'ZMW', 'ZK', '260', 'en', -13.13, 27.85, 25],
  MZ: ['Mozambique', 'MZN', 'MT', '258', 'pt', -18.67, 35.53, 64], AO: ['Angola', 'AOA', 'Kz', '244', 'pt', -11.2, 17.87, 910],
  MG: ['Madagascar', 'MGA', 'Ar', '261', 'fr', -18.77, 46.87, 4500],
  FR: ['France', 'EUR', '€', '33', 'fr', 46.23, 2.21, 0.92], BE: ['Belgique', 'EUR', '€', '32', 'fr', 50.5, 4.47, 0.92],
  ES: ['Espagne', 'EUR', '€', '34', 'es', 40.46, -3.75, 0.92], PT: ['Portugal', 'EUR', '€', '351', 'pt', 39.4, -8.22, 0.92],
  GB: ['Royaume-Uni', 'GBP', '£', '44', 'en', 55.38, -3.44, 0.79], US: ['États-Unis', 'USD', '$', '1', 'en', 37.09, -95.71, 1],
  CN: ['Chine', 'CNY', '¥', '86', 'zh', 35.86, 104.2, 7.2], BR: ['Brésil', 'BRL', 'R$', '55', 'pt', -14.24, -51.93, 5.5],
};
const COUNTRIES = {};
for (const [code, r] of Object.entries(COUNTRY_ROWS)) {
  COUNTRIES[code] = { code, name: r[0], currency: r[1], symbol: r[2], dial: r[3], language: r[4], center: [r[5], r[6]], fallbackRate: r[7] };
}
const DEFAULT_COUNTRY = 'TG';

function countryProfile(code) {
  const c = COUNTRIES[String(code || '').toUpperCase()] || COUNTRIES[DEFAULT_COUNTRY];
  return { code: c.code, name: c.name, currency: c.currency, symbol: c.symbol, dial: c.dial, language: c.language, center: c.center };
}

/** Pays déduit de l'indicatif téléphonique (préfixe le plus long). */
function detectCountryFromPhone(phone) {
  const digits = String(phone || '').replace(/[^\d]/g, '');
  let best = null;
  for (const c of Object.values(COUNTRIES)) {
    if (digits.startsWith(c.dial) && (!best || c.dial.length > best.dial.length)) best = c;
  }
  return best ? best.code : null;
}

function nearestCountry(lat, lng) {
  let best = DEFAULT_COUNTRY, bd = Infinity;
  for (const c of Object.values(COUNTRIES)) {
    const d = haversineKm(Number(lat), Number(lng), c.center[0], c.center[1]);
    if (d < bd) { bd = d; best = c.code; }
  }
  return best;
}

async function userCurrency(userId) {
  const r = await pool.query('SELECT devise FROM users WHERE id = $1', [userId]);
  return r.rows[0]?.devise || 'XOF';
}

// Taux de change réels et gratuits (sans clé), mis en cache 12 h ; repli sur des valeurs approximatives
let rateCache = { at: 0, rates: null };
async function getUsdRate(cur) {
  if (cur === 'USD') return 1;
  if (!rateCache.rates || Date.now() - rateCache.at > 12 * 3600 * 1000) {
    try {
      const r = await axios.get('https://open.er-api.com/v6/latest/USD', { timeout: 6000 });
      if (r.data?.result === 'success' && r.data.rates) rateCache = { at: Date.now(), rates: r.data.rates };
    } catch (e) {
      console.warn('[Taux] Service de change indisponible, valeurs approximatives :', e.message);
      rateCache.at = Date.now() - 11 * 3600 * 1000; // réessayer dans ~1 h
    }
  }
  const live = rateCache.rates?.[cur];
  if (live) return Number(live);
  const c = Object.values(COUNTRIES).find((x) => x.currency === cur);
  return c ? c.fallbackRate : 600;
}

const niceRound = (x) => {
  if (x <= 0) return 1;
  const mag = 10 ** Math.max(0, Math.floor(Math.log10(x)) - 1);
  return Math.max(1, Math.round(x / mag) * mag);
};

/** Tarifs transport par devise : FCFA = réglages existants ; autres = 0,85 $ + 0,25 $/km convertis. */
async function transportTariff(cur) {
  if (cur === 'XOF' || cur === 'XAF') {
    return {
      base: await getCommissionPct('transport_base_fcfa', 500),
      perKm: await getCommissionPct('transport_km_fcfa', 150),
    };
  }
  const base = await getCommissionPct(`transport_base_${cur}`, 0);
  const perKm = await getCommissionPct(`transport_km_${cur}`, 0);
  if (base > 0 && perKm > 0) return { base, perKm };
  const rate = await getUsdRate(cur);
  return { base: niceRound(0.85 * rate), perKm: niceRound(0.25 * rate) };
}

const geoLimiter = rateLimit({ windowMs: 60 * 1000, max: 40, standardHeaders: true, legacyHeaders: false, message: { message: 'Trop de requêtes.' } });
const PHOTON_URL = (process.env.PHOTON_URL || 'https://photon.komoot.io').replace(/\/$/, '');
const NOMINATIM_URL = (process.env.NOMINATIM_URL || 'https://nominatim.openstreetmap.org').replace(/\/$/, '');
const GEO_UA = { 'User-Agent': 'DifaBackend/1.0 (logistique agricole)' };
const geoCache = new Map();
const geoCached = (k) => { const h = geoCache.get(k); return h && Date.now() - h.at < 3600 * 1000 ? h.v : null; };
const geoStore = (k, v) => { if (geoCache.size > 1000) geoCache.delete(geoCache.keys().next().value); geoCache.set(k, { at: Date.now(), v }); return v; };

/** Profil du pays à partir de la position GPS (ou d'un code pays) : devise, indicatif, langue, centre de carte. */
router.get('/geo/profile', geoLimiter, asyncHandler(async (req, res) => {
  const { lat, lng, code } = req.query;
  if (code && COUNTRIES[String(code).toUpperCase()]) return res.json({ ...countryProfile(code), region: null, source: 'code' });
  if (!validCoord(lat, lng)) return res.json({ ...countryProfile(DEFAULT_COUNTRY), region: null, source: 'default' });
  const key = `rev:${Number(lat).toFixed(1)},${Number(lng).toFixed(1)}`;
  let hit = geoCached(key);
  if (!hit) {
    try {
      const r = await axios.get(`${NOMINATIM_URL}/reverse`, {
        params: { format: 'jsonv2', lat, lon: lng, zoom: 8, addressdetails: 1, 'accept-language': 'fr' },
        timeout: 7000, headers: GEO_UA,
      });
      const cc = String(r.data?.address?.country_code || '').toUpperCase();
      hit = geoStore(key, { code: COUNTRIES[cc] ? cc : nearestCountry(lat, lng), region: r.data?.address?.state || r.data?.address?.region || null, source: 'osm' });
    } catch (e) {
      hit = { code: nearestCountry(lat, lng), region: null, source: 'nearest' };
    }
  }
  res.json({ ...countryProfile(hit.code), region: hit.region, source: hit.source });
}));

router.get('/geo/countries', asyncHandler(async (req, res) => {
  res.json(Object.keys(COUNTRIES).map(countryProfile));
}));

/** Recherche d'adresse / lieu (comme Google Maps) via Photon puis Nominatim : gratuit, sans clé. */
router.get('/geo/search', geoLimiter, asyncHandler(async (req, res) => {
  const q = String(req.query.q || '').trim();
  if (q.length < 3) return res.json([]);
  const bias = validCoord(req.query.lat, req.query.lng) ? { lat: Number(req.query.lat), lon: Number(req.query.lng) } : {};
  const key = `s:${q.toLowerCase()}:${bias.lat ? bias.lat.toFixed(1) : ''}:${bias.lon ? bias.lon.toFixed(1) : ''}`;
  const hit = geoCached(key);
  if (hit) return res.json(hit);
  let out = [];
  try {
    const r = await axios.get(`${PHOTON_URL}/api/`, { params: { q, limit: 8, ...bias }, timeout: 7000, headers: GEO_UA });
    out = (r.data?.features || []).map((f) => {
      const p = f.properties || {};
      const [lng, lat] = f.geometry.coordinates;
      const label = [p.name, p.street && `${p.street}${p.housenumber ? ' ' + p.housenumber : ''}`, p.city || p.town || p.village, p.state, p.country]
        .filter(Boolean).filter((v, i, a) => a.indexOf(v) === i).join(', ');
      return { label, lat, lng, countryCode: String(p.countrycode || '').toUpperCase() || null, region: p.state || null };
    });
  } catch (e) {
    try {
      const r = await axios.get(`${NOMINATIM_URL}/search`, { params: { format: 'jsonv2', q, limit: 8, addressdetails: 1 }, timeout: 7000, headers: GEO_UA });
      out = (r.data || []).map((p) => ({
        label: p.display_name, lat: Number(p.lat), lng: Number(p.lon),
        countryCode: String(p.address?.country_code || '').toUpperCase() || null, region: p.address?.state || null,
      }));
    } catch (e2) { return res.status(503).json({ message: 'Recherche indisponible.' }); }
  }
  res.json(geoStore(key, out));
}));

/** Le transporteur se met en ligne / hors ligne et envoie sa position. */
router.patch(
  '/transport/availability',
  requireAuth,
  requireRole('transporteur'),
  asyncHandler(async (req, res) => {
    const { disponible, lat, lng } = req.body;
    const hasPos = validCoord(lat, lng);
    if (disponible === true && !hasPos) {
      return res.status(400).json({ message: 'Position GPS valide requise.' });
    }
    await pool.query(
      `UPDATE users SET
         disponible = $1,
         localisation_lat = CASE WHEN $4::boolean THEN $2::numeric ELSE localisation_lat END,
         localisation_lng = CASE WHEN $4::boolean THEN $3::numeric ELSE localisation_lng END,
         position_updated_at = CASE WHEN $4::boolean THEN now() ELSE position_updated_at END,
         updated_at = now()
       WHERE id = $5`,
      [disponible === true, hasPos ? lat : null, hasPos ? lng : null, hasPos, req.user.id],
    );
    res.json({ message: 'Disponibilité mise à jour.', disponible: disponible === true });
  }),
);

/** Battement de position (toutes les ~30 s tant que le transporteur est en ligne). */
router.post(
  '/transport/location',
  requireAuth,
  requireRole('transporteur'),
  asyncHandler(async (req, res) => {
    const { lat, lng } = req.body;
    if (!validCoord(lat, lng)) return res.status(400).json({ message: 'Position GPS valide requise.' });
    await pool.query(
      `UPDATE users SET localisation_lat = $1, localisation_lng = $2, position_updated_at = now() WHERE id = $3`,
      [lat, lng, req.user.id],
    );
    res.json({ ok: true });
  }),
);

router.get(
  '/transport/me',
  requireAuth,
  requireRole('transporteur'),
  asyncHandler(async (req, res) => {
    const r = await pool.query('SELECT disponible FROM users WHERE id = $1', [req.user.id]);
    res.json({ disponible: r.rows[0]?.disponible === true });
  }),
);

/** Estimation distance / prix / durée avant de commander un transport. */
router.get(
  '/transport/estimate',
  requireAuth,
  asyncHandler(async (req, res) => {
    const { originLat, originLng, destinationLat, destinationLng } = req.query;
    if (!validCoord(originLat, originLng) || !validCoord(destinationLat, destinationLng)) {
      return res.status(400).json({ message: 'Coordonnées manquantes.' });
    }
    const rt = await getRoadRoute(originLat, originLng, destinationLat, destinationLng);
    const est = await estimateTransport(rt.distanceKm, await userCurrency(req.user.id));
    res.json({ distanceKm: rt.distanceKm, ...est, etaMinutes: rt.durationMin, routeSource: rt.source });
  }),
);

/** Transporteurs disponibles autour d'un point (le plus proche en premier). */
router.get(
  '/transport/drivers/nearby',
  requireAuth,
  requireRole('acheteur', 'restaurant', 'agriculteur', 'admin'),
  asyncHandler(async (req, res) => {
    const { lat, lng } = req.query;
    if (!validCoord(lat, lng)) return res.status(400).json({ message: 'Coordonnées manquantes.' });
    const radius = Math.min(200, Number(req.query.radiusKm) || (await getCommissionPct('matching_rayon_km', 50)));
    const drivers = await findNearbyDrivers(lat, lng, radius, [], 20);
    res.json({ radiusKm: radius, drivers });
  }),
);

/** Écran "Trouver un transporteur" : estimation + transporteurs disponibles autour du point de départ. */
router.get(
  '/transport/orders/:id/options',
  requireAuth,
  requireRole('acheteur', 'restaurant', 'admin'),
  asyncHandler(async (req, res) => {
    const ord = await pool.query('SELECT * FROM orders WHERE id = $1', [req.params.id]);
    const o = ord.rows[0];
    if (!o) return res.status(404).json({ message: 'Commande introuvable.' });
    if (o.acheteur_id !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Accès refusé.' });
    }
    const pr = await pool.query(
      `SELECT COALESCE(p.latitude, u.localisation_lat) AS latitude, COALESCE(p.longitude, u.localisation_lng) AS longitude
         FROM products p LEFT JOIN users u ON u.id = p.agriculteur_id WHERE p.id = $1`,
      [o.product_id],
    );
    const oLat = pr.rows[0]?.latitude, oLng = pr.rows[0]?.longitude;
    if (!validCoord(oLat, oLng)) return res.status(400).json({ message: 'Coordonnées manquantes.' });
    let dLat = o.destination_lat, dLng = o.destination_lng;
    if (!validCoord(dLat, dLng)) { dLat = req.query.destLat; dLng = req.query.destLng; }
    if (!validCoord(dLat, dLng)) return res.status(400).json({ message: 'Coordonnées manquantes.' });
    const rt = await getRoadRoute(oLat, oLng, dLat, dLng);
    const est = await estimateTransport(rt.distanceKm, await userCurrency(o.acheteur_id));
    const radius = await getCommissionPct('matching_rayon_km', 50);
    const drivers = await findNearbyDrivers(oLat, oLng, radius, [], 20);
    res.json({ distanceKm: rt.distanceKm, ...est, etaMinutes: rt.durationMin, routeSource: rt.source, radiusKm: radius, drivers });
  }),
);

/** Propose la mission au transporteur le plus proche non encore sollicité (null = ouverte à tous). */
async function offerMissionToNextDriver(missionId) {
  const r = await pool.query('SELECT * FROM transport_missions WHERE id = $1', [missionId]);
  const m = r.rows[0];
  if (!m || m.statut !== 'En attente de transporteur') return null;
  const tried = Array.isArray(m.tried_ids) ? m.tried_ids : [];
  const radius = await getCommissionPct('matching_rayon_km', 50);
  const next = (await findNearbyDrivers(m.origine_lat, m.origine_lng, radius, tried, 1))[0];
  if (!next) {
    await pool.query(`UPDATE transport_missions SET offered_to = NULL, offered_at = NULL WHERE id = $1`, [missionId]);
    return null;
  }
  await pool.query(`UPDATE transport_missions SET offered_to = $1, offered_at = now() WHERE id = $2`, [next.id, missionId]);
  await notifyUser(next.id, 'nouvelle_mission', { km: String(Math.round(Number(m.distance_km) || next.distanceKm)) }, { missionId });
  return next;
}

/** Les offres sans réponse dans le délai passent automatiquement au transporteur suivant. */
async function redispatchExpiredOffers() {
  const timeout = await getCommissionPct('offer_timeout_seconds', 60);
  const r = await pool.query(
    `SELECT id, offered_to FROM transport_missions
      WHERE statut = 'En attente de transporteur' AND offered_to IS NOT NULL
        AND offered_at < now() - make_interval(secs => $1)`,
    [timeout],
  );
  for (const m of r.rows) {
    await pool.query(
      `UPDATE transport_missions SET tried_ids = COALESCE(tried_ids,'[]'::jsonb) || to_jsonb($1::text) WHERE id = $2`,
      [m.offered_to, m.id],
    );
    await offerMissionToNextDriver(m.id);
  }
}
setInterval(() => redispatchExpiredOffers().catch((e) => console.error('[Dispatch]', e.message)), 15000).unref();

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
    const timeout = await getCommissionPct('offer_timeout_seconds', 60);
    const me = await pool.query('SELECT localisation_lat, localisation_lng FROM users WHERE id = $1', [req.user.id]);
    const result = await pool.query(
      `SELECT * FROM transport_missions
        WHERE statut = 'En attente de transporteur'
          AND (offered_to IS NULL OR offered_to = $1 OR offered_at < now() - make_interval(secs => $2))
          AND NOT (COALESCE(tried_ids,'[]'::jsonb) ? $1::text)
        ORDER BY created_at ASC`,
      [req.user.id, timeout],
    );
    const lat = me.rows[0]?.localisation_lat, lng = me.rows[0]?.localisation_lng;
    const out = result.rows.map((row) => {
      const mission = serializeMission(row);
      mission.offeredToMe = row.offered_to === req.user.id;
      mission.distancePickupKm = lat != null
        ? Math.round(haversineKm(Number(lat), Number(lng), Number(row.origine_lat), Number(row.origine_lng)) * 10) / 10
        : null;
      return mission;
    });
    // Offres qui me sont destinées d'abord, puis les plus proches
    out.sort((a, b) =>
      (b.offeredToMe ? 1 : 0) - (a.offeredToMe ? 1 : 0) ||
      (a.distancePickupKm ?? 1e9) - (b.distancePickupKm ?? 1e9));
    res.json(out);
  }),
);

/** Le transporteur refuse l'offre : on la propose au suivant. */
router.post(
  '/transport/missions/:id/decline',
  requireAuth,
  requireRole('transporteur'),
  asyncHandler(async (req, res) => {
    const r = await pool.query('SELECT * FROM transport_missions WHERE id = $1', [req.params.id]);
    const m = r.rows[0];
    if (!m) return res.status(404).json({ message: 'Mission introuvable.' });
    if (m.statut !== 'En attente de transporteur' || m.offered_to !== req.user.id) {
      return res.status(400).json({ message: 'Cette mission ne vous est pas proposée.' });
    }
    await pool.query(
      `UPDATE transport_missions SET tried_ids = COALESCE(tried_ids,'[]'::jsonb) || to_jsonb($1::text) WHERE id = $2`,
      [req.user.id, req.params.id],
    );
    await offerMissionToNextDriver(req.params.id);
    res.json({ message: 'Mission refusée. Proposée au transporteur suivant.' });
  }),
);

router.get(
  '/transport/missions/:id/route',
  requireAuth,
  asyncHandler(async (req, res) => {
    const r = await pool.query('SELECT * FROM transport_missions WHERE id = $1', [req.params.id]);
    const m = r.rows[0];
    if (!m) return res.status(404).json({ message: 'Mission introuvable.' });
    if (m.acheteur_id !== req.user.id && m.transporteur_id !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Accès refusé.' });
    }
    const trip = await getRoadRoute(m.origine_lat, m.origine_lng, m.destination_lat, m.destination_lng);
    let toPickup = null;
    let remaining = null;
    if (m.transporteur_id) {
      const u = await pool.query('SELECT localisation_lat, localisation_lng FROM users WHERE id = $1', [m.transporteur_id]);
      const pLat = m.position_actuelle_lat ?? u.rows[0]?.localisation_lat;
      const pLng = m.position_actuelle_lng ?? u.rows[0]?.localisation_lng;
      if (pLat != null && pLng != null) {
        if (['Acceptée', 'En attente paiement transport', 'Transport payé'].includes(m.statut)) {
          toPickup = await getRoadRoute(pLat, pLng, m.origine_lat, m.origine_lng);
        } else if (['En route', 'Arrivée'].includes(m.statut)) {
          remaining = await getRoadRoute(pLat, pLng, m.destination_lat, m.destination_lng);
        }
      }
    }
    res.json({ trip, toPickup, remaining });
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
    const offerTimeout = await getCommissionPct('offer_timeout_seconds', 60);
    const em = existing.rows[0];
    const offerExpired = em.offered_at && Date.now() - new Date(em.offered_at).getTime() > offerTimeout * 1000;
    if (em.offered_to && em.offered_to !== req.user.id && !offerExpired) {
      return res.status(400).json({ message: 'Cette mission est proposée à un autre transporteur.' });
    }
    // Prix : celui proposé par le transporteur, sinon le prix estimé (comme Gozem)
    let prix = Number(req.body?.prixTransportFcfa ?? req.body?.prix_transport_fcfa) ||
      Number(em.prix_transport_fcfa);
    if (!prix || prix < 100) {
      return res.status(400).json({
        message: 'Indiquez un prix de transport valide (minimum 100 FCFA).',
      });
    }
    prix = Math.round(prix);
    const claimed = await pool.query(
      `UPDATE transport_missions SET
         transporteur_id = $1,
         prix_transport_fcfa = $2,
         statut = 'En attente paiement transport',
         updated_at = now()
       WHERE id = $3 AND statut = 'En attente de transporteur'
       RETURNING id`,
      [req.user.id, prix, req.params.id],
    );
    if (claimed.rowCount === 0) {
      return res.status(400).json({ message: 'Cette mission a déjà été prise.' });
    }
    const result = await pool.query('SELECT * FROM transport_missions WHERE id = $1', [
      req.params.id,
    ]);

    await notifyUser(
      existing.rows[0].acheteur_id,
      'mission_accepte_paiement',
      { amount: String(prix) },
      { missionId: req.params.id },
    );

    res.json(serializeMission(result.rows[0]));
  }),
);

/** Missions de l'acheteur (suivi + paiement transport) */
router.get(
  '/transport/missions/buyer',
  requireAuth,
  requireRole('acheteur', 'restaurant'),
  asyncHandler(async (req, res) => {
    const result = await pool.query(
      `SELECT * FROM transport_missions WHERE acheteur_id = $1 ORDER BY created_at DESC`,
      [req.user.id],
    );
    res.json(result.rows.map(serializeMission));
  }),
);

/** Acheteur paie le transport AVANT le départ du transporteur */
router.post(
  '/transport/missions/:id/pay-transport',
  requireAuth,
  requireRole('acheteur', 'restaurant'),
  asyncHandler(async (req, res) => {
    const existing = await pool.query('SELECT * FROM transport_missions WHERE id = $1', [req.params.id]);
    const m = existing.rows[0];
    if (!m) return res.status(404).json({ message: 'Mission introuvable.' });
    if (m.acheteur_id !== req.user.id) return res.status(403).json({ message: 'Accès refusé.' });
    if (m.statut !== 'En attente paiement transport') {
      return res.status(400).json({
        message: 'Cette mission n\'attend pas un paiement transport.',
      });
    }
    const amount = Number(m.prix_transport_fcfa) || 0;
    if (amount < 100) {
      return res.status(400).json({ message: 'Prix de transport invalide.' });
    }
    await ensureWallet(req.user.id);
    const w = await pool.query('SELECT solde_fcfa FROM wallets WHERE user_id = $1', [req.user.id]);
    const solde = Number(w.rows[0]?.solde_fcfa || 0);
    if (solde < amount) {
      return res.status(400).json({
        message: 'Solde portefeuille insuffisant pour payer le transport.',
        soldeFcfa: solde,
        montantRequis: amount,
      });
    }
    // Débit acheteur
    await pool.query(
      `UPDATE wallets SET solde_fcfa = solde_fcfa - $1, updated_at = now() WHERE user_id = $2`,
      [amount, req.user.id],
    );
    await pool.query(
      `INSERT INTO wallet_transactions (id, user_id, type, montant_fcfa, motif, reference_id)
       VALUES ($1,$2,'debit',$3,'Paiement transport',$4)`,
      [crypto.randomUUID(), req.user.id, amount, m.id],
    );
    await pool.query(
      `UPDATE transport_missions SET statut = 'Transport payé', updated_at = now() WHERE id = $1`,
      [m.id],
    );
    if (m.transporteur_id) {
      await notifyUser(
        m.transporteur_id,
        'transport_paye_par_acheteur',
        { amount: String(amount) },
        { missionId: m.id },
      );
    }
    const result = await pool.query('SELECT * FROM transport_missions WHERE id = $1', [m.id]);
    res.json({
      message: 'Transport payé. Le transporteur peut démarrer.',
      mission: serializeMission(result.rows[0]),
    });
  }),
);

/** Acheteur refuse le prix / le transport → se débrouille seul */
router.post(
  '/transport/missions/:id/refuse-transport',
  requireAuth,
  requireRole('acheteur', 'restaurant'),
  asyncHandler(async (req, res) => {
    const existing = await pool.query('SELECT * FROM transport_missions WHERE id = $1', [req.params.id]);
    const m = existing.rows[0];
    if (!m) return res.status(404).json({ message: 'Mission introuvable.' });
    if (m.acheteur_id !== req.user.id) return res.status(403).json({ message: 'Accès refusé.' });
    if (!['En attente paiement transport', 'Acceptée'].includes(m.statut)) {
      return res.status(400).json({ message: 'Impossible de refuser cette mission maintenant.' });
    }
    await pool.query(
      `UPDATE transport_missions SET statut = 'Refusée par acheteur', updated_at = now() WHERE id = $1`,
      [m.id],
    );
    if (m.transporteur_id) {
      await notifyUser(
        m.transporteur_id,
        'transport_refuse_acheteur',
        {},
        { missionId: m.id },
      );
    }
    const result = await pool.query('SELECT * FROM transport_missions WHERE id = $1', [m.id]);
    res.json({
      message: 'Transport refusé. Organisez la récupération du produit par vos moyens.',
      mission: serializeMission(result.rows[0]),
    });
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

/** Progression statut mission : Acceptée → En route → Arrivée → Livrée */
router.patch(
  '/transport/missions/:id/status',
  requireAuth,
  requireRole('transporteur'),
  asyncHandler(async (req, res) => {
    const { statut, lat, lng } = req.body;
    const allowed = ['En route', 'Arrivée', 'Livrée'];
    if (!allowed.includes(statut)) {
      return res.status(400).json({ message: 'Statut invalide. Utilisez: En route, Arrivée, Livrée.' });
    }
    const existing = await pool.query('SELECT * FROM transport_missions WHERE id = $1', [req.params.id]);
    if (!existing.rows[0]) return res.status(404).json({ message: 'Mission introuvable.' });
    if (existing.rows[0].transporteur_id !== req.user.id) {
      return res.status(403).json({ message: 'Vous n\'êtes pas le transporteur de cette mission.' });
    }
    // Départ uniquement après paiement transport par l'acheteur
    if (statut === 'En route' && existing.rows[0].statut !== 'Transport payé') {
      return res.status(400).json({
        message: 'Le transporteur ne peut démarrer qu\'après le paiement du transport par l\'acheteur.',
      });
    }
    if (statut === 'Arrivée' && existing.rows[0].statut !== 'En route') {
      return res.status(400).json({ message: 'Passez d\'abord en « En route ».' });
    }
    if (statut === 'Livrée' && !['Arrivée', 'En route'].includes(existing.rows[0].statut)) {
      return res.status(400).json({ message: 'Statut précédent invalide pour livrer.' });
    }
    await pool.query(
      `UPDATE transport_missions SET
         statut = $1,
         position_actuelle_lat = COALESCE($2, position_actuelle_lat),
         position_actuelle_lng = COALESCE($3, position_actuelle_lng),
         updated_at = now()
       WHERE id = $4`,
      [statut, lat ?? null, lng ?? null, req.params.id],
    );
    const m = existing.rows[0];
    try {
      io.to(`mission:${m.id}`).emit('statusChanged', { missionId: m.id, statut });
    } catch (_) {}
    if (statut === 'En route') {
      await notifyUser(m.acheteur_id, 'transporteur_en_route', {}, { missionId: m.id });
    } else if (statut === 'Arrivée') {
      await notifyUser(m.acheteur_id, 'livraison_arrivee', {}, { missionId: m.id });
    } else if (statut === 'Livrée') {
      await notifyUser(m.acheteur_id, 'livraison_effectuee', {}, { missionId: m.id });
      if (m.order_id) {
        await pool.query(
          `UPDATE orders SET statut = 'en_livraison', updated_at = now()
           WHERE id = $1 AND statut IN ('paye','confirme')`,
          [m.order_id],
        );
      }
      // Paiement automatique du transporteur (une seule fois)
      if (m.transporteur_id) {
        let amount = Number(m.prix_transport_fcfa) || 0;
        // Si aucun prix fixé, estimer via config (montant minimal de base)
        if (amount <= 0) {
          amount = 1500; // minimum de base FCFA si non renseigné
        }
        const already = await pool.query(
          `SELECT id FROM wallet_transactions
           WHERE user_id = $1 AND reference_id = $2 AND type = 'credit'
             AND motif = 'Transport mission' LIMIT 1`,
          [m.transporteur_id, m.id],
        );
        if (!already.rows[0]) {
          const pct = await getCommissionPct('commission_transport_pct', 10);
          const commission = Math.round(amount * (pct / 100));
          const net = Math.max(0, amount - commission);
          await ensureWallet(m.transporteur_id);
          await pool.query(
            `UPDATE wallets SET solde_fcfa = solde_fcfa + $1, updated_at = now() WHERE user_id = $2`,
            [net, m.transporteur_id],
          );
          await pool.query(
            `INSERT INTO wallet_transactions (id, user_id, type, montant_fcfa, motif, reference_id)
             VALUES ($1,$2,'credit',$3,'Transport mission',$4)`,
            [crypto.randomUUID(), m.transporteur_id, net, m.id],
          );
          // Mémoriser le prix appliqué si absent
          if (!m.prix_transport_fcfa) {
            await pool.query(
              `UPDATE transport_missions SET prix_transport_fcfa = $1 WHERE id = $2`,
              [amount, m.id],
            );
          }
          await notifyUser(
            m.transporteur_id,
            'transport_paye',
            { amount: String(net) },
            { missionId: m.id },
          );
        }
      }
    }
    // Broadcast socket
    try {
      if (typeof io !== 'undefined') {
        io.to(`mission:${req.params.id}`).emit('missionStatus', {
          missionId: req.params.id,
          statut,
          lat,
          lng,
        });
      }
    } catch (_) {}
    const result = await pool.query('SELECT * FROM transport_missions WHERE id = $1', [req.params.id]);
    res.json(serializeMission(result.rows[0]));
  }),
);

/** Notation transporteur (acheteur après livraison) */
router.post(
  '/transport/missions/:id/rate',
  requireAuth,
  requireRole('acheteur', 'restaurant'),
  asyncHandler(async (req, res) => {
    const { note, commentaire } = req.body;
    const n = Number(note);
    if (!n || n < 1 || n > 5) {
      return res.status(400).json({ message: 'Note entre 1 et 5 requise.' });
    }
    const existing = await pool.query('SELECT * FROM transport_missions WHERE id = $1', [req.params.id]);
    if (!existing.rows[0]) return res.status(404).json({ message: 'Mission introuvable.' });
    const m = existing.rows[0];
    if (m.acheteur_id !== req.user.id) return res.status(403).json({ message: 'Accès refusé.' });
    if (m.statut !== 'Livrée') {
      return res.status(400).json({ message: 'Vous ne pouvez noter qu\'après livraison.' });
    }
    await pool.query(
      `UPDATE transport_missions SET note_transporteur = $1, note_commentaire = $2, updated_at = now() WHERE id = $3`,
      [n, commentaire || null, req.params.id],
    );
    if (m.transporteur_id) {
      // Recalcul note moyenne transporteur
      const avg = await pool.query(
        `SELECT AVG(note_transporteur) AS a FROM transport_missions
         WHERE transporteur_id = $1 AND note_transporteur IS NOT NULL`,
        [m.transporteur_id],
      );
      const moyenne = Number(avg.rows[0].a) || n;
      await pool.query('UPDATE users SET note_moyenne = $1 WHERE id = $2', [moyenne, m.transporteur_id]);
      // Seuil minimum 3/5 — avertissement si sous le seuil
      if (moyenne < 3) {
        await notifyUser(m.transporteur_id, 'note_basse', { note: String(moyenne.toFixed(1)) }, {});
      }
    }
    res.json({ message: 'Merci pour votre évaluation.' });
  }),
);

/** Créer mission liée à une commande payée */
router.post(
  '/transport/missions/from-order',
  requireAuth,
  requireRole('acheteur', 'restaurant', 'admin'),
  asyncHandler(async (req, res) => {
    let { orderId, origineLat, origineLng, destinationLat, destinationLng } = req.body;
    const { transporteurId, auto } = req.body;
    if (!orderId) return res.status(400).json({ message: 'orderId requis.' });
    if (!UUID_RE.test(String(orderId))) return res.status(400).json({ message: 'Identifiant invalide.' });
    const ord = await pool.query('SELECT * FROM orders WHERE id = $1', [orderId]);
    if (!ord.rows[0]) return res.status(404).json({ message: 'Commande introuvable.' });
    const o = ord.rows[0];
    if (o.acheteur_id !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Accès refusé.' });
    }
    if (!['paye', 'confirme', 'en_livraison'].includes(o.statut)) {
      return res.status(400).json({ message: 'La commande doit être payée avant le transport.' });
    }
    // Origine = position du produit ; destination = adresse GPS de la commande (ou celle envoyée par l'app)
    if (!validCoord(origineLat, origineLng)) {
      const pr = await pool.query(
        `SELECT COALESCE(p.latitude, u.localisation_lat) AS latitude, COALESCE(p.longitude, u.localisation_lng) AS longitude
           FROM products p LEFT JOIN users u ON u.id = p.agriculteur_id WHERE p.id = $1`,
        [o.product_id],
      );
      origineLat = pr.rows[0]?.latitude; origineLng = pr.rows[0]?.longitude;
    }
    if (!validCoord(destinationLat, destinationLng)) {
      destinationLat = o.destination_lat; destinationLng = o.destination_lng;
    }
    if (!validCoord(origineLat, origineLng) || !validCoord(destinationLat, destinationLng)) {
      return res.status(400).json({ message: 'orderId et coordonnées requis.' });
    }
    origineLat = Number(origineLat); origineLng = Number(origineLng);
    destinationLat = Number(destinationLat); destinationLng = Number(destinationLng);
    const dup = await pool.query(
      `SELECT id FROM transport_missions WHERE order_id = $1 AND statut <> 'Annulée' AND statut <> 'Refusée par acheteur' LIMIT 1`,
      [orderId],
    );
    if (dup.rows[0]) return res.status(409).json({ message: 'Une mission existe déjà pour cette commande.' });

    const rt = await getRoadRoute(origineLat, origineLng, destinationLat, destinationLng);
    const dist = rt.distanceKm;
    const est = await estimateTransport(dist, await userCurrency(o.acheteur_id));
    est.etaMinutes = rt.durationMin;
    const radius = await getCommissionPct('matching_rayon_km', 50);

    // Choix du transporteur : explicite (liste "autour de moi"), automatique (le plus proche) ou ouvert à tous
    let offered = null;
    if (transporteurId) {
      if (!UUID_RE.test(String(transporteurId))) return res.status(400).json({ message: 'Identifiant invalide.' });
      const candidates = await findNearbyDrivers(origineLat, origineLng, radius, [], 50);
      offered = candidates.find((d) => d.id === transporteurId) || null;
      if (!offered) return res.status(400).json({ message: "Ce transporteur n'est pas disponible." });
    } else if (auto === true) {
      offered = (await findNearbyDrivers(origineLat, origineLng, radius, [], 1))[0] || null;
    }

    const id = crypto.randomUUID();
    await pool.query(
      `INSERT INTO transport_missions (
        id, product_id, order_id, acheteur_id, origine_lat, origine_lng,
        destination_lat, destination_lng, distance_km, eta_minutes, prix_transport_fcfa, statut,
        offered_to, offered_at
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'En attente de transporteur',$12, CASE WHEN $12::uuid IS NULL THEN NULL ELSE now() END)`,
      [
        id, o.product_id, orderId, o.acheteur_id,
        origineLat, origineLng, destinationLat, destinationLng,
        Math.round(dist * 100) / 100, est.etaMinutes, est.prixFcfa, offered ? offered.id : null,
      ],
    );
    if (offered) {
      await notifyUser(offered.id, 'nouvelle_mission', { km: String(Math.round(dist)) }, { missionId: id });
    } else {
      // Ouverte à tous : prévenir les transporteurs en ligne les plus proches
      const near = await findNearbyDrivers(origineLat, origineLng, radius, [], 10);
      for (const d of near) {
        await notifyUser(d.id, 'nouvelle_mission', { km: String(Math.round(dist)) }, { missionId: id });
      }
    }
    await pool.query(
      `UPDATE orders SET statut = 'en_livraison', updated_at = now() WHERE id = $1 AND statut IN ('paye','confirme')`,
      [orderId],
    );
    const result = await pool.query('SELECT * FROM transport_missions WHERE id = $1', [id]);
    res.status(201).json({ ...serializeMission(result.rows[0]), offeredTo: offered });
  }),
);

// ============================================================================
// MODULE 7 — INTELLIGENCE ARTIFICIELLE (Gemini, appelé directement en REST)
// ============================================================================

const LANG_NAMES = {
  fr: 'français',
  en: 'English',
  ee: 'Eʋegbe (Ewe)',
  ha: 'Hausa',
  es: 'español',
  pt: 'português',
  ar: 'العربية (Arabic)',
  zh: '中文 (Chinese)',
  yo: 'Yorùbá',
  kbp: 'Kabɩyɛ (Kabiyè)',
};

function buildGeminiSystemPrompt(langCode) {
  const code = (langCode || 'fr').split('-')[0].toLowerCase();
  const langName = LANG_NAMES[code] || LANG_NAMES.fr;

  return `Tu es l'assistant agricole de Difa, une plateforme togolaise qui connecte
agriculteurs, agronomes, acheteurs et transporteurs.

LANGUE DE RÉPONSE (priorité) :
1. Si l'utilisateur demande explicitement une autre langue (ex: "réponds en français", "in English"), utilise cette langue.
2. Sinon, réponds en ${langName} (code : ${code}) — c'est la langue de l'application de l'utilisateur.
3. Ne refuse JAMAIS de changer de langue si l'utilisateur le demande.
4. N'écris pas de phrases du type "I must communicate only in English".

FORMAT :
- Texte brut uniquement : PAS de markdown, PAS d'astérisques **, PAS de #.
- Pas de gras, pas d'italique, pas de backticks.
- Listes avec de simples tirets "-" si besoin.

RÔLE UTILISATEUR : le message peut venir d'un agriculteur, agronome, acheteur, restaurant ou transporteur.
Adapte le ton au besoin (conseil production, qualité, achat, logistique) sans refuser d'accès.

CONTENU :
Tu réponds aux questions liées à l'agriculture tropicale et togolaise :
cultures locales (maïs, manioc, igname, tomate, riz, coton...),
calendrier agricole, irrigation, engrais, maladies des plantes, techniques
de production, conservation post-récolte, qualité des produits, marché local.
Sois concis, pratique, et adapté aux réalités du Togo.
Si la question dépasse ton champ, invite poliment à contacter un agronome Difa via l'application.`;
}

/** Nettoie le markdown et caractères indésirables des réponses Gemini */
function cleanGeminiResponse(input) {
  if (!input || typeof input !== 'string') return input || '';
  let s = input;
  s = s.replace(/\*\*\*(.*?)\*\*\*/gs, '$1');
  s = s.replace(/\*\*(.*?)\*\*/gs, '$1');
  s = s.replace(/__(.*?)__/gs, '$1');
  s = s.replace(/(?<!\w)_([^_\n]+)_(?!\w)/g, '$1');
  s = s.replace(/`{1,3}([^`]*)`{1,3}/g, '$1');
  s = s.replace(/^#{1,6}\s+/gm, '');
  s = s.replace(/^\s*[\*\+]\s+/gm, '- ');
  s = s.replace(/\*\*/g, '');
  s = s.replace(/(?<!\w)\*(?!\w)/g, '');
  s = s.replace(/_{2,}/g, '');
  s = s.replace(/^-{3,}$/gm, '');
  s = s.replace(/^_{3,}$/gm, '');
  s = s.replace(/[ \t]{2,}/g, ' ');
  s = s.replace(/\n{3,}/g, '\n\n');
  return s.trim();
}

// Historique de conversation en mémoire par session (simple — à déplacer
// vers Redis si tu fais tourner plusieurs instances du serveur)
const chatHistories = new Map();

/**
 * Appelle Gemini en tournant les clés (429 / 401 / 403 / erreur réseau → clé suivante).
 * Même logique que le firmware ESP32 (geminiKeyIndex + continue).
 */
async function callGeminiWithRotation(contents) {
  if (GEMINI_API_KEYS.length === 0) {
    const err = new Error('NO_GEMINI_KEYS');
    err.code = 'NO_GEMINI_KEYS';
    throw err;
  }

  let lastError = null;
  const attempts = GEMINI_API_KEYS.length;

  for (let attempt = 0; attempt < attempts; attempt++) {
    const apiKey = GEMINI_API_KEYS[geminiKeyIndex];
    geminiKeyIndex = (geminiKeyIndex + 1) % GEMINI_API_KEYS.length;

    const url = `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent?key=${apiKey}`;

    try {
      const response = await axios.post(
        url,
        {
          contents,
          generationConfig: { temperature: 0.6, maxOutputTokens: 800 },
        },
        { timeout: 25000 },
      );

      const replyText =
        response.data?.candidates?.[0]?.content?.parts?.[0]?.text ||
        "Désolé, je n'ai pas pu générer de réponse.";

      console.log(`[Gemini] OK avec clé #${attempt + 1}/${attempts}`);
      return replyText;
    } catch (err) {
      lastError = err;
      const status = err.response?.status;
      const msg = err.response?.data || err.message;
      console.error(`[Gemini] échec clé #${attempt + 1}/${attempts} (HTTP ${status || 'réseau'}) :`, msg);

      // Quota / auth / rate-limit → essayer la clé suivante
      if (status === 429 || status === 403 || status === 401 || status === 400) {
        continue;
      }
      // Timeout / réseau → essayer aussi la clé suivante
      if (!status || err.code === 'ECONNABORTED' || err.code === 'ETIMEDOUT') {
        continue;
      }
      // Autre erreur HTTP : on continue quand même pour maximiser les chances
      continue;
    }
  }

  const e = new Error('ALL_GEMINI_KEYS_FAILED');
  e.code = 'ALL_GEMINI_KEYS_FAILED';
  e.cause = lastError;
  throw e;
}

router.post(
  '/ai/chat',
  requireAuth,
  // Tous les profils peuvent utiliser l'assistant (pas seulement agriculteur)
  requireRole('agriculteur', 'agronome', 'acheteur', 'restaurant', 'transporteur', 'admin'),
  asyncHandler(async (req, res) => {
    if (GEMINI_API_KEYS.length === 0) {
      return res.status(503).json({
        message: "L'assistant est temporairement indisponible. Réessayez plus tard.",
      });
    }
    const { message, sessionId, language } = req.body;
    if (!message) return res.status(400).json({ message: 'Message requis.' });

    // Priorité : langue envoyée par l'app (UI) > preferred_language en base > fr
    let lang = 'fr';
    if (language && typeof language === 'string') {
      lang = language.split('-')[0].toLowerCase();
    } else {
      try {
        const u = await pool.query('SELECT preferred_language FROM users WHERE id = $1', [
          req.user.id,
        ]);
        if (u.rows[0]?.preferred_language) lang = u.rows[0].preferred_language;
      } catch (_) {}
    }

    // Synchronise la langue de l'app en base (notifs + futurs chats)
    try {
      await pool.query(
        'UPDATE users SET preferred_language = $1 WHERE id = $2',
        [lang, req.user.id],
      );
    } catch (_) {}

    const sid = sessionId || req.user.id;
    // Historique par session uniquement (la langue peut changer en cours de route)
    const historyKey = String(sid);
    const history = chatHistories.get(historyKey) || [];

    const systemPrompt = buildGeminiSystemPrompt(lang);

    const contents = [
      { role: 'user', parts: [{ text: systemPrompt }] },
      {
        role: 'model',
        parts: [
          {
            text:
              'Compris. Je réponds dans la langue de l\'application, ou dans celle demandée par l\'utilisateur, en texte simple sans markdown.',
          },
        ],
      },
      ...history,
      { role: 'user', parts: [{ text: message }] },
    ];

    try {
      let replyText = await callGeminiWithRotation(contents);
      replyText = cleanGeminiResponse(replyText);

      history.push({ role: 'user', parts: [{ text: message }] });
      history.push({ role: 'model', parts: [{ text: replyText }] });
      chatHistories.set(historyKey, history.slice(-20));

      res.json({ reply: replyText, sessionId: sid, language: lang });
    } catch (err) {
      console.error('[Gemini] toutes les clés ont échoué :', err.cause?.response?.data || err.message);
      res.status(502).json({
        message:
          err.code === 'ALL_GEMINI_KEYS_FAILED'
            ? "L'assistant est temporairement indisponible. Réessayez dans quelques minutes."
            : "Impossible d'obtenir une réponse pour le moment. Réessayez.",
      });
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
    let { montantFcfa, email, orderId, purpose } = req.body;
    if (orderId) {
      const chk = await resolveOrderPayable(orderId, req.user.id);
      if (chk.error) return res.status(chk.status).json({ message: chk.error });
      montantFcfa = chk.amount; // on ignore le montant envoyé par le client
    }
    if (!montantFcfa || Number(montantFcfa) < 100) {
      return res.status(400).json({ message: 'Montant invalide (min 100 FCFA).' });
    }
    const metaPurpose = purpose || (orderId ? 'order' : 'wallet_topup');

    const response = await axios.post(
      'https://api.paystack.co/transaction/initialize',
      {
        email: email || `${req.user.phone.replace('+','')}@difa.app`,
        amount: Math.round(Number(montantFcfa) * 100),
        currency: await userCurrency(req.user.id),
        metadata: { purpose: metaPurpose, userId: req.user.id, orderId: orderId || null },
      },
      { headers: { Authorization: `Bearer ${secretKey}` } },
    );

    const id = crypto.randomUUID();
    await pool.query(
      `INSERT INTO transactions (id, user_id, order_id, montant_fcfa, methode, statut, reference_externe, metadata)
       VALUES ($1,$2,$3,$4,'carte','en_attente',$5,$6)`,
      [
        id, req.user.id, orderId || null, montantFcfa, response.data.data.reference,
        JSON.stringify({ purpose: metaPurpose, provider: 'paystack' }),
      ],
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
      const paidFcfa = Number(event.data.amount) / 100;
      const tx = await pool.query(
        `UPDATE transactions SET statut = 'reussi', metadata = $1
         WHERE reference_externe = $2 AND statut = 'en_attente' AND montant_fcfa <= $3
         RETURNING user_id, montant_fcfa, order_id`,
        [JSON.stringify(event.data), event.data.reference, paidFcfa],
      );
      if (tx.rows[0]) {
        if (tx.rows[0].order_id) {
          await pool.query(
            `UPDATE orders SET statut = 'paye', updated_at = now()
             WHERE id = $1 AND statut = 'en_attente_paiement'`,
            [tx.rows[0].order_id],
          );
          const ord = await pool.query('SELECT agriculteur_id FROM orders WHERE id = $1', [
            tx.rows[0].order_id,
          ]);
          if (ord.rows[0]) {
            await notifyUser(
              ord.rows[0].agriculteur_id,
              'paiement_recu',
              { amount: String(tx.rows[0].montant_fcfa) },
              { orderId: tx.rows[0].order_id },
            );
          }
        } else {
          await creditWalletOnce(
            tx.rows[0].user_id,
            tx.rows[0].montant_fcfa,
            'Recharge Paystack',
            event.data.reference,
          );
        }
        await notifyUser(
          tx.rows[0].user_id,
          'paiement_recu',
          { amount: String(tx.rows[0].montant_fcfa) },
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
    let { montantFcfa, phone, provider, orderId } = req.body;
    if (orderId) {
      const chk = await resolveOrderPayable(orderId, req.user.id);
      if (chk.error) return res.status(chk.status).json({ message: chk.error });
      montantFcfa = chk.amount;
    }
    montantFcfa = Math.round(Number(montantFcfa) || 0);
    if (montantFcfa < 100 || montantFcfa > 2000000) {
      return res.status(400).json({ message: 'Montant invalide (100 à 2 000 000 FCFA).' });
    }
    const operateur = String(provider || 'tmoney').toLowerCase().replace(/\s+/g, '_');
    const MM_PROVIDERS = [
      'tmoney', 'flooz', 'wave', 'mtn_momo', 'vodafone_cash', 'airtel_money',
      'orange_money', 'moov_money', 'free_money'
    ];
    if (!MM_PROVIDERS.includes(operateur)) {
      return res.status(400).json({
        message: 'provider invalide.',
        allowed: MM_PROVIDERS,
      });
    }
    const id = crypto.randomUUID();
    const ref = `MM-${operateur.toUpperCase()}-${id.slice(0, 8)}`;
    await pool.query(
      `INSERT INTO transactions (id, user_id, order_id, montant_fcfa, methode, statut, reference_externe, operateur, telephone_paiement, metadata)
       VALUES ($1,$2,$3,$4,'mobile_money','en_attente',$5,$6,$7,$8)`,
      [
        id, req.user.id, orderId || null, montantFcfa, ref, operateur,
        phone || req.user.phone,
        JSON.stringify({ provider: operateur, phone: phone || req.user.phone, sandbox: true }),
      ],
    );

    // Mode sandbox fonctionnel : si MOBILE_MONEY_SANDBOX=true (défaut) on confirme après 2s
    // En production, brancher l'API officielle T-Money / Flooz / Wave ici.
    // SÉCURITÉ : le sandbox crédite de l'argent fictif. Il n'est actif que si
    // MOBILE_MONEY_SANDBOX=true est défini explicitement (jamais par défaut).
    const sandbox = SANDBOX_PAYMENTS;
    if (sandbox) {
      setTimeout(async () => {
        try {
          const claimed = await pool.query(
            `UPDATE transactions SET statut = 'reussi' WHERE id = $1 AND statut = 'en_attente' RETURNING id`,
            [id],
          );
          if (claimed.rowCount === 0) return;
          if (orderId) {
            await pool.query(
              `UPDATE orders SET statut = 'paye', updated_at = now()
               WHERE id = $1 AND statut = 'en_attente_paiement'`,
              [orderId],
            );
            const ord = await pool.query('SELECT agriculteur_id FROM orders WHERE id = $1', [orderId]);
            if (ord.rows[0]) {
              await notifyUser(ord.rows[0].agriculteur_id, 'paiement_recu', {
                amount: String(montantFcfa),
              }, { orderId });
            }
          } else {
            // Recharge portefeuille
            await creditWalletOnce(req.user.id, montantFcfa, `Recharge ${operateur}`, id);
          }
          await notifyUser(req.user.id, 'paiement_recu', { amount: String(montantFcfa) }, {
            transactionId: id,
          });
          console.log(`[MobileMoney][Sandbox] ${operateur} OK ${ref} ${montantFcfa} FCFA`);
        } catch (e) {
          console.error('[MobileMoney][Sandbox] erreur', e.message);
        }
      }, 2000);
    } else {
      console.warn(`[MobileMoney] Mode prod — brancher API ${operateur} pour ${ref}`);
    }

    res.json({
      transactionId: id,
      reference: ref,
      statut: sandbox ? 'processing' : 'en_attente',
      provider: operateur,
      sandbox,
      message: sandbox
        ? 'Paiement sandbox initié — confirmation automatique dans ~2s.'
        : 'En attente de confirmation opérateur.',
    });
  }),
);

/** Confirmer manuellement un paiement mobile money (webhook opérateur ou admin) */
router.post(
  '/payments/mobile-money/confirm',
  requireAuth,
  asyncHandler(async (req, res) => {
    const { transactionId } = req.body;
    // Seul un admin (ou le webhook d'un opérateur) peut valider un paiement.
    if (req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Réservé aux administrateurs.' });
    }
    if (!transactionId || !UUID_RE.test(String(transactionId))) {
      return res.status(400).json({ message: 'transactionId invalide.' });
    }
    const tx = await pool.query('SELECT * FROM transactions WHERE id = $1', [transactionId]);
    if (!tx.rows[0]) return res.status(404).json({ message: 'Transaction introuvable.' });
    const claimed = await pool.query(
      `UPDATE transactions SET statut = 'reussi' WHERE id = $1 AND statut = 'en_attente' RETURNING id`,
      [transactionId],
    );
    if (claimed.rowCount === 0) {
      return res.status(400).json({ message: 'Transaction déjà traitée.' });
    }
    if (tx.rows[0].order_id) {
      await pool.query(
        `UPDATE orders SET statut = 'paye', updated_at = now()
         WHERE id = $1 AND statut = 'en_attente_paiement'`,
        [tx.rows[0].order_id],
      );
    } else {
      await creditWalletOnce(
        tx.rows[0].user_id,
        tx.rows[0].montant_fcfa,
        'Recharge mobile money',
        transactionId,
      );
    }
    res.json({ message: 'Paiement confirmé.', statut: 'reussi' });
  }),
);


/** Liste des moyens de paiement supportés (UI multi-langue côté app) */
router.get(
  '/payments/providers',
  requireAuth,
  asyncHandler(async (_req, res) => {
    res.json({
      mobileMoney: [
        { id: 'tmoney', name: 'TMoney', countries: ['TG'] },
        { id: 'flooz', name: 'Flooz', countries: ['TG', 'BJ'] },
        { id: 'wave', name: 'Wave', countries: ['TG', 'SN', 'CI'] },
        { id: 'mtn_momo', name: 'MTN MoMo', countries: ['GH', 'CI', 'CM', 'BJ'] },
        { id: 'vodafone_cash', name: 'Vodafone Cash', countries: ['GH'] },
        { id: 'airtel_money', name: 'Airtel Money', countries: ['NE', 'TD'] },
        { id: 'orange_money', name: 'Orange Money', countries: ['CI', 'SN', 'ML', 'BF'] },
        { id: 'moov_money', name: 'Moov Money', countries: ['TG', 'BJ', 'CI'] },
      ],
      cards: [
        { id: 'paystack', name: 'Paystack (Visa / Mastercard)' },
        { id: 'flutterwave', name: 'Flutterwave (Visa / Mastercard)' },
        { id: 'card_ecobank', name: 'Carte Ecobank (via Paystack/Flutterwave)' },
        { id: 'card_orabank', name: 'Carte Orabank (via Paystack/Flutterwave)' },
      ],
      note: 'Ecobank/Orabank passent par Paystack ou Flutterwave (pas d API banque directe).',
    });
  }),
);

/** Flutterwave — init recharge / paiement */
router.post(
  '/payments/flutterwave/initiate',
  requireAuth,
  asyncHandler(async (req, res) => {
    const secret = process.env.FLUTTERWAVE_SECRET_KEY;
    if (!secret) {
      return res.status(400).json({ message: 'Flutterwave non configuré (FLUTTERWAVE_SECRET_KEY).' });
    }
    let { montantFcfa, email, orderId, purpose, phone } = req.body;
    if (orderId) {
      const chk = await resolveOrderPayable(orderId, req.user.id);
      if (chk.error) return res.status(chk.status).json({ message: chk.error });
      montantFcfa = chk.amount;
    }
    if (!montantFcfa || Number(montantFcfa) < 100) {
      return res.status(400).json({ message: 'Montant invalide (min 100 FCFA).' });
    }
    const metaPurpose = purpose || (orderId ? 'order' : 'wallet_topup');
    const txRef = `FLW-${crypto.randomUUID().slice(0, 12)}`;
    const id = crypto.randomUUID();
    await pool.query(
      `INSERT INTO transactions (id, user_id, order_id, montant_fcfa, methode, statut, reference_externe, metadata)
       VALUES ($1,$2,$3,$4,'carte','en_attente',$5,$6)`,
      [
        id, req.user.id, orderId || null, montantFcfa, txRef,
        JSON.stringify({ purpose: metaPurpose, provider: 'flutterwave' }),
      ],
    );
    try {
      const response = await axios.post(
        'https://api.flutterwave.com/v3/payments',
        {
          tx_ref: txRef,
          amount: Number(montantFcfa),
          currency: await userCurrency(req.user.id),
          redirect_url: process.env.FLUTTERWAVE_REDIRECT_URL || 'https://difabackenf.onrender.com/payments/flutterwave/return',
          customer: {
            email: email || `${String(req.user.phone).replace('+','')}@difa.app`,
            phonenumber: phone || req.user.phone,
          },
          meta: { userId: req.user.id, orderId: orderId || null, purpose: metaPurpose },
          customizations: { title: 'Difa', description: metaPurpose === 'wallet_topup' ? 'Recharge portefeuille' : 'Paiement Difa' },
        },
        { headers: { Authorization: `Bearer ${secret}` } },
      );
      const link = response.data?.data?.link;
      res.json({
        authorizationUrl: link,
        reference: txRef,
        transactionId: id,
        provider: 'flutterwave',
      });
    } catch (err) {
      console.error('[Flutterwave] init', err.response?.data || err.message);
      res.status(502).json({ message: 'Impossible d initier Flutterwave.' });
    }
  }),
);

/** Webhook Flutterwave */
router.post(
  '/payments/flutterwave/webhook',
  asyncHandler(async (req, res) => {
    const secretHash = process.env.FLUTTERWAVE_SECRET_HASH || '';
    const signature = req.headers['verif-hash'];
    // Signature OBLIGATOIRE : sans FLUTTERWAVE_SECRET_HASH le webhook est refusé.
    if (!secretHash || !signature || signature !== secretHash) {
      return res.status(200).json({ received: false, reason: 'invalid_signature' });
    }
    const body = req.body || {};
    const status = body.status || body.data?.status;
    const txRef = body.txRef || body.tx_ref || body.data?.tx_ref;
    const amount = body.amount || body.data?.amount;
    if (String(status).toLowerCase() === 'successful' && txRef) {
      const tx = await pool.query(
        `UPDATE transactions SET statut = 'reussi', metadata = COALESCE(metadata, '{}'::jsonb) || $1::jsonb
         WHERE reference_externe = $2 AND statut = 'en_attente' AND montant_fcfa <= $3
         RETURNING user_id, montant_fcfa, order_id`,
        [JSON.stringify(body.data || body), txRef, Number(amount) || 0],
      );
      if (tx.rows[0]) {
        if (tx.rows[0].order_id) {
          await pool.query(`UPDATE orders SET statut = 'paye', updated_at = now() WHERE id = $1 AND statut = 'en_attente_paiement'`, [tx.rows[0].order_id]);
        } else {
          await creditWalletOnce(tx.rows[0].user_id, tx.rows[0].montant_fcfa, 'Recharge Flutterwave', txRef);
        }
        await notifyUser(tx.rows[0].user_id, 'paiement_recu', { amount: String(tx.rows[0].montant_fcfa || amount) }, {});
      }
    }
    res.json({ received: true });
  }),
);

/** Retrait portefeuille → Mobile Money / banque (sandbox ou API réelle) */
router.post(
  '/wallet/withdraw',
  requireAuth,
  asyncHandler(async (req, res) => {
    const { montantFcfa, provider, destination, accountName } = req.body;
    const amount = Math.round(Number(montantFcfa) || 0);
    if (amount < 500) {
      return res.status(400).json({ message: 'Montant minimum de retrait : 500 FCFA.' });
    }
    if (!provider || !destination) {
      return res.status(400).json({ message: 'provider et destination (téléphone ou compte) requis.' });
    }
    await ensureWallet(req.user.id);
    const id = crypto.randomUUID();
    const ref = `WD-${id.slice(0, 8)}`;
    // Débit + historique + demande de retrait dans UNE transaction :
    // soit tout réussit, soit rien (jamais d'argent débité sans trace).
    const okDebit = await withTransaction(async (c) => {
      const debit = await c.query(
        `UPDATE wallets SET solde_fcfa = solde_fcfa - $1, updated_at = now()
         WHERE user_id = $2 AND solde_fcfa >= $1 RETURNING solde_fcfa`,
        [amount, req.user.id],
      );
      if (debit.rowCount === 0) return false;
      await c.query(
        `INSERT INTO wallet_transactions (id, user_id, type, montant_fcfa, motif, reference_id)
         VALUES ($1,$2,'debit',$3,$4,$5)`,
        [crypto.randomUUID(), req.user.id, amount, `Retrait ${provider}`, ref],
      );
      await c.query(
        `INSERT INTO transactions (id, user_id, montant_fcfa, methode, statut, reference_externe, operateur, telephone_paiement, metadata)
         VALUES ($1,$2,$3,'mobile_money','en_attente',$4,$5,$6,$7)`,
        [
          id, req.user.id, amount, ref, String(provider).toLowerCase(),
          String(destination),
          JSON.stringify({ type: 'withdraw', accountName: accountName || null, sandbox: SANDBOX_PAYMENTS }),
        ],
      );
      return true;
    });
    if (!okDebit) {
      const w = await pool.query('SELECT solde_fcfa FROM wallets WHERE user_id = $1', [req.user.id]);
      return res.status(400).json({ message: 'Solde insuffisant.', soldeFcfa: Number(w.rows[0]?.solde_fcfa || 0) });
    }
    const sandbox = SANDBOX_PAYMENTS;
    if (sandbox) {
      setTimeout(async () => {
        try {
          await pool.query(`UPDATE transactions SET statut = 'reussi' WHERE id = $1`, [id]);
          await notifyUser(req.user.id, 'retrait_reussi', { amount: String(amount) }, { reference: ref });
          console.log(`[Withdraw][Sandbox] OK ${ref} ${amount} → ${provider} ${destination}`);
        } catch (e) {
          console.error('[Withdraw] sandbox', e.message);
        }
      }, 1500);
    } else {
      // Production : brancher Paystack Transfer / Flutterwave Transfer / API opérateur
      console.warn(`[Withdraw] Prod — exécuter transfert ${provider} ${destination} ${amount} FCFA (${ref})`);
    }
    res.status(201).json({
      message: sandbox
        ? 'Retrait initié (sandbox). Confirmation automatique sous peu.'
        : 'Retrait en cours de traitement.',
      reference: ref,
      transactionId: id,
      montantFcfa: amount,
      provider,
      destination,
      sandbox,
    });
  }),
);

/** Payer une commande avec le portefeuille interne */
router.post(
  '/payments/wallet/pay',
  requireAuth,
  asyncHandler(async (req, res) => {
    const { orderId } = req.body;
    if (!orderId) return res.status(400).json({ message: 'orderId requis.' });
    const ord = await pool.query('SELECT * FROM orders WHERE id = $1', [orderId]);
    if (!ord.rows[0]) return res.status(404).json({ message: 'Commande introuvable.' });
    const o = ord.rows[0];
    if (o.acheteur_id !== req.user.id) return res.status(403).json({ message: 'Accès refusé.' });
    if (o.statut !== 'en_attente_paiement') {
      return res.status(400).json({ message: 'Commande déjà traitée.' });
    }
    await ensureWallet(req.user.id);
    // Verrou : la commande ne peut être payée qu'une fois (statut passe à 'paye' atomiquement)
    const lock = await pool.query(
      `UPDATE orders SET statut = 'paye', updated_at = now()
       WHERE id = $1 AND statut = 'en_attente_paiement' RETURNING id`,
      [orderId],
    );
    if (lock.rowCount === 0) {
      return res.status(400).json({ message: 'Commande déjà traitée.' });
    }
    const debit = await pool.query(
      `UPDATE wallets SET solde_fcfa = solde_fcfa - $1, updated_at = now()
       WHERE user_id = $2 AND solde_fcfa >= $1 RETURNING solde_fcfa`,
      [o.montant_total_fcfa, req.user.id],
    );
    if (debit.rowCount === 0) {
      await pool.query(
        `UPDATE orders SET statut = 'en_attente_paiement', updated_at = now() WHERE id = $1`,
        [orderId],
      );
      return res.status(400).json({ message: 'Solde portefeuille insuffisant.' });
    }
    await pool.query(
      `INSERT INTO wallet_transactions (id, user_id, type, montant_fcfa, motif, reference_id)
       VALUES ($1,$2,'debit',$3,'Paiement commande',$4)`,
      [crypto.randomUUID(), req.user.id, o.montant_total_fcfa, orderId],
    );
    const txId = crypto.randomUUID();
    await pool.query(
      `INSERT INTO transactions (id, user_id, order_id, montant_fcfa, methode, statut, reference_externe)
       VALUES ($1,$2,$3,$4,'portefeuille_interne','reussi',$5)`,
      [txId, req.user.id, orderId, o.montant_total_fcfa, `WALLET-${txId.slice(0, 8)}`],
    );
    await pool.query(
      `UPDATE orders SET statut = 'paye', updated_at = now() WHERE id = $1`,
      [orderId],
    );
    await notifyUser(o.agriculteur_id, 'paiement_recu', { amount: String(o.montant_total_fcfa) }, {
      orderId,
    });
    res.json({ message: 'Paiement portefeuille réussi.', transactionId: txId });
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

/** Textes de notifications multilingues (type -> langue -> { title, body }) */
const NOTIF_I18N = {
  test_push: {
    fr: { title: 'Test Difa', body: 'Si vous lisez ceci, les notifications push fonctionnent.' },
    en: { title: 'Difa Test', body: 'If you see this, push notifications work.' },
    ee: { title: 'Difa kpɔɖeŋu', body: 'Ne èkpɔ sia la, push notificationwo dze egɔme nyuie.' },
    ha: { title: 'Gwaji Difa', body: 'Idan kun ga wannan, sanarwar turawa tana aiki.' },
    es: { title: 'Prueba Difa', body: 'Si ves esto, las notificaciones funcionan.' },
    pt: { title: 'Teste Difa', body: 'Se estiver a ver isto, as notificações funcionam.' },
    ar: { title: 'اختبار ديفا', body: 'إذا رأيت هذا، فالإشعارات تعمل.' },
    zh: { title: 'Difa 测试', body: '如果您看到此消息，推送通知正常。' },
    yo: { title: 'Ìdánwò Difa', body: 'Tí o bá rí èyí, àwọn ìfitónilétí ń ṣiṣẹ́.' },
    kbp: { title: 'Difa kpɔndʋ', body: 'Ñɛ ka naa se, push notification wɛ nyuie.' },
  },

  produit_soumis: {
    fr: { title: 'Produit soumis', body: 'Votre produit "{name}" est en attente de validation.' },
    en: { title: 'Product submitted', body: 'Your product "{name}" is pending validation.' },
    ee: { title: 'Nusiwo ɖe ɖa', body: 'Wò nusi "{name}" le kpɔɖeŋu dzi.' },
    ha: { title: 'An gabatar da kaya', body: 'Kayanka "{name}" yana jiran tabbatarwa.' },
    es: { title: 'Producto enviado', body: 'Su producto "{name}" está pendiente de validación.' },
    pt: { title: 'Produto enviado', body: 'O seu produto "{name}" está pendente de validação.' },
    ar: { title: 'تم إرسال المنتج', body: 'منتجك "{name}" في انتظار التحقق.' },
    zh: { title: '产品已提交', body: '您的产品“{name}”正在等待审核。' },
    yo: { title: 'Ọja ti firanṣẹ', body: 'Ọja rẹ "{name}" ń dúró fún ìjẹ́rìísí.' },
    kbp: { title: 'Nusi lɩzɩ', body: 'Wà nusi "{name}" wɛ kpɔndʋ yɔɔ.' },
  },
  produit_valide: {
    fr: { title: 'Produit certifié', body: 'Votre produit "{name}" a été validé avec le badge {badge}.' },
    en: { title: 'Product certified', body: 'Your product "{name}" was validated with badge {badge}.' },
    ee: { title: 'Nusiwo kpe ɖe eŋu', body: 'Wò nusi "{name}" kpe ɖe eŋu kple badge {badge}.' },
    ha: { title: 'An tabbatar da kaya', body: 'An tabbatar da kayanka "{name}" da alamar {badge}.' },
    es: { title: 'Producto certificado', body: 'Su producto "{name}" fue validado con la insignia {badge}.' },
    pt: { title: 'Produto certificado', body: 'O seu produto "{name}" foi validado com o selo {badge}.' },
    ar: { title: 'منتج معتمد', body: 'تم التحقق من منتجك "{name}" بشارة {badge}.' },
    zh: { title: '产品已认证', body: '您的产品“{name}”已通过认证，徽章：{badge}。' },
    yo: { title: 'Ọja ti jẹ́rìísí', body: 'Ọja rẹ "{name}" ti jẹ́rìísí pẹ̀lú àmì {badge}.' },
    kbp: { title: 'Nusi ɖɔ', body: 'Wà nusi "{name}" ɖɔ badge {badge} yɔɔ.' },
  },
  produit_rejete: {
    fr: { title: 'Produit rejeté', body: 'Votre produit "{name}" a été rejeté.{reason}' },
    en: { title: 'Product rejected', body: 'Your product "{name}" was rejected.{reason}' },
    ee: { title: 'Wogbe nusiwo', body: 'Wogbe wò nusi "{name}".{reason}' },
    ha: { title: 'An ƙi kaya', body: 'An ƙi kayanka "{name}".{reason}' },
    es: { title: 'Producto rechazado', body: 'Su producto "{name}" fue rechazado.{reason}' },
    pt: { title: 'Produto rejeitado', body: 'O seu produto "{name}" foi rejeitado.{reason}' },
    ar: { title: 'تم رفض المنتج', body: 'تم رفض منتجك "{name}".{reason}' },
    zh: { title: '产品已拒绝', body: '您的产品“{name}”已被拒绝。{reason}' },
    yo: { title: 'A kọ ọja', body: 'A kọ ọja rẹ "{name}".{reason}' },
    kbp: { title: 'Nusi gɛ', body: 'Wà nusi "{name}" gɛ.{reason}' },
  },
  produit_publie: {
    fr: { title: 'Produit publié', body: 'Votre produit "{name}" est maintenant visible sur le marché.' },
    en: { title: 'Product published', body: 'Your product "{name}" is now visible on the market.' },
    ee: { title: 'Nusiwo ɖe go', body: 'Wò nusi "{name}" le market dzi fifia.' },
    ha: { title: 'An buga kaya', body: 'Yanzu ana iya ganin kayanka "{name}" a kasuwa.' },
    es: { title: 'Producto publicado', body: 'Su producto "{name}" ya es visible en el mercado.' },
    pt: { title: 'Produto publicado', body: 'O seu produto "{name}" está visível no mercado.' },
    ar: { title: 'تم نشر المنتج', body: 'منتجك "{name}" مرئي الآن في السوق.' },
    zh: { title: '产品已上架', body: '您的产品“{name}”已在市场上可见。' },
    yo: { title: 'Ọja ti tẹ̀jáde', body: 'Ọja rẹ "{name}" ti hàn ní ọjà báyìí.' },
    kbp: { title: 'Nusi lɩzɩ', body: 'Wà nusi "{name}" wɛ asɩda yɔɔ fifia.' },
  },
  culture_ajoutee: {
    fr: { title: 'Culture enregistrée', body: 'Votre culture "{name}" a bien été enregistrée.' },
    en: { title: 'Crop saved', body: 'Your crop "{name}" has been saved.' },
    ee: { title: 'Agble ŋlɔ', body: 'Wò agble "{name}" ŋlɔ nyuie.' },
    ha: { title: 'An adana amfanin gona', body: 'An adana amfanin gonarka "{name}".' },
    es: { title: 'Cultivo registrado', body: 'Su cultivo "{name}" se ha registrado correctamente.' },
    pt: { title: 'Cultura registada', body: 'A sua cultura "{name}" foi registada.' },
    ar: { title: 'تم تسجيل المحصول', body: 'تم تسجيل محصولك "{name}" بنجاح.' },
    zh: { title: '作物已保存', body: '您的作物“{name}”已保存。' },
    yo: { title: 'Iṣẹ́-ọgbìn ti fi pamọ́', body: 'Iṣẹ́-ọgbìn rẹ "{name}" ti fi pamọ́.' },
    kbp: { title: 'Wenaa lɩzɩ', body: 'Wà wenaa "{name}" lɩzɩ nyuie.' },
  },
  transporteur_en_route: {
    fr: { title: 'Transporteur trouvé', body: 'Un transporteur a accepté votre commande et va la récupérer.' },
    en: { title: 'Transporter found', body: 'A transporter accepted your order and will pick it up.' },
    ee: { title: 'Wokpɔ dɔwɔla', body: 'Dɔwɔla aɖe lɔ wò ɖoɖo eye wòayi akpɔe.' },
    ha: { title: 'An sami mai jigilar kaya', body: 'Mai jigilar kaya ya karɓi odar ku kuma zai ɗauke ta.' },
    es: { title: 'Transportista encontrado', body: 'Un transportista aceptó su pedido y lo recogerá.' },
    pt: { title: 'Transportador encontrado', body: 'Um transportador aceitou a sua encomenda e vai buscá-la.' },
    ar: { title: 'تم العثور على ناقل', body: 'قبل ناقل طلبك وسيقوم باستلامه.' },
    zh: { title: '已找到运输商', body: '运输商已接受您的订单并将取货。' },
    yo: { title: 'A ti rí awakọ̀', body: 'Awakọ̀ kan ti gba àṣẹ rẹ yóò sì gbé e.' },
    kbp: { title: 'Tɩlɩyʊ wɛ ŋgbe', body: 'Tɩlɩyʊ wɛ ŋgbe mission yɔɔ.' },
  },
  paiement_recu: {
    fr: { title: 'Paiement confirmé', body: 'Votre paiement de {amount} FCFA a été reçu avec succès.' },
    en: { title: 'Payment confirmed', body: 'Your payment of {amount} FCFA was received successfully.' },
    ee: { title: 'Gaƒoƒo kpe ɖe eŋu', body: 'Woxɔ wò ga {amount} FCFA nyuie.' },
    ha: { title: 'An tabbatar da biyan kuɗi', body: 'An karɓi biyan kuɗin ku na {amount} FCFA cikin nasara.' },
    es: { title: 'Pago confirmado', body: 'Su pago de {amount} FCFA se recibió correctamente.' },
    pt: { title: 'Pagamento confirmado', body: 'O seu pagamento de {amount} FCFA foi recebido com sucesso.' },
    ar: { title: 'تم تأكيد الدفع', body: 'تم استلام دفعتك بمبلغ {amount} فرنك بنجاح.' },
    zh: { title: '付款已确认', body: '已成功收到您 {amount} FCFA 的付款。' },
    yo: { title: 'Ìsanwó ti jẹ́rìísí', body: 'A ti gba ìsanwó rẹ {amount} FCFA ní àṣeyọrí.' },
    kbp: { title: 'Liidiye ɖɔ', body: 'Woxɔ wà liidiye {amount} FCFA nyuie.' },
  },
  nouvelle_commande: {
    ar: {"title": "طلب جديد", "body": "تم استلام طلب لـ \"{name}\" (x{qty})."},
    zh: {"title": "新订单", "body": "收到“{name}”的订单（x{qty}）。"},
    fr: { title: 'Nouvelle commande', body: 'Commande reçue pour "{name}" (x{qty}).' },
    en: { title: 'New order', body: 'Order received for "{name}" (x{qty}).' },
    ee: { title: 'Asixɔ yeye', body: 'Asixɔ va na "{name}" (x{qty}).' },
    kbp: { title: 'Caŋ yɔɔdʋ', body: 'Caŋ wɛ "{name}" (x{qty}).' },
    ha: { title: 'Sabon oda', body: 'An karɓi oda "{name}" (x{qty}).' },
    yo: { title: 'Aṣẹ tuntun', body: 'Aṣẹ "{name}" (x{qty}).' },
    es: { title: 'Nuevo pedido', body: 'Pedido de "{name}" (x{qty}).' },
    pt: { title: 'Novo pedido', body: 'Pedido de "{name}" (x{qty}).' },
  },
  commande_annulee: {
    ar: {"title": "تم إلغاء الطلب", "body": "تم إلغاء طلب."},
    zh: {"title": "订单已取消", "body": "一个订单已被取消。"},
    fr: { title: 'Commande annulée', body: 'Une commande a été annulée.' },
    en: { title: 'Order cancelled', body: 'An order was cancelled.' },
    ee: { title: 'Asixɔ ƒe ɖeɖe', body: 'Asixɔ aɖe ɖe ɖe.' },
    kbp: { title: 'Caŋ kpɛ', body: 'Caŋ kʋ kpɛ.' },
    ha: { title: 'An soke oda', body: 'An soke wani oda.' },
    yo: { title: 'A fagile aṣẹ', body: 'A fagile aṣẹ kan.' },
    es: { title: 'Pedido anulado', body: 'Se anuló un pedido.' },
    pt: { title: 'Pedido cancelado', body: 'Um pedido foi cancelado.' },
  },
  commande_livree: {
    ar: {"title": "تم تسليم الطلب", "body": "تم تأكيد التسليم. +{amount} فرنك أضيفت إلى رصيدك."},
    zh: {"title": "订单已送达", "body": "已确认收货。+{amount} FCFA 已入账。"},
    fr: { title: 'Commande livrée', body: 'Livraison confirmée. +{amount} FCFA crédités.' },
    en: { title: 'Order delivered', body: 'Delivery confirmed. +{amount} FCFA credited.' },
    ee: { title: 'Asixɔ wɔ', body: 'Nɔnɔme kɔ. +{amount} FCFA.' },
    kbp: { title: 'Caŋ tɩ', body: 'Tɩ lɛ. +{amount} FCFA.' },
    ha: { title: 'An isar da oda', body: 'An tabbatar. +{amount} FCFA.' },
    yo: { title: 'A ti fi aṣẹ ranṣẹ', body: 'A jẹrisi. +{amount} FCFA.' },
    es: { title: 'Pedido entregado', body: 'Entrega confirmada. +{amount} FCFA.' },
    pt: { title: 'Pedido entregue', body: 'Entrega confirmada. +{amount} FCFA.' },
  },
  kyc_valide: {
    ar: {"title": "تم قبول التحقق", "body": "تم التحقق من هويتك.{reason}"},
    zh: {"title": "KYC 已通过", "body": "您的身份已验证。{reason}"},
    fr: { title: 'KYC validé', body: 'Votre identité a été vérifiée.{reason}' },
    en: { title: 'KYC approved', body: 'Your identity was verified.{reason}' },
    ee: { title: 'KYC sɔ', body: 'Wò ŋkɔ sɔ.{reason}' },
    kbp: { title: 'KYC sɔɔlʋ', body: 'Ɛ-yɔɔdʋ sɔɔlʋ.{reason}' },
    ha: { title: 'KYC an amince', body: 'An tabbatar da kai.{reason}' },
    yo: { title: 'KYC ti fọwọsi', body: 'A ti ṣayẹwo ẹ.{reason}' },
    es: { title: 'KYC validado', body: 'Identidad verificada.{reason}' },
    pt: { title: 'KYC validado', body: 'Identidade verificada.{reason}' },
  },
  kyc_rejete: {
    ar: {"title": "تم رفض التحقق", "body": "تم رفض التحقق.{reason}"},
    zh: {"title": "KYC 被拒绝", "body": "验证未通过。{reason}"},
    fr: { title: 'KYC rejeté', body: 'Vérification refusée.{reason}' },
    en: { title: 'KYC rejected', body: 'Verification refused.{reason}' },
    ee: { title: 'KYC gbe', body: 'Wogbe.{reason}' },
    kbp: { title: 'KYC gɛ', body: 'Gɛ.{reason}' },
    ha: { title: 'KYC an ƙi', body: 'An ƙi.{reason}' },
    yo: { title: 'KYC kọ', body: 'A kọ.{reason}' },
    es: { title: 'KYC rechazado', body: 'Verificación rechazada.{reason}' },
    pt: { title: 'KYC rejeitado', body: 'Verificação recusada.{reason}' },
  },
  alerte_agricole: {
    ar: {"title": "{title}", "body": "{msg}"},
    zh: {"title": "{title}", "body": "{msg}"},
    fr: { title: '{title}', body: '{msg}' },
    en: { title: '{title}', body: '{msg}' },
    ee: { title: '{title}', body: '{msg}' },
    kbp: { title: '{title}', body: '{msg}' },
    ha: { title: '{title}', body: '{msg}' },
    yo: { title: '{title}', body: '{msg}' },
    es: { title: '{title}', body: '{msg}' },
    pt: { title: '{title}', body: '{msg}' },
  },
  nouvelle_mission: {
    ar: {"title": "مهمة جديدة", "body": "مهمة نقل متاحة (~{km} كم)."},
    zh: {"title": "新任务", "body": "有可接运输任务（约 {km} 公里）。"},
    fr: { title: 'Nouvelle mission', body: 'Mission transport disponible (~{km} km).' },
    en: { title: 'New mission', body: 'Transport mission available (~{km} km).' },
    ee: { title: 'Dɔ yeye', body: 'Dɔ transport (~{km} km).' },
    kbp: { title: 'Tʋmʋ yɔɔdʋ', body: 'Tʋmʋ transport (~{km} km).' },
    ha: { title: 'Sabon aiki', body: 'Aikin sufuri (~{km} km).' },
    yo: { title: 'Iṣẹ tuntun', body: 'Iṣẹ gbigbe (~{km} km).' },
    es: { title: 'Nueva misión', body: 'Misión de transporte (~{km} km).' },
    pt: { title: 'Nova missão', body: 'Missão de transporte (~{km} km).' },
  },
  livraison_arrivee: {
    ar: { title: 'وصل الناقل', body: 'وصل الناقل إلى نقطة التسليم.' },
    zh: { title: '运输员已到达', body: '运输员已到达送货地点。' },
    fr: { title: 'Transporteur arrivé', body: 'Le transporteur est arrivé au point de livraison.' },
    en: { title: 'Transporter arrived', body: 'The transporter arrived at the delivery point.' },
    ee: { title: 'Transport va', body: 'Transport va ɖe afisi.' },
    kbp: { title: 'Transport wa', body: 'Transport wa tɛ.' },
    ha: { title: 'Mai sufuri ya iso', body: 'Ya isa wurin bayarwa.' },
    yo: { title: 'Olugbe de', body: 'Olugbe ti de ibi ifijiṣẹ.' },
    es: { title: 'Transportista llegó', body: 'Llegó al punto de entrega.' },
    pt: { title: 'Transportador chegou', body: 'Chegou ao ponto de entrega.' },
  },
  livraison_effectuee: {
    ar: {"title": "تم التسليم", "body": "تم تسليم طلبك. يرجى تأكيد الاستلام."},
    zh: {"title": "已送达", "body": "您的包裹已送达，请确认收货。"},
    fr: { title: 'Livraison effectuée', body: 'Votre colis a été livré. Confirmez la réception.' },
    en: { title: 'Delivery done', body: 'Your package was delivered. Please confirm.' },
    ee: { title: 'Nɔnɔme wɔ', body: 'Nɔnɔme wɔ. Kɔe.' },
    kbp: { title: 'Tɩ lɛ', body: 'Tɩ lɛ. Sɔɔlʋ.' },
    ha: { title: 'An isar', body: 'An isar da kaya. Tabbatar.' },
    yo: { title: 'Ti fi ranṣẹ', body: 'A ti fi ranṣẹ. Jẹrisi.' },
    es: { title: 'Entrega realizada', body: 'Paquete entregado. Confirme.' },
    pt: { title: 'Entrega feita', body: 'Encomenda entregue. Confirme.' },
  },
  nouveau_litige: {
    ar: {"title": "نزاع جديد", "body": "تم فتح نزاع: {motif}"},
    zh: {"title": "新纠纷", "body": "已发起纠纷：{motif}"},
    fr: { title: 'Nouveau litige', body: 'Litige ouvert : {motif}' },
    en: { title: 'New dispute', body: 'Dispute opened: {motif}' },
    ee: { title: 'Nya yeye', body: 'Nya : {motif}' },
    kbp: { title: 'Nyɔŋ yɔɔdʋ', body: 'Nyɔŋ : {motif}' },
    ha: { title: 'Sabon rikici', body: 'Rikici: {motif}' },
    yo: { title: 'Ariyanjiyan tuntun', body: 'Ariyanjiyan: {motif}' },
    es: { title: 'Nueva disputa', body: 'Disputa: {motif}' },
    pt: { title: 'Nova disputa', body: 'Disputa: {motif}' },
  },
  mission_accepte_paiement: {
    fr: { title: 'Mission acceptée', body: 'Un transporteur a accepté. Payez {amount} FCFA pour le transport avant le départ.' },
    en: { title: 'Mission accepted', body: 'A transporter accepted. Pay {amount} FCFA for transport before departure.' },
    ee: { title: 'Woxɔ dɔ', body: 'Kɔkɔɖeanyi xɔe. Ga {amount} FCFA hafi wòadze agbagba.' },
    kbp: { title: 'Mission acceptée', body: 'Transporteur accepté. Fɛɛlɩ {amount} FCFA avant départ.' },
    ha: { title: 'An karɓi manufa', body: 'Mai jigila ya yarda. Biya {amount} FCFA kafin tafiya.' },
    yo: { title: 'Iṣẹ́ gba', body: 'Olùgbé ti gba. San {amount} FCFA kí ó tó bẹ̀rẹ̀.' },
    es: { title: 'Misión aceptada', body: 'Un transportista aceptó. Pague {amount} FCFA antes de la salida.' },
    pt: { title: 'Missão aceite', body: 'Um transportador aceitou. Pague {amount} FCFA antes da partida.' },
    ar: { title: 'تم قبول المهمة', body: 'قبل الناقل. ادفع {amount} فرنك قبل المغادرة.' },
    zh: { title: '任务已接受', body: '承运人已接受。出发前请支付 {amount} FCFA 运费。' },
  },
  transport_paye_par_acheteur: {
    fr: { title: 'Transport payé', body: "L'acheteur a payé {amount} FCFA. Vous pouvez démarrer la mission." },
    en: { title: 'Transport paid', body: 'The buyer paid {amount} FCFA. You can start the mission.' },
    ee: { title: 'Woxɔ ga', body: 'Asitsala xɔ {amount} FCFA. Àte ŋu adze agbagba.' },
    kbp: { title: 'Transport payé', body: 'Acheteur fɛɛlɩ {amount} FCFA. Démarrez.' },
    ha: { title: 'An biya jigila', body: 'Mai saya ya biya {amount} FCFA. Za ku iya farawa.' },
    yo: { title: 'A san gbigbe', body: 'Oníbàárà san {amount} FCFA. O le bẹ̀rẹ̀.' },
    es: { title: 'Transporte pagado', body: 'El comprador pagó {amount} FCFA. Puede iniciar.' },
    pt: { title: 'Transporte pago', body: 'O comprador pagou {amount} FCFA. Pode iniciar.' },
    ar: { title: 'تم دفع النقل', body: 'دفع المشتري {amount} فرنك. يمكنك البدء.' },
    zh: { title: '运费已付', body: '买家已支付 {amount} FCFA。可以出发。' },
  },
  transport_refuse_acheteur: {
    fr: { title: 'Transport refusé', body: "L'acheteur a refusé le transport. Mission annulée de votre côté." },
    en: { title: 'Transport refused', body: 'The buyer refused transport. Mission cancelled on your side.' },
    ee: { title: 'Wogbe kɔkɔɖeanyi', body: 'Asitsala gbe. Dɔa wu.' },
    kbp: { title: 'Transport refusé', body: 'Acheteur a refusé. Mission annulée.' },
    ha: { title: 'An ƙi jigila', body: 'Mai saya ya ƙi. An soke manufa.' },
    yo: { title: 'Kọ gbigbe', body: 'Oníbàárà kọ̀. Iṣẹ́ ti parẹ́.' },
    es: { title: 'Transporte rechazado', body: 'El comprador rechazó el transporte. Misión cancelada.' },
    pt: { title: 'Transporte recusado', body: 'O comprador recusou o transporte. Missão cancelada.' },
    ar: { title: 'رفض النقل', body: 'رفض المشتري النقل. ألغيت المهمة.' },
    zh: { title: '拒绝运输', body: '买家拒绝运输。任务已取消。' },
  },
  retrait_reussi: {
    fr: { title: 'Retrait réussi', body: '{amount} FCFA envoyés vers votre compte.' },
    en: { title: 'Withdrawal successful', body: '{amount} FCFA sent to your account.' },
    ee: { title: 'Ga ɖe go', body: '{amount} FCFA yi wò akɔnta me.' },
    kbp: { title: 'Retrait OK', body: '{amount} FCFA ɖe compte.' },
    ha: { title: 'An yi nasarar cirewa', body: 'An aika {amount} FCFA zuwa asusun ku.' },
    yo: { title: 'Yiyọ́ ṣaṣeyọri', body: 'A fi {amount} FCFA ránṣẹ́ sí àkántì rẹ.' },
    es: { title: 'Retiro exitoso', body: '{amount} FCFA enviados a su cuenta.' },
    pt: { title: 'Levantamento OK', body: '{amount} FCFA enviados para a sua conta.' },
    ar: { title: 'سحب ناجح', body: 'تم إرسال {amount} فرنك إلى حسابك.' },
    zh: { title: '提现成功', body: '已向您的账户发送 {amount} FCFA。' },
  },
  transport_paye: {
    fr: { title: 'Paiement transport', body: 'Livraison terminée. +{amount} FCFA crédités sur votre portefeuille.' },
    en: { title: 'Transport payment', body: 'Delivery completed. +{amount} FCFA credited to your wallet.' },
    ee: { title: 'Gaƒoƒo kɔkɔɖeanyi', body: 'Wotsɔe vɔ. +{amount} FCFA le wò wallet me.' },
    kbp: { title: 'Fɛɛlɩ transport', body: 'Livraison wɛ. +{amount} FCFA ɖe wallet.' },
    ha: { title: 'Biyan jigila', body: 'An kammala isarwa. +{amount} FCFA an cika wallet.' },
    yo: { title: 'Isanwo gbigbe', body: 'Ikojọpọ pari. +{amount} FCFA ti wa si wallet.' },
    es: { title: 'Pago transporte', body: 'Entrega completada. +{amount} FCFA en su billetera.' },
    pt: { title: 'Pagamento transporte', body: 'Entrega concluída. +{amount} FCFA na carteira.' },
    ar: { title: 'دفع النقل', body: 'اكتملت التسليم. +{amount} فرنك في محفظتك.' },
    yo: { title: 'Isanwo gbigbe', body: 'Ikojọpọ pari. +{amount} FCFA ti wa si wallet.' },
    zh: { title: '运输付款', body: '配送完成。+{amount} FCFA 已入账。' },
  },
  note_basse: {
    ar: {"title": "تنبيه التقييم", "body": "متوسط تقييمك {note}/5. حسّن خدمتك."},
    zh: {"title": "评分偏低", "body": "您的平均评分为 {note}/5，请改进服务。"},
    fr: { title: 'Attention note', body: 'Votre note moyenne est de {note}/5. Améliorez votre service.' },
    en: { title: 'Low rating', body: 'Your average rating is {note}/5. Improve your service.' },
    ee: { title: 'Note kpakpa', body: 'Note {note}/5.' },
    kbp: { title: 'Note kɩlɛ', body: 'Note {note}/5.' },
    ha: { title: 'Ƙarancin maki', body: 'Makin ku {note}/5.' },
    yo: { title: 'Oṣuwọn kekere', body: 'Oṣuwọn {note}/5.' },
    es: { title: 'Nota baja', body: 'Su nota media es {note}/5.' },
    pt: { title: 'Nota baixa', body: 'A sua nota média é {note}/5.' },
  },
  certification_en_attente: {
    fr: { title: 'Nouvelle certification', body: 'Un produit "{name}" attend votre inspection.' },
    en: { title: 'New certification', body: 'A product "{name}" is waiting for your inspection.' },
    ee: { title: 'Certification yeye', body: 'Nusi "{name}" le wò kpɔɖeŋu dzi.' },
    ha: { title: 'Sabon tabbatarwa', body: 'Kaya "{name}" yana jiran duba ku.' },
    es: { title: 'Nueva certificación', body: 'Un producto "{name}" espera su inspección.' },
    pt: { title: 'Nova certificação', body: 'Um produto "{name}" aguarda a sua inspeção.' },
    ar: { title: 'شهادة جديدة', body: 'منتج "{name}" ينتظر فحصك.' },
    zh: { title: '新认证请求', body: '产品“{name}”等待您的检查。' },
    yo: { title: 'Ìjẹ́rìísí tuntun', body: 'Ọja "{name}" ń dúró fún àyẹ̀wò rẹ.' },
    kbp: { title: 'Certification ɛsɩda', body: 'Nusi "{name}" wɛ wà kpɔndʋ yɔɔ.' },
  },
};

function fillTemplate(str, vars = {}) {
  return String(str || '').replace(/\{(\w+)\}/g, (_, k) => (vars[k] != null ? String(vars[k]) : ''));
}

function resolveNotifText(type, lang, vars = {}, fallbackTitle, fallbackMessage) {
  const code = (lang || 'fr').split('-')[0].toLowerCase();
  const pack = NOTIF_I18N[type];
  const entry = (pack && (pack[code] || pack.fr)) || null;
  if (!entry) {
    return { title: fallbackTitle || type, body: fallbackMessage || '' };
  }
  return {
    title: fillTemplate(entry.title, vars),
    body: fillTemplate(entry.body, vars),
  };
}

/** Met à jour preferred_language si une langue UI valide est fournie */
async function applyUserLanguage(userId, language) {
  if (!language || typeof language !== 'string') return null;
  const code = language.split('-')[0].toLowerCase().slice(0, 8);
  if (!code) return null;
  try {
    await pool.query('UPDATE users SET preferred_language = $1, updated_at = now() WHERE id = $2', [
      code,
      userId,
    ]);
    return code;
  } catch (_) {
    return null;
  }
}

async function notifyUser(userId, type, varsOrTitle, maybeMessage, maybeData) {
  // Compat : notifyUser(id, type, vars, data) OU ancien notifyUser(id, type, titre, message, data)
  let vars = {};
  let data = null;
  let fallbackTitle = type;
  let fallbackMessage = '';

  if (varsOrTitle && typeof varsOrTitle === 'object' && !Array.isArray(varsOrTitle)) {
    vars = varsOrTitle;
    data = maybeMessage && typeof maybeMessage === 'object' ? maybeMessage : null;
  } else {
    fallbackTitle = varsOrTitle || type;
    fallbackMessage = typeof maybeMessage === 'string' ? maybeMessage : '';
    data = maybeData || null;
    // Essayer d'extraire name/badge/amount depuis l'ancien message n'est pas fiable
  }

  let lang = 'fr';
  try {
    const u = await pool.query('SELECT preferred_language FROM users WHERE id = $1', [userId]);
    if (u.rows[0]?.preferred_language) lang = String(u.rows[0].preferred_language).split('-')[0].toLowerCase();
  } catch (_) {}

  const { title, body } = resolveNotifText(type, lang, vars, fallbackTitle, fallbackMessage);
  console.log(`[Push] i18n type=${type} lang=${lang} title="${title}"`);

  const id = crypto.randomUUID();
  await pool.query(
    `INSERT INTO notifications (id, user_id, type, titre, message, data) VALUES ($1,$2,$3,$4,$5,$6)`,
    [id, userId, type, title, body, data ? JSON.stringify(data) : null],
  );

  if (firebaseMessaging) {
    try {
      const tokens = (
        await pool.query('SELECT fcm_token FROM push_tokens WHERE user_id = $1', [userId])
      ).rows.map((r) => r.fcm_token).filter(Boolean);

      if (tokens.length === 0) {
        console.log(`[Push] Aucun token FCM pour user ${userId} — notif in-app seulement.`);
      } else {
        const resp = await firebaseMessaging.sendEachForMulticast({
          tokens,
          // Bloc notification = affichage système (app fermée / arrière-plan / verrouillé)
          notification: { title, body },
          android: {
            priority: 'high',
            notification: {
              channelId: 'difa_notifications_v2',
              sound: 'default',
              defaultSound: true,
              defaultVibrateTimings: true,
              priority: 'high',
              visibility: 'public',
            },
          },
          // data duplique title/body pour le handler background (messages data-only)
          data: {
            type: String(type),
            title: String(title),
            body: String(body),
            ...(data
              ? Object.fromEntries(Object.entries(data).map(([k, v]) => [k, String(v)]))
              : {}),
          },
        });
        console.log(
          `[Push] Envoyé type=${type} user=${userId} success=${resp.successCount} failure=${resp.failureCount}`,
        );
        if (resp.failureCount > 0 && resp.responses) {
          for (let i = 0; i < resp.responses.length; i++) {
            const r = resp.responses[i];
            if (!r.success) {
              const code = r.error?.code || '';
              const msg = r.error?.message || String(r.error);
              console.error(`[Push] Token #${i} erreur :`, msg);
              // Token invalide / app désinstallée → on le retire de la base
              if (
                code.includes('registration-token-not-registered') ||
                code.includes('invalid-registration-token') ||
                /NotRegistered|InvalidRegistration/i.test(msg)
              ) {
                try {
                  await pool.query('DELETE FROM push_tokens WHERE fcm_token = $1', [tokens[i]]);
                  console.log(`[Push] Token invalide supprimé de la base.`);
                } catch (_) {}
              }
            }
          }
        }
      }
    } catch (err) {
      console.error('[Push] Échec envoi notification :', err.message);
    }
  } else {
    console.log('[Push] Firebase non initialisé — notif in-app seulement.');
  }
}

router.post(
  '/notifications/register-token',
  requireAuth,
  asyncHandler(async (req, res) => {
    const { fcmToken } = req.body;
    if (!fcmToken) return res.status(400).json({ message: 'fcmToken requis.' });

    // Un seul token actif par appareil : on retire les anciens tokens de cet utilisateur
    // puis on enregistre le nouveau (évite les NotRegistered cumulés).
    await pool.query('DELETE FROM push_tokens WHERE user_id = $1 OR fcm_token = $2', [
      req.user.id,
      fcmToken,
    ]);
    await pool.query(
      `INSERT INTO push_tokens (id, user_id, fcm_token) VALUES ($1,$2,$3)`,
      [crypto.randomUUID(), req.user.id, fcmToken],
    );
    console.log(`[Push] Token FCM enregistré pour user ${req.user.id}`);
    res.status(204).send();
  }),
);



router.post(
  '/notifications/test-push',
  requireAuth,
  asyncHandler(async (req, res) => {
    const tokens = (
      await pool.query('SELECT fcm_token FROM push_tokens WHERE user_id = $1', [req.user.id])
    ).rows.map((r) => r.fcm_token).filter(Boolean);

    if (!firebaseMessaging) {
      return res.status(503).json({
        message: 'Firebase non initialisé côté serveur. Vérifiez FIREBASE_* sur Render.',
        tokensRegistered: tokens.length,
      });
    }
    if (tokens.length === 0) {
      return res.status(400).json({
        message:
          'Aucun token FCM enregistré pour ce compte. Rouvrez l\'app, acceptez les notifications, puis reconnectez-vous.',
        tokensRegistered: 0,
      });
    }

    await notifyUser(req.user.id, 'test_push', {
      name: 'Difa',
    });

    res.json({
      message: 'Notification de test envoyée.',
      tokensRegistered: tokens.length,
    });
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
    const prod = await pool.query('SELECT agriculteur_id, nom FROM products WHERE id = $1', [
      req.params.id,
    ]);
    await pool.query('UPDATE products SET statut = $1, updated_at = now() WHERE id = $2', [
      statut,
      req.params.id,
    ]);
    if (prod.rows[0]) {
      const type = action === 'approve' ? 'produit_publie' : 'produit_rejete';
      await notifyUser(
        prod.rows[0].agriculteur_id,
        type,
        {
          name: prod.rows[0].nom,
          reason: action === 'reject' ? '' : '',
        },
        { productId: req.params.id },
      );
    }
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
      assistantAvailable: GEMINI_API_KEYS.length > 0,
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

// Authentification : le client doit fournir son JWT (auth.token) à la connexion.
io.use((socket, next) => {
  try {
    const token =
      socket.handshake.auth?.token ||
      (socket.handshake.headers.authorization || '').replace(/^Bearer /, '');
    if (!token) return next(new Error('unauthorized'));
    const payload = jwt.verify(token, JWT_ACCESS_SECRET);
    socket.user = { id: payload.sub, role: payload.role };
    next();
  } catch (_) {
    next(new Error('unauthorized'));
  }
});

io.on('connection', (socket) => {
  console.log(`[Socket.io] Client connecté : ${socket.id} (${socket.user.role})`);

  // Rejoindre une mission : uniquement acheteur, transporteur assigné ou admin
  socket.on('joinMission', async (missionId) => {
    try {
      if (!UUID_RE.test(String(missionId))) return;
      const r = await pool.query(
        'SELECT acheteur_id, transporteur_id FROM transport_missions WHERE id = $1',
        [missionId],
      );
      const m = r.rows[0];
      if (!m) return;
      const uid = socket.user.id;
      if (m.acheteur_id !== uid && m.transporteur_id !== uid && socket.user.role !== 'admin') return;
      socket.join(`mission:${missionId}`);
      socket.emit('joinedMission', { missionId });
    } catch (err) {
      console.error('[Socket.io] joinMission :', err.message);
    }
  });

  // Position GPS : uniquement le transporteur assigné, mission "En route"
  // (les changements de statut passent EXCLUSIVEMENT par l'API REST)
  socket.on('positionUpdate', async ({ missionId, lat, lng } = {}) => {
    try {
      if (!UUID_RE.test(String(missionId))) return;
      const la = Number(lat), lo = Number(lng);
      if (!Number.isFinite(la) || !Number.isFinite(lo) || Math.abs(la) > 90 || Math.abs(lo) > 180) return;
      const upd = await pool.query(
        `UPDATE transport_missions
            SET position_actuelle_lat = $1, position_actuelle_lng = $2, updated_at = now()
          WHERE id = $3 AND transporteur_id = $4 AND statut = 'En route'
        RETURNING statut`,
        [la, lo, missionId, socket.user.id],
      );
      if (upd.rowCount === 0) return;
      io.to(`mission:${missionId}`).emit('positionUpdated', {
        missionId,
        lat: la,
        lng: lo,
        statut: upd.rows[0].statut,
        timestamp: new Date().toISOString(),
      });
    } catch (err) {
      console.error('[Socket.io] Erreur positionUpdate :', err.message);
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

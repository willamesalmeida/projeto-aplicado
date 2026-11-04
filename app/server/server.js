'use strict';

/**
 * Servidor principal da aplicação Secure by Design.
 *
 * Estrutura de segurança implementada:
 * - Helmet com CSP restritiva
 * - Sessions com SQLite store
 * - CSRF via Synchronizer Token Pattern
 * - Rate limiting
 * - Expiração absoluta de sessão (8h)
 * - Logs estruturados sem dados sensíveis
 */

const path = require('path');
const fs = require('fs');
const express = require('express');
const helmet = require('helmet');
const session = require('express-session');
const SqliteStoreBase = require('better-sqlite3-session-store')(session);

/**
 * Extensão do SqliteStore para controle do timer de limpeza de sessões expiradas.
 * O better-sqlite3-session-store original dispara um setInterval sem .unref() e sem método
 * de parada, mantendo o event loop do Node.js aberto indefinidamente.
 * Sobrescrevemos startInterval para chamar timer.unref() e expomos stopInterval().
 */
class SqliteStore extends SqliteStoreBase {
  startInterval() {
    this.intervalTimer = setInterval(
      this.clearExpiredSessions.bind(this),
      this.expired.intervalMs
    );
    if (this.intervalTimer && typeof this.intervalTimer.unref === 'function') {
      this.intervalTimer.unref();
    }
  }

  stopInterval() {
    if (this.intervalTimer) {
      clearInterval(this.intervalTimer);
      this.intervalTimer = null;
    }
  }
}

const { carregarConfig } = require('./src/config/env');
const { criarBancoDeDados } = require('./src/db/database');
const { validarContentType } = require('./src/middleware/contentType');
const { criarRotaCsrf } = require('./src/routes/csrf');
const { criarRotaLogin } = require('./src/routes/login');
const { criarRotaLogout } = require('./src/routes/logout');
const { criarRotaMe } = require('./src/routes/me');
const { criarRotaDashboard } = require('./src/routes/dashboard');

/**
 * Cria e configura a aplicação Express.
 * Esta fábrica permite múltiplas instâncias isoladas para os testes.
 *
 * @param {object} [opcoes]
 * @param {function(): number} [opcoes.getNow] - Função de tempo injetável (para testes).
 * @param {import('better-sqlite3').Database} [opcoes.dbInstance] - Instância de banco já criada (para testes).
 * @param {object} [opcoes.configOverrides] - Sobrescritas de configuração (para testes).
 * @returns {import('express').Application} Aplicação Express configurada.
 */
function criarApp(opcoes = {}) {
  const { getNow = Date.now, dbInstance, configOverrides = {} } = opcoes;

  // Valida configuração — lança erro se SESSION_SECRET inválido
  const config = carregarConfig(configOverrides);

  // Usa banco injetado (testes) ou cria um novo
  const db = dbInstance ?? criarBancoDeDados(config.databasePath);

  const app = express();

  // Confia no primeiro proxy reverso (Nginx) para req.ip e req.secure funcionarem corretamente
  // OWASP A02:2025 - Security Misconfiguration
  app.set('trust proxy', 1);

  // Remove cabeçalho X-Powered-By para evitar enumeração e vazamento de tecnologia
  // OWASP A02:2025 - Security Misconfiguration
  app.disable('x-powered-by');

  // Cabeçalhos de segurança com Helmet (CSP restritiva e HSTS em produção)
  // OWASP A02:2025 - Security Misconfiguration
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"],
        imgSrc: ["'self'", 'data:'],
        connectSrc: ["'self'"],
        fontSrc: ["'self'"],
        objectSrc: ["'none'"],
        mediaSrc: ["'self'"],
        frameSrc: ["'none'"],
      },
    },
    // HSTS apenas em produção, sem preload, para evitar problemas em desenvolvimento
    hsts: config.isProduction
      ? { maxAge: 31536000, includeSubDomains: true }
      : false,
  }));

  // Limite estrito de tamanho do corpo da requisição (10kb) para mitigar negação de serviço (DoS)
  // OWASP A02:2025 - Security Misconfiguration
  app.use(express.json({ limit: '10kb' }));

  // Configuração do store de sessão persistente no SQLite via better-sqlite3-session-store
  // OWASP A07:2025 - Authentication Failures: limpeza de sessões expiradas a cada 15 min
  const storeOpcoes = {
    client: db,
    expired: {
      clear: true,          // Limpa sessões expiradas no SQLite automaticamente
      intervalMs: 900000,   // A cada 15 minutos
    },
  };

  // Configuração segura de sessões e cookies
  // OWASP A02:2025 - Security Misconfiguration (HttpOnly, SameSite, Secure)
  // OWASP A07:2025 - Authentication Failures (resave: false, saveUninitialized: false)
  const sessionStore = new SqliteStore(storeOpcoes);
  app.sessionStore = sessionStore;

  app.use(session({
    store: sessionStore,
    secret: config.sessionSecret,
    name: 'sid',             // Nome genérico, não expõe a biblioteca nem framework
    resave: false,
    saveUninitialized: false, // Não cria sessão em disco sem que haja dados salvos
    cookie: {
      httpOnly: true,        // Inacessível via JavaScript, prevenindo roubo via XSS
      sameSite: 'lax',      // Proteção no nível do navegador contra CSRF
      secure: config.isProduction, // Transmissão estritamente via HTTPS em produção
      maxAge: 15 * 60 * 1000,     // 15 min de vida inicial para sessões anônimas
    },
  }));

  // Validação de Content-Type ANTES das rotas da API
  // OWASP A02:2025 - Security Misconfiguration
  app.use(validarContentType);

  // Rotas da API
  // Impede cache de qualquer resposta da API (inclui o token CSRF e os 401)
  app.use('/api', (req, res, next) => {
    res.setHeader('Cache-Control', 'no-store');
    next();
  });
  app.use('/api/csrf', criarRotaCsrf({ getNow }));
  app.use('/api/login', criarRotaLogin({ db, getNow }));
  app.use('/api/logout', criarRotaLogout());
  app.use('/api/me', criarRotaMe({ getNow }));
  app.use('/api/dashboard', criarRotaDashboard({ getNow }));

  // Rotas da API inexistentes retornam 404 genérico em JSON (nunca atendidas pelo front-end)
  // OWASP A02:2025 - Security Misconfiguration
  app.all('/api/*', (req, res) => {
    res.status(404).json({ erro: 'Rota não encontrada.' });
  });

  // Serve arquivos estáticos do cliente (se existir o build de produção Vite)
  // Se app/client/dist não existir, o servidor inicia normalmente sem erro
  const clientDistPath = path.resolve(__dirname, '..', 'client', 'dist');
  if (fs.existsSync(clientDistPath)) {
    app.use(express.static(clientDistPath));
    // SPA: redireciona rotas do cliente para index.html (exceto /api)
    app.get('*', (req, res, next) => {
      if (req.path.startsWith('/api')) {
        return next();
      }
      res.sendFile(path.join(clientDistPath, 'index.html'));
    });
  }

  // Rota inexistente: 404 genérico em JSON
  // OWASP A02:2025 - Security Misconfiguration
  app.use((req, res) => {
    res.status(404).json({ erro: 'Rota não encontrada.' });
  });

  // Handler de erro genérico — sem stack trace nem detalhes internos para o cliente
  // OWASP A02:2025 - Security Misconfiguration: suprime detalhes internos e vazamento de stack traces
  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    const status = Number.isInteger(err?.status) && err.status >= 400 && err.status < 500
      ? err.status
      : 500;

    if (status === 500) {
      console.error(JSON.stringify({
        timestamp: new Date().toISOString(),
        tipo: 'erro_nao_tratado',
        mensagem: err?.message ?? 'Erro desconhecido',
      }));
      return res.status(500).json({ erro: 'Erro interno no servidor.' });
    }

    return res.status(status).json({
      erro: status === 413 ? 'Corpo da requisição muito grande.' : 'Requisição inválida.',
    });
  });

  return app;
}

// Exporta a fábrica para uso nos testes
module.exports = { criarApp };

// Inicializa o servidor quando executado diretamente (não via require/import)
if (require.main === module) {
  let config;
  try {
    config = carregarConfig();
  } catch (err) {
    console.error(`[Inicialização] ${err.message}`);
    process.exit(1);
  }

  const app = criarApp();
  const servidor = app.listen(config.port, '127.0.0.1', () => {
    console.log(JSON.stringify({
      timestamp: new Date().toISOString(),
      tipo: 'servidor_iniciado',
      porta: config.port,
      ambiente: config.nodeEnv,
    }));
  });

  // Encerra graciosamente em SIGTERM (ex: kill do SO ou orquestrador)
  process.on('SIGTERM', () => {
    console.log(JSON.stringify({ timestamp: new Date().toISOString(), tipo: 'shutdown', sinal: 'SIGTERM' }));
    servidor.close(() => process.exit(0));
  });
}

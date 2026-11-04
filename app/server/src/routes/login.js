'use strict';

/**
 * Rota POST /api/login — autenticação de usuários.
 *
 * OWASP A04:2025 - Cryptographic Failures: argon2id com parâmetros robustos;
 * hash fictício gerado na inicialização para equalizar tempos e evitar enumeração de usuários.
 * OWASP A05:2025 - Injection: validação e normalização de entradas, consultas 100% parametrizadas.
 * OWASP A07:2025 - Authentication Failures: mensagem única de erro, regeneração de sessão
 * para evitar session fixation, rotação de CSRF e rate limiting focado exclusivamente em falhas.
 * OWASP A09:2025 - Security Logging and Alerting Failures: registro de eventos de segurança
 * em formato JSON estruturado, sem nunca expor credenciais, senhas, hashes ou tokens.
 */

const { Router } = require('express');
const { rateLimit } = require('express-rate-limit');
const argon2 = require('argon2');
const { validarCsrf, definirTokenNaSessao } = require('../middleware/csrf');

// Parâmetros Argon2id recomendados (OWASP Password Storage Cheat Sheet)
// OWASP A04:2025 - Cryptographic Failures
const ARGON2_OPCOES = {
  type: argon2.argon2id,
  memoryCost: 19456, // 19456 KiB
  timeCost: 2,
  parallelism: 1,
};

/**
 * Promessa do hash fictício gerado UMA VEZ na inicialização do módulo com os mesmos parâmetros do Argon2id.
 * Guardamos a Promise e aguardamos (await) durante o login para garantir que nenhuma requisição
 * utilize um hash indefinido, prevenindo timing attacks contra usuários inexistentes.
 * OWASP A04:2025 - Cryptographic Failures & OWASP A07:2025 - Authentication Failures
 */
const dummyHashPromise = argon2.hash('dummy-placeholder-never-matches', ARGON2_OPCOES).catch((err) => {
  console.error(JSON.stringify({
    timestamp: new Date().toISOString(),
    tipo: 'erro_inicializacao',
    mensagem: 'Falha ao gerar hash fictício na inicialização',
  }));
  return null;
});

/**
 * Retorna o hash fictício gerado na inicialização, aguardando a Promise caso ainda esteja resolvendo.
 * @returns {Promise<string|null>}
 */
async function obterDummyHash() {
  return await dummyHashPromise;
}

/**
 * Sanitiza entrada para logs, removendo quebras de linha e caracteres de controle
 * para evitar log injection / log forging, e truncando em 50 caracteres.
 * NUNCA utilize esta função para registrar senhas, hashes ou tokens.
 *
 * @param {unknown} str - Valor a sanitizar.
 * @returns {string} String sanitizada de até 50 caracteres.
 */
function sanitizarEntrada(str) {
  if (typeof str !== 'string') return '[não-string]';
  return str.replace(/[\x00-\x1f\x7f]/g, '').substring(0, 50);
}

/**
 * Registra eventos de segurança no console em formato JSON estruturado.
 * OWASP A09:2025 - Security Logging and Alerting Failures:
 * NUNCA inclui senhas, hashes, tokens, cookies ou segredos.
 *
 * @param {string} tipo - Tipo do evento ('login_sucesso', 'login_falha', 'rate_limit').
 * @param {string} ip - Endereço IP da requisição.
 * @param {string|null} [username] - Nome do usuário sanitizado.
 */
function log(tipo, ip, username = null) {
  const entrada = {
    timestamp: new Date().toISOString(),
    tipo,
    ip: sanitizarEntrada(String(ip ?? '')),
    username: username ? sanitizarEntrada(username) : null,
  };
  console.log(JSON.stringify(entrada));
}

/**
 * Fábrica da rota de login.
 * Permite injeção de dependências para isolamento completo em testes.
 *
 * @param {object} opcoes
 * @param {import('better-sqlite3').Database} opcoes.db - Instância do banco de dados SQLite.
 * @param {function(): number} [opcoes.getNow] - Função de tempo injetável (para testes).
 * @returns {import('express').Router}
 */
function criarRotaLogin(opcoes = {}) {
  const { db, getNow = Date.now } = opcoes;
  const router = Router();

  /**
   * Rate limiter: máximo 5 FALHAS por IP a cada 15 minutos.
   * A configuração garante que SOMENTE falhas de autenticação (HTTP 401) consomem o limite.
   * Logins bem-sucedidos (200), erros internos (500), falhas de CSRF (403) ou 415 NÃO consomem o limite.
   * OWASP A07:2025 - Authentication Failures
   */
  const limitador = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutos
    max: 5,                    // Máximo de 5 falhas de autenticação por IP
    skipSuccessfulRequests: true,
    requestWasSuccessful: (req, res) => res.statusCode !== 401,
    standardHeaders: true,
    legacyHeaders: false,
    message: { erro: 'Muitas tentativas de login. Tente novamente em 15 minutos.' },
    handler: (req, res, next, options) => {
      // OWASP A09:2025 - Log do evento de bloqueio por rate limit
      log('rate_limit', req.ip);
      res.status(429).json(options.message);
    },
  });

  // Fluxo de login na ordem estrita solicitada:
  // 1. Validar token CSRF (middleware validarCsrf). Falhou: 403 genérico.
  // Rate limiter aplicado antes da rota, consumindo apenas falhas de autenticação.
  router.post('/', limitador, validarCsrf, async (req, res) => {
    const ip = req.ip;

    // 2. Validar o formato: username e password precisam ser strings não vazias
    // (máximo de 50 e 128 caracteres, respectivamente).
    // OWASP A05:2025 - Injection: validação rigorosa de tipo e tamanho
    const { username: usernameRaw, password } = req.body ?? {};

    if (
      typeof usernameRaw !== 'string' ||
      usernameRaw.trim().length < 1 ||
      usernameRaw.trim().length > 50
    ) {
      log('login_falha', ip);
      return res.status(401).json({ erro: 'Usuário ou senha inválidos' });
    }

    if (
      typeof password !== 'string' ||
      password.length < 1 ||
      password.length > 128
    ) {
      log('login_falha', ip, usernameRaw);
      return res.status(401).json({ erro: 'Usuário ou senha inválidos' });
    }

    // Normalizar o username (trim e minúsculas)
    // OWASP A05:2025 - Normalização de entrada
    const username = usernameRaw.trim().toLowerCase();

    try {
      // 3. Buscar o usuário com consulta parametrizada
      // OWASP A05:2025 - Injection: SQL parametrizado
      const usuario = db.prepare(
        'SELECT id, username, password_hash, last_login_at FROM users WHERE username = ?'
      ).get(username);

      let autenticado = false;

      // 4. Verificar com argon2.verify. Se o usuário NÃO existir, verificar contra o hash fictício
      // gerado uma vez na inicialização para equalizar o tempo de resposta
      // OWASP A04:2025 - Cryptographic Failures & OWASP A07:2025 - Authentication Failures
      if (usuario) {
        autenticado = await argon2.verify(usuario.password_hash, password, ARGON2_OPCOES);
      } else {
        const dummyHash = await obterDummyHash();
        if (dummyHash) {
          await argon2.verify(dummyHash, password, ARGON2_OPCOES);
        }
        autenticado = false;
      }

      // 5. Falha: 401 com a mensagem única "Usuário ou senha inválidos"
      // OWASP A07:2025 - Mensagem única impede enumeração de usuários
      if (!autenticado || !usuario) {
        log('login_falha', ip, username);
        return res.status(401).json({ erro: 'Usuário ou senha inválidos' });
      }

      // 6. Sucesso:
      // Recupera o último login anterior antes de atualizar o banco
      const previousLogin = usuario.last_login_at ?? null;

      // Atualiza last_login_at no banco de dados com query parametrizada
      // OWASP A05:2025 - Injection
      db.prepare(
        "UPDATE users SET last_login_at = datetime('now') WHERE id = ?"
      ).run(usuario.id);

      // Regenera a sessão para prevenir ataques de Session Fixation
      // OWASP A07:2025 - Authentication Failures
      req.session.regenerate((err) => {
        if (err) {
          console.error(JSON.stringify({
            timestamp: new Date().toISOString(),
            tipo: 'erro_sessao',
            mensagem: 'Falha ao regenerar sessão',
          }));
          return res.status(500).json({ erro: 'Erro interno no servidor.' });
        }

        // Guarda na sessão APENAS userId, username, createdAt e login anterior
        req.session.userId = usuario.id;
        req.session.username = usuario.username;
        req.session.createdAt = getNow(); // Timestamp de criação para expiração absoluta de 8h
        req.session.previousLogin = previousLogin;
        req.session.cookie.maxAge = 30 * 60 * 1000;

        // Gera novo token CSRF após o login (o anterior não é reaproveitado)
        definirTokenNaSessao(req.session);

        // Salva a sessão de forma explícita
        req.session.save((errSave) => {
          if (errSave) {
            console.error(JSON.stringify({
              timestamp: new Date().toISOString(),
              tipo: 'erro_sessao',
              mensagem: 'Falha ao salvar sessão',
            }));
            return res.status(500).json({ erro: 'Erro interno no servidor.' });
          }

          // OWASP A09:2025 - Log de sucesso (sem credenciais)
          log('login_sucesso', ip, usuario.username);
          return res.status(200).json({ username: usuario.username });
        });
      });
    } catch (erro) {
      console.error(JSON.stringify({
        timestamp: new Date().toISOString(),
        tipo: 'erro_login',
        mensagem: 'Erro inesperado no fluxo de login',
      }));
      return res.status(500).json({ erro: 'Erro interno no servidor.' });
    }
  });

  return router;
}

module.exports = { criarRotaLogin, obterDummyHash, dummyHashPromise };

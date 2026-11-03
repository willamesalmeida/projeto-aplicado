'use strict';

/**
 * Rota GET /api/csrf — fornece o token CSRF para o cliente.
 *
 * OWASP A07:2025 - Authentication Failures:
 * Cria a sessão anônima e gera token CSRF seguro.
 * Aplica expiração de 15 minutos para sessões anônimas e limite de 30 req/min por IP.
 * NUNCA registrar o token CSRF em logs.
 */

const { Router } = require('express');
const { rateLimit } = require('express-rate-limit');
const { definirTokenNaSessao } = require('../middleware/csrf');

/**
 * Fábrica da rota CSRF.
 * Aceita `getNow` para injeção de tempo nos testes (expiração de sessão anônima).
 *
 * @param {object} [opcoes]
 * @param {function(): number} [opcoes.getNow] - Função que retorna timestamp em ms.
 * @returns {import('express').Router}
 */
function criarRotaCsrf(opcoes = {}) {
  const { getNow = Date.now } = opcoes;
  const router = Router();

  // Rate limit: 30 requisições por minuto por IP
  const limitador = rateLimit({
    windowMs: 60 * 1000,
    max: 30,
    standardHeaders: true,
    legacyHeaders: false,
    message: { erro: 'Muitas requisições. Tente novamente em breve.' },
  });

  const QUINZE_MIN_MS = 15 * 60 * 1000;

  router.get('/', limitador, (req, res) => {
    // Trata caso de req.session ser indefinido garantindo que haja sessão instanciada
    if (!req.session) {
      if (req.sessionStore && typeof req.sessionStore.generate === 'function') {
        req.sessionStore.generate(req);
      } else {
        return res.status(500).json({ erro: 'Erro interno ao inicializar sessão.' });
      }
    }

    // Verifica se a sessão anônima expirou (campo anonCreatedAt)
    if (!req.session.userId && req.session.anonCreatedAt) {
      const agora = getNow();
      if (agora - req.session.anonCreatedAt > QUINZE_MIN_MS) {
        // Sessão anônima expirada: regenera a sessão.
        // O método req.session.regenerate() do express-session apaga a sessão antiga
        // no store e aloca uma nova sessão no request.
        // Chamar req.session.destroy() antes apagava req.session (delete req.session),
        // causando erro TypeError ao tentar ler req.session.regenerate.
        return req.session.regenerate((err) => {
          if (err) {
            return res.status(500).json({ erro: 'Erro interno ao renovar sessão.' });
          }
          req.session.anonCreatedAt = agora;
          const token = definirTokenNaSessao(req.session);
          return req.session.save((errSave) => {
            if (errSave) {
              return res.status(500).json({ erro: 'Erro interno ao salvar sessão.' });
            }
            // NUNCA logar o token
            return res.json({ csrfToken: token });
          });
        });
      }
    }

    // Sessão nova ou ainda válida: registra anonCreatedAt se ainda não existir
    if (!req.session.anonCreatedAt && !req.session.userId) {
      req.session.anonCreatedAt = getNow();
    }

    const token = definirTokenNaSessao(req.session);

    // Força o salvamento da sessão (saveUninitialized é false)
    req.session.save((err) => {
      if (err) {
        return res.status(500).json({ erro: 'Erro interno ao salvar sessão.' });
      }
      // NUNCA logar o token
      return res.json({ csrfToken: token });
    });
  });

  return router;
}

module.exports = { criarRotaCsrf };


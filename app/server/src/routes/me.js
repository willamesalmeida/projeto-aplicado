'use strict';

/**
 * Rota GET /api/me — retorna dados do usuário autenticado.
 *
 * OWASP A01:2025 - Broken Access Control:
 * Protegida pelo middleware requireAuth, que valida a sessão e a
 * expiração absoluta de 8 horas.
 */

const { Router } = require('express');
const { requireAuth } = require('../middleware/auth');

/**
 * Fábrica da rota /api/me.
 * Aceita `getNow` para injeção de tempo nos testes.
 *
 * @param {object} [opcoes]
 * @param {function(): number} [opcoes.getNow]
 * @returns {import('express').Router}
 */
function criarRotaMe(opcoes = {}) {
  const { getNow = Date.now } = opcoes;
  const router = Router();

  router.get('/', requireAuth(getNow), (req, res) => {
    return res.json({ username: req.session.username });
  });

  return router;
}

module.exports = { criarRotaMe };


'use strict';

/**
 * Rota GET /api/dashboard — retorna dados do painel do usuário autenticado.
 *
 * OWASP A01:2025 - Broken Access Control:
 * Protegida pelo middleware requireAuth, que valida a sessão e a
 * expiração absoluta de 8 horas.
 */

const { Router } = require('express');
const { requireAuth } = require('../middleware/auth');

/**
 * Fábrica da rota /api/dashboard.
 * Aceita `getNow` para injeção de tempo nos testes.
 *
 * @param {object} [opcoes]
 * @param {function(): number} [opcoes.getNow]
 * @returns {import('express').Router}
 */
function criarRotaDashboard(opcoes = {}) {
  const { getNow = Date.now } = opcoes;
  const router = Router();

  router.get('/', requireAuth(getNow), (req, res) => {
    return res.json({
      mensagem: 'Bem-vindo!',
      username: req.session.username,
      ultimoLogin: req.session.previousLogin ?? null,
    });
  });

  return router;
}

module.exports = { criarRotaDashboard };


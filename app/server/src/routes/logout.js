'use strict';

/**
 * Rota POST /api/logout — encerra a sessão do usuário.
 *
 * OWASP A07:2025 - Authentication Failures:
 * Destrói completamente a sessão no servidor (SQLiteStore) e instrui o navegador a
 * limpar o cookie sid, garantindo que o identificador de sessão não possa ser reutilizado.
 *
 * OWASP A09:2025 - Security Logging and Alerting Failures:
 * Registra o evento de logout em JSON estruturado com IP e username sanitizados.
 */

const { Router } = require('express');
const { validarCsrf } = require('../middleware/csrf');

/**
 * Sanitiza entrada para logs evitando log forging.
 *
 * @param {unknown} str
 * @returns {string}
 */
function sanitizarEntrada(str) {
  if (typeof str !== 'string') return '[não-string]';
  return str.replace(/[\x00-\x1f\x7f]/g, '').substring(0, 50);
}

/**
 * Fábrica da rota de logout.
 *
 * @returns {import('express').Router}
 */
function criarRotaLogout() {
  const router = Router();

  // 1. Valida o token CSRF. Falhou: 403 genérico
  router.post('/', validarCsrf, (req, res) => {
    const ip = req.ip;
    const username = req.session?.username ?? null;

    // OWASP A07:2025 - Destrói a sessão completamente no servidor
    req.session.destroy((err) => {
      if (err) {
        console.error(JSON.stringify({
          timestamp: new Date().toISOString(),
          tipo: 'erro_logout',
          mensagem: 'Falha ao destruir sessão',
        }));
        return res.status(500).json({ erro: 'Erro interno no servidor.' });
      }

      // OWASP A07:2025 - Limpa o cookie de sessão no cliente
      res.clearCookie('sid', {
        httpOnly: true,
        sameSite: 'lax',
      });

      // OWASP A09:2025 - Log do evento de encerramento de sessão
      console.log(JSON.stringify({
        timestamp: new Date().toISOString(),
        tipo: 'logout',
        ip: sanitizarEntrada(String(ip ?? '')),
        username: username ? sanitizarEntrada(username) : null,
      }));

      // Resposta sem conteúdo: HTTP 204 No Content
      return res.status(204).end();
    });
  });

  return router;
}

module.exports = { criarRotaLogout };


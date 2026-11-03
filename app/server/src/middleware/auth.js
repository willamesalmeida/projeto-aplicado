'use strict';

/**
 * Middleware de autenticação e controle de acesso a rotas privadas.
 *
 * OWASP A01:2025 - Broken Access Control:
 * Garante que apenas requisições com sessão autenticada ativa possam acessar rotas privadas.
 * Respostas autenticadas recebem o cabeçalho Cache-Control: no-store para impedir armazenamento
 * intermediário em proxies, navegadores ou caches locais.
 *
 * OWASP A07:2025 - Authentication Failures:
 * Implementa política rigorosa de expiração de sessão:
 * 1. Expiração absoluta máxima de 8 horas a partir da criação da sessão autenticada.
 * 2. Expiração por inatividade de 30 minutos, renovada a cada requisição sem ultrapassar o teto de 8 horas.
 */

const OITO_HORAS_MS = 8 * 60 * 60 * 1000;   // 8 horas em milissegundos
const TRINTA_MIN_MS = 30 * 60 * 1000;         // 30 minutos em milissegundos

/**
 * Fábrica do middleware de autenticação.
 * Aceita uma função `getNow` para injeção de tempo nos testes automatizados.
 *
 * @param {function(): number} [getNow] - Função que retorna o timestamp atual em ms.
 * @returns {import('express').RequestHandler} Middleware de autenticação.
 */
function requireAuth(getNow = Date.now) {
  return (req, res, next) => {
    // OWASP A01:2025 - Verifica se existe uma sessão autenticada válida
    if (!req.session?.userId) {
      return res.status(401).json({ erro: 'Não autenticado.' });
    }

    const agora = getNow();
    const criadoEm = req.session.createdAt;

    // OWASP A07:2025 - Verifica expiração absoluta de 8 horas independente de atividade contínua
    if (!criadoEm || agora - criadoEm > OITO_HORAS_MS) {
      req.session.destroy(() => {});
      return res.status(401).json({ erro: 'Sessão expirada. Faça login novamente.' });
    }

    // OWASP A07:2025 - Verifica expiração por inatividade de 30 minutos na aplicação
    const ultimaAtividade = req.session.lastActivity ?? criadoEm;
    if (agora - ultimaAtividade > TRINTA_MIN_MS) {
      req.session.destroy(() => {});
      return res.status(401).json({ erro: 'Sessão expirada por inatividade.' });
    }

    // Renova o registro de atividade da sessão autenticada
    req.session.lastActivity = agora;

    // OWASP A07:2025 - Renova o maxAge por inatividade (30 min), sem exceder a janela absoluta de 8h
    const tempoRestanteMs = OITO_HORAS_MS - (agora - criadoEm);
    const novaDuracaoMs = Math.min(TRINTA_MIN_MS, tempoRestanteMs);
    req.session.cookie.maxAge = novaDuracaoMs;

    // OWASP A01:2025 - Impede cache de respostas autenticadas sensíveis
    res.setHeader('Cache-Control', 'no-store');

    next();
  };
}

module.exports = { requireAuth };


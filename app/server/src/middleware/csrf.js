'use strict';

/**
 * Middleware de proteção contra ataques CSRF (Cross-Site Request Forgery).
 *
 * OWASP A07:2025 - Authentication Failures:
 * O padrão Synchronizer Token Pattern garante que requisições mutantes (POST)
 * contenham um token imprevisível, validado por comparação em tempo constante.
 *
 * OWASP A09:2025 - Security Logging and Alerting Failures:
 * Tentativas de requisição com CSRF inválido ou ausente são registradas com
 * o tipo 'csrf_invalido' em formato JSON estruturado.
 *
 * IMPORTANTE: O token CSRF NUNCA deve ser registrado em logs.
 */

const crypto = require('crypto');

/**
 * Gera um token CSRF criptograficamente seguro.
 * OWASP A04:2025 - Cryptographic Failures: uso de CSPRNG (crypto.randomBytes).
 *
 * @returns {string} Token hexadecimal de 64 caracteres (32 bytes).
 */
function gerarToken() {
  return crypto.randomBytes(32).toString('hex');
}

/**
 * Atribui um novo token CSRF à sessão, se ainda não existir.
 *
 * @param {import('express-session').Session} session - Objeto de sessão do Express.
 * @returns {string} O token CSRF da sessão.
 */
function definirTokenNaSessao(session) {
  const token = gerarToken();
  session.csrfToken = token;
  return token;
}

/**
 * Sanitiza o endereço IP para evitar log injection / log forging.
 *
 * @param {unknown} ip
 * @returns {string}
 */
function sanitizarIp(ip) {
  if (typeof ip !== 'string') return '[ip-indefinido]';
  return ip.replace(/[\x00-\x1f\x7f]/g, '').substring(0, 50);
}

/**
 * Registra eventos de CSRF inválido no console em JSON estruturado.
 * NUNCA registra o token fornecido ou o token esperado.
 * OWASP A09:2025 - Security Logging and Alerting Failures
 *
 * @param {string} ip
 */
function registrarLogCsrfInvalido(ip) {
  const entrada = {
    timestamp: new Date().toISOString(),
    tipo: 'csrf_invalido',
    ip: sanitizarIp(ip),
    username: null,
  };
  console.log(JSON.stringify(entrada));
}

/**
 * Middleware que valida o token CSRF nas requisições de estado mutante.
 * Compara o header X-CSRF-Token com o token armazenado na sessão usando
 * comparação em tempo constante (crypto.timingSafeEqual) para evitar ataques de timing.
 *
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @param {import('express').NextFunction} next
 */
function validarCsrf(req, res, next) {
  const tokenHeader = req.headers['x-csrf-token'];
  const tokenSessao = req.session?.csrfToken;

  // Rejeita imediatamente se qualquer um dos tokens estiver ausente
  if (!tokenHeader || !tokenSessao || typeof tokenHeader !== 'string') {
    registrarLogCsrfInvalido(req.ip);
    return res.status(403).json({ erro: 'Token de segurança inválido ou ausente.' });
  }

  let igual = false;
  try {
    // OWASP A07:2025 - Comparação em tempo constante evita timing attacks
    const bufHeader = Buffer.from(tokenHeader, 'utf8');
    const bufSessao = Buffer.from(tokenSessao, 'utf8');

    // timingSafeEqual exige buffers do mesmo tamanho
    if (bufHeader.length === bufSessao.length) {
      igual = crypto.timingSafeEqual(bufHeader, bufSessao);
    }
  } catch {
    igual = false;
  }

  if (!igual) {
    registrarLogCsrfInvalido(req.ip);
    return res.status(403).json({ erro: 'Token de segurança inválido ou ausente.' });
  }

  next();
}

module.exports = { gerarToken, definirTokenNaSessao, validarCsrf };


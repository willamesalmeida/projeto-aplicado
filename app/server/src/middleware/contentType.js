'use strict';

/**
 * Middleware de validação de Content-Type para requisições POST.
 *
 * OWASP A02:2025 - Security Misconfiguration:
 * Rejeita com HTTP 415 requisições POST sem Content-Type: application/json,
 * impedindo confusão de tipo de mídia (MIME-sniffing), bypass de parsers
 * e submissões como text/plain, multipart/form-data ou x-www-form-urlencoded.
 */

/**
 * Rejeita requisições POST que não tenham Content-Type: application/json.
 *
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @param {import('express').NextFunction} next
 */
function validarContentType(req, res, next) {
  // Apenas verifica requisições POST (ou mutantes com corpo)
  if (req.method === 'POST') {
    const contentType = req.headers['content-type'] ?? '';
    if (!contentType.toLowerCase().startsWith('application/json')) {
      return res.status(415).json({
        erro: 'Tipo de mídia não suportado. Utilize Content-Type: application/json.',
      });
    }
  }

  next();
}

module.exports = { validarContentType };

